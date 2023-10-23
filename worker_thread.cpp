
#include <pthread.h>
#include "log.h"
#include "worker_thread.h"
#include <sys/epoll.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <errno.h>

#define WORKER_LEN (MAXCONN)

typedef struct _WorkEvent{

	char event_type;             // 0: read event.1:write event
	void* write_ptr;
	int fd;
}WorkEvent;

typedef struct _ThreadStatus{

	int status; 						// 1:busy or idle
	int stop;   						// 1:thread stop 
	WorkEvent work_list[WORKER_LEN];  // work list,save fd for read and write, no need mutex
	sem_t worker_sem;
	unsigned short list_read_pos;		            // work_list read position
	unsigned short list_write_pos;                 // work_list write position  
	pthread_t tid;
}ThreadStatus;

ThreadStatus* thread_status;

struct epoll_event io_event_set[MAXCONN];

static int parse_frame_head(unsigned char* buff, int len, FrameHead* head)
{
	if(len < 2)
		return -1;
	head->fin = (buff[0] & 0x80) == 0x80;
	head->opcode = buff[0] & 0x0F;

	head->mask = (buff[1] & 0x80) == 0X80;
	len -=2;
	/*get payload length*/
	head->payload_length = buff[1] & 0x7F;
	if (head->payload_length == 126)
	{
		if(len < 6){

			return -1;
		}

		head->payload_length = (buff[2] & 0xFF) << 8 | (buff[3] & 0xFF);
		memcpy(head->masking_key, buff+4, 4);

		return 2+2+4;
	}
	else if (head->payload_length == 127)
	{
		unsigned char* extern_len = buff+2;
		char temp;
		int i;

		if(len < 14)
			return -1;

		for (i = 0; i < 4; i++)
		{
			temp = extern_len[i];
			extern_len[i] = extern_len[7 - i];
			extern_len[7 - i] = temp;
		}
		memcpy(&(head->payload_length), extern_len, 8);
		memcpy(head->masking_key, extern_len+8, 4);

		return 2+8+4;
	}
	if(len < 4)
		return -1;
	memcpy(head->masking_key, buff+2, 4);
	return 2+4;
}

static inline int get_method(char* header, int index)
{

	char* p = NULL;

	if((p = strstr(header, "websocket")) == NULL)
		return -1;

	if((p = strstr(header, "GET")) == NULL)
		return -1;

	if(strlen(p) < 4)
		return -1;

	p+=3;

	while(*p == ' ')
		p++;

	int i = 0;
	while(*p != ' ' && *p != '?')
	{
		if(*p == '\0' || i == sizeof(conn_list[index]->method[i])-2 )
			return -1;

		conn_list[index]->method[i++] = *p;
		p++;
	}
	conn_list[index]->method[i] = '\0';
	return 0;

}

static inline int get_seckey(char* buff, int index)
{
	char* p = NULL;
	if((p = strstr(buff, "Sec-WebSocket-Key:")) == NULL ){
		LOG("can`t find Sec-WebSocket-Key:");
		return -1;
	}
	p+=strlen("Sec-WebSocket-Key:");
	while(*p == ' ')
		p++;

	if(*p == '\0')
		return -1;

	char* p1 = NULL;
	if((p1 = strstr(p, "\r\n")) == NULL )
		return -1;

	if(p1 - p >= sizeof(conn_list[index]->sec_key)-2 )
		return -1;

	memcpy(conn_list[index]->sec_key, p, p1-p);
	conn_list[index]->sec_key[p1-p] = '\0';

	return 0;
}


static void umask(unsigned char* data, int len, char* mask)
{
	int i;
	for (i = 0; i < len; ++i)
		*(data + i) ^= *(mask + (i % 4));
}

static inline int parse_http_header(char* buff, int index)
{
	if(!buff || strlen(buff) == 0)
		return -1;

	if(get_method(buff, index) < 0)
		return -2;

	if(get_seckey(buff, index) < 0)
		return -3;

	return 0;

}

static inline int get_http_header( char* buff, const int fd)
{
	// 这是接收客户端发送的第一个数据包(很短)，且发送之后客户端在等待响应。所以调用一次recv 能且仅能 接收到完整的http头
	// 除非客户端将很短的http头分多次发送,且缓冲区不到0.3k, 应该不会这么做吧。。。
	int n = recv(fd, buff, 1500, 0); 
	if(n <= 0){  
		return -1;
	}
	char* p = NULL;
	if((p = strstr(buff, "\r\n\r\n")) == NULL){

		return -1;
	}

	return 0;
}

static inline int base64_encode(char *in_str, int in_len, char *out_str)
{
	BIO *b64, *bio;
	BUF_MEM *bptr = NULL;
	size_t size = 0;

	if (in_str == NULL || out_str == NULL)
		return -1;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_write(bio, in_str, in_len);
	BIO_flush(bio);

	BIO_get_mem_ptr(bio, &bptr);
	memcpy(out_str, bptr->data, bptr->length);
	out_str[bptr->length-1] = '\0';
	size = bptr->length;

	BIO_free_all(bio);
	return size;
}

void modify_event(int epfd, int fd, uint32_t events, int op)
{
	struct epoll_event ev;
	ev.events = events;
	ev.data.fd = fd;
	epoll_ctl(epfd, op, fd, &ev);
}

static void del_conn(int fd)
{
	LOG("############################del_conn:%d\n",fd);
	epoll_ctl(io_epfd, EPOLL_CTL_DEL, fd, NULL);
	close(fd);
	conn_list[fd]->is_connected = 0;
}

static int send_handshake_msg(int fd)
{
	unsigned char sha1_data[SHA_DIGEST_LENGTH]={0};
	char encode_str[32] = "";

	strcat(conn_list[fd]->sec_key, GUID);

	LOG("method:%s---[%d]\n", conn_list[fd]->method, fd);
	LOG("sec_key:%s---[%d]\n", conn_list[fd]->sec_key, strlen(conn_list[fd]->sec_key));

	SHA1((unsigned char*)conn_list[fd]->sec_key, strlen(conn_list[fd]->sec_key), (unsigned char*)&sha1_data);

	base64_encode((char*)sha1_data, SHA_DIGEST_LENGTH, (char*)encode_str);

	char resp_head[2048] = "";
	sprintf(resp_head, "HTTP/1.1 101 Switching Protocols\r\n" \
			"Upgrade: websocket\r\n" \
			"Connection: Upgrade\r\n" \
			"Sec-WebSocket-Accept: %s\r\n" \
			"\r\n",encode_str);

	/* 这是向客户端发送的第一个数据包，且数据包很短。
	 * 所以调用一次send可将完整的数据发送出去，也不会阻塞, 没必要利用epoll发送*/

	return send(fd, resp_head, strlen(resp_head), MSG_NOSIGNAL);
}


/*** event_type:0 connected event
 ***		   :1 recv event  
 *****/
static int do_callback(int event_type, int fd, int opcode)
{
	IoEvent* notify_data = NULL;
	MALLOC(notify_data, IoEvent*, sizeof(IoEvent));

	notify_data->event_type = event_type;
	notify_data->fd = fd;
	strcpy(notify_data->key, conn_list[fd]->sec_key);

	if(event_type == 0){ // connected event

		( (CallBack)(funcMap[conn_list[fd]->method]) ) (notify_data); // do callback
		return 0;
	}

	/****** read event  ***********/
	notify_data->is_text = opcode;
	notify_data->pdata = (conn_list[fd])->read_cache+conn_list[fd]->read_cache_pos;
	notify_data->data_len = conn_list[fd]->read_data_len - conn_list[fd]->read_cache_pos;

	( (CallBack)(funcMap[conn_list[fd]->method]) ) (notify_data); // do callback

	return 0;
}

static inline int websocket_handshake(int fd)
{
	char buff[1024] = "";  // TODO  websocket header length >= 1024??

	if(get_http_header(buff, fd) < 0)    // recv websocket header
	{
		LOG("get_http_header[%d] error\n", fd);
		del_conn(fd);

		return -1;
	}

	int	ret = parse_http_header(buff, fd);
	if(ret < 0){

		del_conn(fd);
		LOG("parse http header failed:[%s]  %d\n", buff, ret);
		return -1;
	}

	if( funcMap.find(conn_list[fd]->method) == funcMap.end() ){ // no request method in server

		del_conn(fd);
		return -1;
	}

	if(send_handshake_msg(fd) < 0){

		del_conn(fd);
		return -1;
	}

	conn_list[fd]->status = HANDSHAKE;  // finish websocket handshake

	do_callback(0, fd, 0);
	conn_list[fd]->read_data_len = 0;
	conn_list[fd]->error_times = 0;
	conn_list[fd]->get_ws_header = 0;   // market it:need get websocekt header next time

	return 0;
}

static inline int do_read_event(int fd)
{
	char buff[CACHE_LEN] = "";

	int n = 0;

	if(conn_list[fd]->status == CONNECTED){  // finish tcp three times handshake, but no websocket handshake

		return websocket_handshake(fd);
	}

	while(1){   //  already finish websocket handshake

		n = recv(fd, buff, sizeof(buff), 0);
		if(n < 0)
		{
			if(errno == EAGAIN){
				if(conn_list[fd]->read_data_len == 0)	
					break;
				else{
				
					if(conn_list[fd]->error_times > 5){
						del_conn(fd);
						break;
					}
				}

			}else{
				LOG("recv faield:%d-%s\n", fd, strerror(errno));
				del_conn(fd);
				break;
			}

		}else if(n == 0){

			LOG("peer is closed: [%d]\n", fd);
			del_conn(fd);
			break;
		}

		if( conn_list[fd]->status == HANDSHAKE ){ // websocket handshaked already

			if(n > 0){
				memcpy(conn_list[fd]->read_cache+conn_list[fd]->read_data_len, buff, n); 
				conn_list[fd]->read_data_len += n;
			}else{
			
				conn_list[fd]->error_times++;
			}

			if(conn_list[fd]->get_ws_header == 0){  // must get websocket header first 

				int head_len = parse_frame_head(conn_list[fd]->read_cache, conn_list[fd]->read_data_len, &conn_list[fd]->ws_head);
				if(head_len < 0){

					conn_list[fd]->error_times++;
					continue;   // I`m not get websocket header yet,wait epoll event for receive websocket header
				}else 
					conn_list[fd]->get_ws_header = 1; // I get websocket header already

				if(conn_list[fd]->ws_head.opcode == 8){ // close operation by peer  

					LOG("op is 8 close:%d\n", fd);
					del_conn(fd);
					break;
				}

				conn_list[fd]->read_cache_pos= head_len; 
			}

			if(conn_list[fd]->ws_head.payload_length > conn_list[fd]->read_cache_len){ // websocket body data too length , realloc

				unsigned char* tmp = (unsigned char*)malloc(conn_list[fd]->ws_head.payload_length + conn_list[fd]->read_data_len -  conn_list[fd]->read_cache_pos);
				if(tmp == NULL){

					LOG("malloc failed:%s", strerror(errno));
					del_conn(fd);
					break;
				}
				conn_list[fd]->read_cache_len = conn_list[fd]->ws_head.payload_length +  conn_list[fd]->read_data_len - conn_list[fd]->read_cache_pos;
				memcpy(tmp, conn_list[fd]->read_cache + conn_list[fd]->read_cache_pos, conn_list[fd]->read_data_len - conn_list[fd]->read_cache_pos);
				FREE(conn_list[fd]->read_cache);
				conn_list[fd]->read_data_len = conn_list[fd]->read_data_len - conn_list[fd]->read_cache_pos;
				conn_list[fd]->read_cache = tmp;
				conn_list[fd]->read_cache_pos = 0;
			}

			if( conn_list[fd]->read_data_len - conn_list[fd]->read_cache_pos >= conn_list[fd]->ws_head.payload_length){ // get enough data, unmask it and do callback

				umask(conn_list[fd]->read_cache + conn_list[fd]->read_cache_pos, conn_list[fd]->read_data_len - conn_list[fd]->read_cache_pos, conn_list[fd]->ws_head.masking_key); 

				conn_list[fd]->get_ws_header = 0;  // need get websocket header next time

				if(conn_list[fd]->ws_head.opcode != 9){ // 9:ping in websocekt protocol, don`t notify caller

					do_callback(1, fd, conn_list[fd]->ws_head.opcode);
				}

				int expired_data_pos = conn_list[fd]->read_cache_pos + conn_list[fd]->ws_head.payload_length; // 已经处理的数据的位置

				if(conn_list[fd]->read_data_len - conn_list[fd]->read_cache_pos - conn_list[fd]->ws_head.payload_length > 0){ // tcp粘包，半包
					memcpy(conn_list[fd]->read_cache, conn_list[fd]->read_cache + expired_data_pos, conn_list[fd]->read_data_len - expired_data_pos); // 只保留未处理的数据
				}

				conn_list[fd]->read_data_len = conn_list[fd]->read_data_len - expired_data_pos;
				conn_list[fd]->read_cache_pos=0;
				conn_list[fd]->error_times = 0;
			}

		} // if(status == HANDSHAKE)
	} // while 1

	return 0;
}

static inline int do_write_event(IoEvent* event)
{
	int ret = 0;
	do{
		if(!event || !event->pdata)
		{
			LOG("do_write_event error: event %x and event->pdata %x\n", event, event->pdata);
			ret = -1;
			break;
		}

		if(conn_list[event->fd] == NULL){

			LOG("send_data error:socket [%d] is not connectd\n", event->fd);
			ret = -3; 
			break;
		}   

		if(strcmp(event->key, conn_list[event->fd]->sec_key) != 0){ 
			LOG("send_data error:handler->key is[%s], and conn_list[%d]->sec_key is [%s]\n", event->key, event->fd, conn_list[event->fd]->sec_key);
			ret = -4; 
			break;
		}

		int n = send(event->fd, event->pdata+event->pos, event->data_len-event->pos, MSG_NOSIGNAL);
		event->pos += n;

	}while(0);


	if(ret < 0 || event->pos == event->data_len){ // all data is send

		modify_event(io_epfd, event->fd, EPOLLIN|EPOLLET|EPOLLERR, EPOLL_CTL_MOD);
		FREE(event->pdata);
		FREE(event);
	}
	return 0;
}

/** 每一个worker线程可以处理n个连接
 *  但每一个连接要由一个线程处理*/
void* worker_thread(void* arg)
{
	int index = (int)arg;
	thread_status[index].status = 0;
	sem_init(&((thread_status+index)->worker_sem), 0, 0);

	while(1){

		sem_wait(&(thread_status[index].worker_sem));
		if(thread_status[index].stop == 1){ 
			break;
		}

		thread_status[index].status = 1;

		if(thread_status[index].list_read_pos >= WORKER_LEN)
			thread_status[index].list_read_pos = 0;

		WorkEvent worker_event= thread_status[index].work_list[thread_status[index].list_read_pos++]; // read fd from task queue
		if(worker_event.event_type == 0){ // read event

			LOG("thread %d start work and socket is %d\n", index, worker_event.fd);
			do_read_event(worker_event.fd);

		}else if(worker_event.event_type == 1){ // write event

			IoEvent* ev = (IoEvent*)(worker_event.write_ptr);
			do_write_event(ev);
		}

		thread_status[index].status = 0;
		continue;
	}

	return NULL;
}

void inline destroy_worker()
{

	for(int i = 0; i< thread_num; i++){
		thread_status[i].stop = 1;
		sem_post( &((thread_status+i)->worker_sem) );
		pthread_join(thread_status[i].tid, NULL);
		sem_destroy( &((thread_status+i)->worker_sem) );
	}

	for(int i = 0;i < MAXCONN;i++){

		if(conn_list[i] != NULL){

			if(conn_list[i]->is_connected == 1)	{
				close(i);
			}

			FREE(conn_list[i]->read_cache);
			FREE(conn_list[i]);
		}
	}

	FREE(thread_status);
	close(io_epfd);
	pthread_exit(NULL);
}

static void add_task_queue(int thread_index, int fd, void* write_ptr)
{
	if(thread_status[thread_index].list_write_pos >= WORKER_LEN) // 任务队列是否达到最大值
		thread_status[thread_index].list_write_pos = 0;

	if(write_ptr)
	{
		thread_status[thread_index].work_list[thread_status[thread_index].list_write_pos].write_ptr = write_ptr; 
		thread_status[thread_index].work_list[thread_status[thread_index].list_write_pos].event_type = 1; 
	}else{

		thread_status[thread_index].work_list[thread_status[thread_index].list_write_pos].event_type = 0; 
	}

	thread_status[thread_index].work_list[thread_status[thread_index].list_write_pos++].fd = fd; // 写入任务队列
	LOG("choose worker thread:%d and socket is %d\n",  thread_index,fd);


	sem_post( &((thread_status+thread_index)->worker_sem) ); // 激活worker thread

	return ;
}

void* schedule_thread(void* arg)
{

	for(int i = 0; i < MAXCONN;i++) //预先分配最大连接数1/3的内存,其余的用到的时候再分配
	{   
		if(i < MAXCONN/3){

			conn_list[i] = (ConnArgs*)malloc(sizeof(ConnArgs));
			conn_list[i]->read_cache_len = CACHE_LEN;
			conn_list[i]->read_cache = (unsigned char*)malloc(conn_list[i]->read_cache_len);

		}else{
			conn_list[i] = NULL;
		}   
	}

	create_worker_threads(thread_num);

	io_epfd = epoll_create(1);

	while(1){

		int fd_count = epoll_wait(io_epfd, io_event_set, sizeof(io_event_set)/sizeof(struct epoll_event), -1);
		if(fd_count < 0)
		{
			LOG("epoll_wait failed:%s\n", strerror(errno));
			continue;
		}
		int i = 0;
		for(; i< fd_count; i++){

			if(io_event_set[i].events & EPOLLIN){

				int fd = io_event_set[i].data.fd;
				if(fd == mq_fd){ // stop task

					destroy_worker();
					return NULL;
				}

				int thread_index = conn_list[fd]->thread_index;
				if(thread_index != -1){ // 该连接已经绑定了workder线程,交给该线程
					add_task_queue(thread_index, fd, NULL);

				}else{    

					int j = 0;
					for(;j < thread_num; j++){

						if(thread_status[j].status == 0 ){ // 空闲状态

							conn_list[fd]->thread_index = j;
							add_task_queue(j, fd, NULL);
							break;
						}
					}

					if(j >= thread_num){ // 没有空闲线程

						conn_list[fd]->thread_index = fd%thread_num; // 任务均匀分配到每一个线程.未来有时间会引入时间片来调度worker线程
						add_task_queue(conn_list[fd]->thread_index, fd, NULL); 
					}
				}

			}else if(io_event_set[i].events & EPOLLOUT){

				IoEvent* data = (IoEvent*)io_event_set[i].data.ptr;

				if(!data || conn_list[data->fd]->thread_index < 0) // imposibble < 0,unless there is a bug
				{
					LOG("bug:data is %x and thread_index is %d\n", data, conn_list[data->fd]->thread_index);
					continue;
				}
				add_task_queue(conn_list[data->fd]->thread_index, data->fd, data);

			}else if(io_event_set[i].events & EPOLLERR){

				LOG("socket get EPOLLERR:%d\n", io_event_set[i].data.fd);
				del_conn(io_event_set[i].data.fd);
			}
		} 
	}

	return NULL;
}

void create_worker_threads(int num)
{
	thread_status = (ThreadStatus*)malloc(sizeof(ThreadStatus)* num);
	for(int i = 0;i < num;i++){

		memset(thread_status+i, 0x00, sizeof(thread_status[i]));
		pthread_create(&(thread_status[i].tid), NULL, worker_thread, (void*)i);
	}
}

pthread_t create_schedule_thread()
{
	pthread_t tid;
	pthread_create(&tid, NULL, schedule_thread, NULL);

	return tid;
}
