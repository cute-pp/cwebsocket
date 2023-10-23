#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <sys/types.h>     
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <arpa/inet.h>
#include <map>
#include <mqueue.h>

#include "cwebsocket_server.h"
#include "worker_thread.h"
#include "log.h"

map<string, CallBack> funcMap;

#define SERVERPORT 30080

ConnArgs* conn_list[MAXCONN];

int conn_epfd;  // epoll fd:connected event 
int io_epfd;    // epoll fd:io event

int thread_num = 4; // create worker thread count
FILE* fp_log;       // TODO 日志暂时直接写文件吧,有时间再搞
mqd_t mq_fd;        // use stop server only

static int get_cpu_count()
{

	FILE* fp = popen("cat /proc/cpuinfo |grep 'processor'|wc -l", "r");
	if (!fp) {

		LOG("popen failed:%s\n", strerror(errno));
		return -1;
	}
	char tmp[512] = "";
	fgets(tmp, sizeof(tmp), fp);
	pclose(fp);

	return atoi(tmp);
}

void set_keepalive(int fd)
{

	int keep_idle = 3600, keep_alive = 1, keep_interval = 10, keep_count = 3;
	if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(keep_idle)) < 0){ 

		LOG("setsockopt SO_KEEPALIVE failed:%s\n", strerror(errno));
		return ;
	}   

	if(setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keep_idle, sizeof(keep_idle)) < 0){ 

		LOG("setsockopt TCP_KEEPIDLE failed:%s\n", strerror(errno));
	}   

	if(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &keep_interval, sizeof(keep_idle)) < 0){ 

		LOG("setsockopt TCP_KEEPIDLE failed:%s\n", strerror(errno));
	}   

	if(setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keep_count, sizeof(keep_idle)) < 0){ 

		LOG("setsockopt TCP_KEEPIDLE failed:%s\n", strerror(errno));
	}   

	return ;
}

static int create_tcp_server()
{
	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_fd < 0)
	{
		LOG("socket failed:%s\n");	
		return -1;
	}

	struct sockaddr_in localaddr;
	localaddr.sin_family = AF_INET; 
	localaddr.sin_addr.s_addr = inet_addr("0.0.0.0");
	localaddr.sin_port = htons(SERVERPORT);
	int socklen = sizeof(localaddr);

	int option=1;
	socklen_t optlen = sizeof(option);
	setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,(void*)&option,optlen);

	if (bind(sock_fd, (struct sockaddr*)&localaddr, socklen) < 0)
	{
		close(sock_fd);
		LOG("bind  failed:%s\n", strerror(errno));
		return -1;
	}

	if (listen(sock_fd, 256) < 0)
	{
		close(sock_fd);
		LOG("listen  faield:%s\n", strerror(errno));

		return -1;
	}

	LOG("create server success\n");

	return sock_fd;
}

static void stop_server(pthread_t schedule_tid, int sock_fd)
{
	epoll_ctl(conn_epfd, EPOLL_CTL_DEL, mq_fd, NULL);
	struct epoll_event ev;
	ev.events = EPOLLIN;
	ev.data.fd = mq_fd;	

	epoll_ctl(io_epfd, EPOLL_CTL_ADD, mq_fd, &ev); // add mq event
	send_stop();	                               // notify schedule thread to stop server
	pthread_join(schedule_tid, NULL);

	close(conn_epfd);
	close(sock_fd);
	mq_close(mq_fd);
	if(fp_log)
		fclose(fp_log);
	LOG("server stoped\n");
	return ;
}

static inline void init_conn_args(int index)
{
	if(conn_list[index] == NULL) {

		conn_list[index] = (ConnArgs*)malloc(sizeof(ConnArgs));
		conn_list[index]->read_cache_len = CACHE_LEN;
		conn_list[index]->read_cache = (unsigned char*)malloc(conn_list[index]->read_cache_len);
	}

	conn_list[index]->status = CONNECTED; // finish tcp three times handshake
	memset(conn_list[index]->method, 0x00, sizeof(conn_list[index]->method));
	memset(conn_list[index]->sec_key, 0x00, sizeof(conn_list[index]->sec_key));
	conn_list[index]->read_data_len = 0;
	conn_list[index]->thread_index = -1;
	conn_list[index]->is_connected = 1;  // mark it:need to close
}

int register_callback(string value, CallBack key)
{
	funcMap[value] = key;
	return 0;
}

int send_stop()
{
	LOG("stop\n");
	char cmd[]="stop";
	if(mq_send(mq_fd, cmd, sizeof(cmd), 0) < 0)
	{
		printf("mq_send failed:%s\n", strerror(errno));
	}
}

static int make_frame_head(IoEvent* handler, unsigned char* frame_head) // add websocket header
{

	if(!handler || !frame_head){
		LOG("handler is %x, frame_head is %x\n", handler, frame_head);
		return -1;
	}

	if(handler->is_text == 1)
		frame_head[0] = 0x81;
	else
		frame_head[0] = 0x82;

	if (handler->data_len < 126)
	{
		frame_head[1] = handler->data_len;
		return 2;
	}
	else if (handler->data_len < 0xFFFF)
	{
		frame_head[1] = 126;
		frame_head[2] = (handler->data_len >> 8 & 0xFF);
		frame_head[3] = (handler->data_len & 0xFF);
		return 4;

	}else{

		frame_head[1] = 127;
		frame_head[2] = (handler->data_len & 0x000000ff);
		frame_head[3] = ((handler->data_len & 0x0000ff00) >> 8);
		frame_head[4] = ((handler->data_len & 0x00ff0000) >> 16);
		frame_head[5] = ((handler->data_len & 0xff000000) >> 24);

		frame_head[6] = 0;
		frame_head[7] = 0;
		frame_head[8] = 0;
		frame_head[9] = 0;
		return 10;
	}
}

/***  send data   ****
 * send data is a Asynchronous event, so
 *
 * handler:  second argument of callback function
 * buff:     data to be send
 * buff_len: data length to be send
 * is_text:  0: data is binary
 * 			 1: data is text
 *
 * *******************/
int send_data(IoEvent* handler, unsigned char* buff, int buff_len, int is_text)
{

	if(!handler){
		LOG("send_data error:handler is %x\n", handler);
		return -1;
	}

	if(handler->fd < 0){
		LOG("send_data error:handler->fd is %d\n", handler->fd);
		return -2;
	}

	if(conn_list[handler->fd] == NULL){

		LOG("send_data error:socket [%d] is not connectd\n", handler->fd);
		return -3;
	}

	if(strcmp(handler->key, conn_list[handler->fd]->sec_key) != 0){
		LOG("send_data error:handler->key is[%s], and conn_list[%d]->sec_key is [%s]\n", handler->key, handler->fd, conn_list[handler->fd]->sec_key);
		return -4;
	}

	// because send data is a Asynchronous event, must be malloc new memory
	// and will be free after send  by worker thread
	IoEvent* event_data = (IoEvent*)malloc(sizeof(IoEvent));
	if(event_data == NULL)
	{
		LOG("send_data error:malloc failed:%s\n", strerror(errno));
		return -1;
	}

	memcpy(event_data, handler, sizeof(IoEvent));

	event_data->event_type = 1;
	event_data->is_text = is_text;
	event_data->data_len = buff_len;
	event_data->pos = 0;

	unsigned char head[10];
	int len =  make_frame_head(event_data, head);
	if(len < 0){
		return -1;
	}
	event_data->data_len = len + buff_len;

	MALLOC(event_data->pdata, unsigned char*, event_data->data_len);
	memcpy(event_data->pdata, head, len);
	memcpy(event_data->pdata + len, buff, buff_len);

	struct epoll_event ev;
	ev.events = EPOLLET|EPOLLOUT|EPOLLERR;
	ev.data.ptr = event_data;	
	epoll_ctl(io_epfd, EPOLL_CTL_MOD, handler->fd, &ev); // notify schedule thread,  do write event

	return 0;
}

int start_server(int num )
{	

	if(num <= 0){
		thread_num = get_cpu_count(); // get cpu count
		if(thread_num <= 0)
			thread_num = 4;
	}else 
		thread_num = num;

	mq_unlink("/anonymQueue");
	mq_fd = mq_open("/anonymQueue", O_RDWR | O_CREAT, 0666, NULL); // open mq for recv stop command
	if(mq_fd < 0){
		printf("mq_open failed:%s\n", strerror(errno));
		return -1;
	}	

	fp_log = fopen("log.txt", "w");

	pthread_t schedule_tid = create_schedule_thread();

	memset(conn_list, 0x00, sizeof(conn_list));

	int sock_fd = create_tcp_server();
	if(sock_fd < 0)
		return -1;

	conn_epfd = epoll_create(1);
	struct epoll_event conn_event_set[1];

	modify_event(conn_epfd, sock_fd, EPOLLIN|EPOLLERR, EPOLL_CTL_ADD);
	modify_event(conn_epfd, mq_fd, EPOLLIN, EPOLL_CTL_ADD);

	long long total_conns = 0;

	while(1)
	{
		int fd_count = epoll_wait(conn_epfd, conn_event_set, sizeof(conn_event_set)/sizeof(struct epoll_event), -1);
		if(fd_count < 0)
		{
			LOG("epoll_wait failed:%s\n", strerror(errno));
			continue;
		}
		int i = 0;
		for(; i< fd_count; i++){

			if(conn_event_set[i].data.fd == mq_fd){           // stop server

				stop_server(schedule_tid, sock_fd);
				return 0;
			}

			if(conn_event_set[i].data.fd == sock_fd){

				struct sockaddr_in client_addr;
				memset(&client_addr, 0x00 ,sizeof(struct sockaddr_in));
				socklen_t addr_len = sizeof(client_addr);
				int conn_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &addr_len);
				if (conn_fd < 0)
				{
					LOG("accept failed:%s\n", strerror(errno));
					continue;
				}
				LOG("\n\n");
				LOG("get %ld request:%s--%d---new socket:%d\n", ++total_conns, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), conn_fd);

				set_keepalive(conn_fd);

				int flags = fcntl(conn_fd, F_GETFL, 0);
				fcntl(conn_fd, F_SETFL, flags | O_NONBLOCK);

				init_conn_args(conn_fd);
				modify_event(io_epfd, conn_fd, EPOLLET|EPOLLIN|EPOLLERR, EPOLL_CTL_ADD);// notify schedule thread, wait io event

			}else if(conn_event_set[i].events & EPOLLERR){ 

				LOG("get fatal error:%s, exit epoll\n", strerror(errno));
				return -1;
			}

		} // for(i < fd_count)

	} // while(1)
}
