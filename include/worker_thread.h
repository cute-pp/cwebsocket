#ifndef _THREAD_POLL_h_
#define _THREAD_POLL_h_
#include <semaphore.h>
#include <string>
#include <map>
#include "cwebsocket_server.h"
#include <sys/epoll.h>
#include <mqueue.h>
#include <pthread.h>
using namespace std;

#define MAXCONN 65535

#define MALLOC(ptr, type, n)\
{\
	ptr = (type)malloc(n);\
	if(ptr == NULL){\
		LOG("mem alloc failed:%s\n", strerror(errno));\
		return -1;\
	}\
}

#define REALLOC(ptr, type, n)\
{\
	ptr = (type)realloc(ptr, n);\
	if(ptr == NULL){\
		LOG("mem alloc failed:%s\n", strerror(errno));\
		return -1;\
	}\
}

#define FREE(ptr){ \
	if(ptr){ \
		free(ptr); \
		ptr = NULL; \
	} \
}

/***   websocket protocol header  ***/
typedef struct _FrameHead {
	char fin;
	char opcode;
	char mask;
	unsigned long long payload_length;
	char masking_key[4];
}FrameHead;

typedef struct _ConnArgs
{
	int status;                        // CONNECTED or HANDSHAKE 
	char sec_key[64];                  // sec_key in websocket protocol

	unsigned char* read_cache;           
	unsigned long long read_cache_len; // total length of cache
	unsigned long long read_data_len;  // data length in cache
	unsigned long long read_cache_pos; // 缓存中已经处理的数据位置 

	char method[64];              // requset method in http header
	char thread_index;             // witch worker thread handle this request in threads poll  
	char is_connected;             // 1:connecting, need close,0: not connect ,no need close 

	char get_ws_header;            // 0:will recv data until get websocket header 1: already get websocket header
	FrameHead ws_head;

	char error_times;               // max error times

}ConnArgs;

enum  ConnStatus
{
	UNCONNECT=1,
	CONNECTED, // tcp connected complete
	HANDSHAKE  // websocket handshake complete
};


typedef struct _MyData
{
	unsigned char* buffer;
	int data_len;
	int fd;
	int buffer_pos;
}MyData;


#define CACHE_LEN 1024 
#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

extern map<string, CallBack> funcMap;
extern int io_epfd;
extern int thread_num;
extern FILE* fp_log;
extern mqd_t mq_fd;
extern ConnArgs* conn_list[MAXCONN]; // all clients
void modify_event(int epfd, int fd, uint32_t events, int op);
void create_worker_threads(int num);
pthread_t create_schedule_thread();
#endif
