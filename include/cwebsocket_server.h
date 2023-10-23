
#ifndef _EPOLL_H_
#define _EPOLL_H_
#include <string> 

typedef struct _Ioevent
{
	int event_type; //-1:get error,0: connect event,1:io event

	int is_text;  //1:pdata is text,0:pdata is binary
	unsigned char* pdata; // data pointer for io
	int data_len;  // length of pdata
	int pos;       // already send pos in pdata  
	char key[64];  // The unique identifier of this connection
	int fd;
	
}IoEvent;

using namespace std;

typedef void (*CallBack)(IoEvent* data);
int start_server(int n);
int register_callback(string value, CallBack key);

int send_data(IoEvent* handler, unsigned char* buff, int buff_len, int is_text);
int send_stop();

#endif
