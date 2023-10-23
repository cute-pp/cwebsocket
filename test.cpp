#include "cwebsocket_server.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>

// don`t forget free data, if caller unuse it
void callback(IoEvent* data)
{

	//printf("callback:%d---[%s]\n", data->event_type, data->key);
	if(data->event_type == 1)
	{
	
		char buff[1024] = "";
		memcpy(buff, data->pdata, data->data_len);
		printf("%s\n", buff);
	}

	char p[5500+1] = "";;
	for(int i = 0; i < 5500;i++){
		p[i] = 'a';
	}
	//send_data(data, (unsigned char*)p, strlen(p), 1);
	return ;
}

void* func(void* arg)
{

	start_server(0);
}

int main()
{

	register_callback("/testfunc", callback);

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_t tid;
	pthread_create(&tid, &attr, func, NULL);

	//sleep(10);
	//send_stop();
	pause();
}
