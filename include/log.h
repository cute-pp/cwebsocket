#ifndef _LOG_H_
#define _LOG_H_
#include <stdio.h>
#if 0
#define LOG(_format, ...)\
{\
	if(strcmp(_format, "\n\n") == 0){\
		fprintf(fp_log, "\n\n");\
		fflush(fp_log);\
	}else{\
	fprintf(fp_log, "[%s:%d]--" _format, __FILE__, __LINE__, ##__VA_ARGS__);\
	fflush(fp_log);\
	}\
}
#else
#define LOG(_format, ...)\
{\
}
#endif
#endif
