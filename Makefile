SRC=cwebsocket_server.o test.o worker_thread.o
TARGET=cwebsocket_server
LIBS=-L./3rd_lib -lcrypto -lssl -pthread -lrt
OPT=-std=c++11 -Wint-to-pointer-cast -fpermissive -w
INC=-I./include

${TARGET}:${SRC}
	g++  ${SRC}   -o ${TARGET} ${LIBS} -Wl,-rpath=${PWD}/3rd_lib
%.o:%.cpp
	g++  -c  $^ -o $@ ${OPT} ${INC}

.PHONY : clean
clean:
	rm -f ${TARGET}
	rm -f *.o
