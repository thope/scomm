VERSION = 1.0
CC = gcc
CFLAGS  = -g -Wall -DGMP_DESC -DLTC_SOURCE
LIBS = -ltomcrypt 
SRC = main.c socket.c crypto.c list.c
OBJ = ${SRC:.c=.o}

all: scomm

.c.o:
	${CC} -c ${CFLAGS} $<

scomm: ${OBJ}
	${CC} -o $@ ${OBJ} ${LIBS}

clean:
	rm scomm *.o

.PHONY: all clean
