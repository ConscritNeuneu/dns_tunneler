CC=gcc
LD=gcc
CFLAGS=-pthread -Wextra -Wall -std=c99 -pedantic -O
LDFLAGS=-pthread

all: client server

client: client.o lib.o

server: server.o lib.o

client.o: client.c lib.h

server.o: server.c lib.h

clean:
	rm -f *~ *.o client server
