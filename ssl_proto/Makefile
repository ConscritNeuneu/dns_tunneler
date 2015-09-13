CC=gcc
LD=gcc
CFLAGS=-pthread -Wextra -Wall -std=c99 -pedantic -O
LDFLAGS=-pthread

all: client server

client: client.o lib.o
	$(LD) $(LDFLAGS) -o client client.o lib.o -lcrypto -lssl

server: server.o lib.o
	$(LD) $(LDFLAGS) -o server server.o lib.o -lcrypto -lssl

client.o: client.c lib.h

server.o: server.c lib.h

clean:
	rm -f *~ *.o client server
