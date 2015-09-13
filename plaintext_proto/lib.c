#include <stdlib.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "lib.h"

void *
my_malloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL)
		exit(EXIT_FAILURE);
	return ptr;
}

ssize_t
read_with_select(int sock, void *buf, size_t len, int tout)
{
        size_t read = 0;
        fd_set readfd;
        struct timeval timeout;
        while (read < len)
        {
                FD_ZERO(&readfd);
                FD_SET(sock, &readfd);
                timeout.tv_sec = tout;
                timeout.tv_usec = 0;
                if (select(sock + 1, &readfd, NULL, NULL, &timeout) <= 0)
                        return -1;
                ssize_t howmany;
                /* 0 means EOF */
                if ((howmany = recv(sock, ((char *) buf) + read, len - read, 0)) <= 0)
                        return -1;
                read += howmany;
        }
        return read;
}

ssize_t
write_with_select(int sock, void *buf, size_t len, int tout)
{
	size_t sent = 0;
	fd_set writefd;
	struct timeval timeout;
	while (sent < len)
	{
		FD_ZERO(&writefd);
		FD_SET(sock, &writefd);
		timeout.tv_sec = tout;
		timeout.tv_usec = 0;
		if (select(sock + 1, NULL, &writefd, NULL, &timeout) <= 0)
			return -1;
		ssize_t howmany;
		if ((howmany = send(sock, ((char *) buf) + sent, len - sent, 0)) <= 0)
			return -1;
		sent += howmany;
	}
	return sent;
}
