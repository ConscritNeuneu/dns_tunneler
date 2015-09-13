#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <pthread.h>

#include "lib.h"

#define BUFLEN 1500
#define TIMEOUT 20
/* quatramaran.ens.fr */
#define SERVER 129 + (199 << 8) + (129 << 16) + (64 << 24)
#define SERVER_PORT 5353

int dns_listen, quatra; /*sockets*/
struct sockaddr_in local, remote;

char is_connected = 0;
pthread_mutex_t is_connected_mutex = PTHREAD_MUTEX_INITIALIZER;

void *
receive_then_answer(void)
{
	/* I suppose i have a connected socket */
	while (1)
	{
		uint16_t length; 
		char prot_msg[BUFLEN + sizeof(uint16_t)];
		/* beware of alignment */
		uint16_t *port = (void *) prot_msg;
		char *dns_msg = prot_msg + 2;
		
		if (read_with_select(quatra,
		                     &length, sizeof(uint16_t),
		                     TIMEOUT) < 0)
			break;
		length = ntohs(length);
		if (length > BUFLEN + sizeof(uint16_t) || length <= sizeof(uint16_t))
			break;
		if (read_with_select(quatra, prot_msg, length, TIMEOUT) != length)
			break;

		struct sockaddr_in to_send;
		to_send.sin_family = AF_INET;
		to_send.sin_port = *port;
		to_send.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sendto(dns_listen,
		       dns_msg,
		       length - sizeof(uint16_t),
		       0,
		       (struct sockaddr *) &to_send,
		       sizeof(to_send));
	}

	pthread_mutex_lock(&is_connected_mutex);
	if(is_connected)
	{
		is_connected = 0;
		close(quatra);
		/* no need to join me as I closed myself the connection */
		pthread_detach(pthread_self());
	}
	pthread_mutex_unlock(&is_connected_mutex);
	return NULL;
}

void
listen_then_send(void)
{
	char mustjoin = 0;
	pthread_t recvanswer;
	while(1)
	{
		restart_loop:
		;
		char buf[BUFLEN], buf2[BUFLEN + 2 * sizeof(uint16_t)];
		struct sockaddr_in caller;
		socklen_t caller_len = sizeof(caller);
		ssize_t len = recvfrom(dns_listen,
		                       buf,
		                       BUFLEN,
		                       0,
		                       (struct sockaddr *) &caller,
		                       &caller_len);
		uint16_t length = htons(len + sizeof(uint16_t));
		uint16_t port = caller.sin_port;

		/* don't know here if there is another thread */
		pthread_mutex_lock(&is_connected_mutex);
		if (!is_connected)
		{
			/* If is_connected == 0, then there is no other
			 * thread */
			pthread_mutex_unlock(&is_connected_mutex);
			quatra = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
			int flags = fcntl(quatra, F_GETFL);
			fcntl(quatra, F_SETFL, flags | O_NONBLOCK);
			if (connect(quatra, (struct sockaddr *) &remote, sizeof(remote)) < 0)
			{
				fd_set wr_fd;
				FD_ZERO(&wr_fd);
				FD_SET(quatra, &wr_fd);
				struct timeval t_out;
				t_out.tv_sec = TIMEOUT;
				t_out.tv_usec = 0;

				switch (errno)
				{
					case EINPROGRESS:
					if (select(quatra + 1, NULL, &wr_fd, NULL, &t_out) > 0)
					{
						/* no timeout */
						int quatra_error;
						socklen_t quatra_error_len = sizeof(quatra_error);
						getsockopt(quatra, SOL_SOCKET, SO_ERROR, &quatra_error, &quatra_error_len);
						if (quatra_error == 0)
							break;
					}

					default:
					close(quatra);
					goto restart_loop;
				}
			}
			fcntl(quatra, F_SETFL, flags & ~O_NONBLOCK);
			if (pthread_create(&recvanswer,
			                   NULL,
			                   (void *(*)(void *)) &receive_then_answer,
			                   NULL) == 0)
			{
				is_connected = 1;
			}
			else
			{
				close(quatra);
				continue;
			}
		}
		else
			pthread_mutex_unlock(&is_connected_mutex);

		memcpy(buf2, &length, sizeof(length));
		memcpy(buf2 + sizeof(length), &port, sizeof(port));
		memcpy(buf2 + sizeof(length) + sizeof(port), buf, len);
		if (write_with_select(quatra, buf2, len + 2*sizeof(short), TIMEOUT) < 0)
		{
			/* could be badfd */
			pthread_mutex_lock(&is_connected_mutex);
			if (is_connected)
			{
				close(quatra);
				is_connected = 0;
				mustjoin = 1;
			}
			pthread_mutex_unlock(&is_connected_mutex);
			if (mustjoin)
			{
				void *thread_return;
				pthread_join(recvanswer, &thread_return);
				mustjoin = 0;
			}
		}
	}
}

int
main(void)
{
	dns_listen = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	local.sin_family = AF_INET;
	local.sin_port = htons(53);
	local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(dns_listen, (struct sockaddr *) &local, sizeof(local)) < 0)
	{
		perror("Bind");
		return EXIT_FAILURE;
	}
	remote.sin_family = AF_INET;
	remote.sin_port = htons(SERVER_PORT);
	remote.sin_addr.s_addr = SERVER;

	pid_t child_pid;
	if ((child_pid = fork()))
	{
		if (child_pid < 0)
		{
			perror("Fork");
			return EXIT_FAILURE;
		}
		printf("%d\n", child_pid);
		return EXIT_SUCCESS;
	}
	setsid();
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	listen_then_send();
	return EXIT_FAILURE;
}
