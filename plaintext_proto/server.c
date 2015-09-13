#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "lib.h"

#define LISTEN_PORT 5353
#define BUFLEN 1500
#define TIMEOUT 20
/* ns.ens.fr */
#define NAMESERVER 129 + (199 << 8) + (96 << 16) + (11 << 24)

struct transmit_order {
	pthread_mutex_t *write_mutex;
	int write_socket;
	size_t dns_len;
	void *buf;
	pthread_mutex_t *counter_mutex;
	pthread_cond_t *counter_cond;
	unsigned int *counter;
	uint16_t port;
};

struct sockaddr_in dns_server;


/* One for each message to send */
void *
transmit_then_answer(struct transmit_order *order)
{
	char resp_buf[BUFLEN + 2 * sizeof(uint16_t)];
	ssize_t resp_len;
	int dns_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	connect(dns_sock,
	        (struct sockaddr *) &dns_server,
	        sizeof(dns_server));
	send(dns_sock, order->buf, order->dns_len, 0);
	free(order->buf);
	order->buf = NULL;

	fd_set readfd;
	struct timeval timeout;

	while(1)
	{
		FD_ZERO(&readfd);
		FD_SET(dns_sock, &readfd);
		timeout.tv_sec = TIMEOUT;
		timeout.tv_usec = 0;
		if (select(dns_sock + 1, &readfd, NULL, NULL, &timeout) <= 0)
			break;
		resp_len = recv(dns_sock,
		                resp_buf + 2 * sizeof(uint16_t),
		                BUFLEN,
		                MSG_TRUNC);
		if (resp_len <= 0)
			break;
		if (resp_len > BUFLEN)
			continue;
		uint16_t resplen_networkorder = htons(resp_len + sizeof(uint16_t));
		memcpy(resp_buf, &resplen_networkorder, sizeof(uint16_t));
		memcpy(resp_buf + sizeof(uint16_t), &order->port, sizeof(uint16_t));

		pthread_mutex_lock(order->write_mutex);
		ssize_t ret = write_with_select(order->write_socket,
		                                resp_buf,
		                                resp_len + 2 * sizeof(uint16_t),
		                                TIMEOUT);
		pthread_mutex_unlock(order->write_mutex);
		if (ret < 0)
			break;
		
	}
	close(dns_sock);
	pthread_mutex_lock(order->counter_mutex);
	if ((--(*(order->counter))) == 0)
		pthread_cond_broadcast(order->counter_cond);
	pthread_mutex_unlock(order->counter_mutex);
	free(order);
	order = NULL;
	return NULL;
}

void *
consume_connection(int *spkr_socket_ptr)
{
	int spkr_socket = *spkr_socket_ptr;
	free(spkr_socket_ptr);
	spkr_socket_ptr = NULL;

	pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t counter_cond = PTHREAD_COND_INITIALIZER;
	unsigned int thr_counter = 0;
	
	while(1)
	{
		uint16_t length;
		uint16_t port;
		char *dns_msg = my_malloc(BUFLEN);

		ssize_t len_read;
		len_read = read_with_select(spkr_socket,
		                            &length,
		                            sizeof(length),
		                            TIMEOUT);
		if (len_read < 0 || (length = ntohs(length)) > BUFLEN + sizeof(uint16_t))
			break;

		len_read = read_with_select(spkr_socket,
		                            &port,
		                            sizeof(port),
		                            TIMEOUT);
		if (len_read < 0)
			break;

		len_read = read_with_select(spkr_socket,
		                            dns_msg,
		                            length - sizeof(port),
		                            TIMEOUT);
		if (len_read < 0)
			break;

		struct transmit_order *order = my_malloc(sizeof(struct transmit_order));
		order->write_mutex = &write_mutex;
		order->write_socket = spkr_socket;
		order->port = port;
		order->dns_len = length - sizeof(port);
		order->buf = dns_msg;
		order->counter = &thr_counter;
		order->counter_mutex = &counter_mutex;
		order->counter_cond = &counter_cond;

		pthread_t thread_id;
		pthread_attr_t thread_attributes;
		pthread_attr_init(&thread_attributes);
		pthread_attr_setdetachstate(&thread_attributes, PTHREAD_CREATE_DETACHED);

		pthread_mutex_lock(&counter_mutex);
		if (pthread_create(&thread_id,
		                   &thread_attributes,
		                   (void *(*)(void *)) &transmit_then_answer,
		                   order) == 0)
		{
			thr_counter++;
		}
		else
		{
			free(dns_msg);
			dns_msg = NULL;
			order->buf = NULL;
			free(order);
			order = NULL;
		}
		pthread_mutex_unlock(&counter_mutex);
	}

	pthread_mutex_lock(&counter_mutex);
	while (thr_counter != 0)
		pthread_cond_wait(&counter_cond, &counter_mutex);
	pthread_mutex_unlock(&counter_mutex);
	/* there should be no worker threads left using socket now */

	close(spkr_socket);
	return NULL;
}

int
main(void)
{
	int listen_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in listen_addr;
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_port = htons(5353);
	listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(listen_socket,
	    (struct sockaddr *) &listen_addr,
	    sizeof listen_addr) < 0)
	{
		perror("Bind");
		return EXIT_FAILURE;
	}
	
	pid_t pid = fork();
	if (pid > 0)
	{
		printf("%d\n", pid);
		return EXIT_SUCCESS;
	}
	else if (pid < 0)
	{
		perror("Fork");
		return EXIT_FAILURE;
	}

	if (listen(listen_socket, 16) < 0)
	{
		perror("Listen");
		return EXIT_FAILURE;
	}

	setsid();
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);

	dns_server.sin_family = AF_INET;
	dns_server.sin_port = htons(53);
	dns_server.sin_addr.s_addr = NAMESERVER;

	int *spkr_socket_ptr;
	while (1)
	{
		spkr_socket_ptr = my_malloc(sizeof (int));
		
		accept_again:
		if ((*spkr_socket_ptr = accept(listen_socket, NULL, NULL)) < 0)
		{
			switch (errno)
			{
				/* TCP protocol errors can go here */
				case ENETDOWN:
				case EPROTO:
				case ENOPROTOOPT:
				case EHOSTDOWN:
				case ENONET:
				case EHOSTUNREACH:
				case EOPNOTSUPP:
				case ENETUNREACH:
				goto accept_again;
				break;

				default:
				goto main_accept_error;
				break;
			}
		}

		pthread_t accept_thr;
		pthread_attr_t accept_thr_attr;
		pthread_attr_init(&accept_thr_attr);
		pthread_attr_setdetachstate(&accept_thr_attr,
		                            PTHREAD_CREATE_DETACHED);
		if (pthread_create(&accept_thr,
		                   &accept_thr_attr,
		                   (void *(*)(void *)) &consume_connection,
		                   spkr_socket_ptr))
		{
			close(*spkr_socket_ptr);
			free(spkr_socket_ptr);
			spkr_socket_ptr = NULL;
		}
	}
	main_accept_error:
	/* Should not happen */
	return EXIT_FAILURE;
}
