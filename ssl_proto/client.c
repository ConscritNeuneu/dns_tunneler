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
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "lib.h"

#ifndef PROGNAME
#define PROGNAME "dns_forwarder_client"
#endif /* PROGNAME */

#define BUFLEN 1500
#define TIMEOUT 20
/* quatramaran.ens.fr */
#ifndef SERVER
#define SERVER 129 + (199 << 8) + (129 << 16) + (64 << 24)
#ifndef SERVER_PORT
#define SERVER_PORT 5353
#endif /* SERVER_PORT */
#endif /* SERVER */

/* SSL Defines */
/* OpenSSL defines */
#ifndef CLIENT_CHAIN_FILE
#define CLIENT_CHAIN_FILE "client_chain.pem"
#endif /* CLIENT_CHAIN_FILE */
#ifndef CLIENT_PRIVATE_KEY_FILE
#define CLIENT_PRIVATE_KEY_FILE "client_private.pem"
#endif /* CLIENT_PRIVATE_KEY_FILE */
#ifndef CA_FILE
#define CA_FILE "ca.pem"
#endif /* CA_FILE */

const char *chain_file = CLIENT_CHAIN_FILE;
const char *key_file = CLIENT_PRIVATE_KEY_FILE;
const char *ca_file = CA_FILE;
uint32_t remote_ip  = SERVER;
uint16_t remote_port = SERVER_PORT;

int dns_listen, quatra; /*sockets*/
struct sockaddr_in local, remote;

/* SSL */
SSL *ssl_connection = NULL;
struct ssl_mutual_exclusion ssl_exclusion;
SSL_CTX *global_ssl_context;
/* END SSL */

char thread_launched = 0;
pthread_mutex_t thread_launched_mutex = PTHREAD_MUTEX_INITIALIZER;

void
usage(void)
{
	fprintf(stderr, "Usage : " PROGNAME " [--ip <ipaddr> ] [--cafile <cafile>]\n"
	                "[--keyfile <keyfile>] [--chainfile <chainfile>] [--port <port>]\n");
	exit(EXIT_FAILURE);
}

void
parse_command_line(char **argv)
{
	for(; *argv != NULL; argv++)
	{
		char *arg = *argv;
		if (*(arg++) != '-' || *(arg++) != '-')
			usage();
		switch (*arg)
		{
			case 'c':
				switch (*(arg+1))
				{
					case 'a':
						if (strcmp(arg, "cafile") == 0)
							ca_file = *(++argv);
						else usage();
						break;
					case 'h':
						if (strcmp(arg, "chainfile") == 0)
							chain_file = *(++argv);
						else usage();
						break;
					default:
						usage();
				}
				break;
			case 'i':
				if (strcmp(arg, "ip") == 0)
					remote_ip = inet_addr(*(++argv));
				else
					usage();
				break;
			case 'k':
				if (strcmp(arg, "keyfile") == 0)
					key_file = *(++argv);
				else
					usage();
				break;
			case 'p':
				if (strcmp(arg, "port") == 0)
					remote_port = atoi(*(++argv));
				break;
			default:
				usage();
				
		}
	}
}

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
		ssize_t ret;
		ret = read_with_select(ssl_connection, &ssl_exclusion, &length, sizeof(uint16_t), TIMEOUT);
		if (ret < 0)
			break;
		length = ntohs(length);
		if (length > BUFLEN + sizeof(uint16_t) || length <= sizeof(uint16_t))
			break;
		ret = read_with_select(ssl_connection, &ssl_exclusion, prot_msg, length, TIMEOUT);
		if (ret != length)
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

	/* must launch an error if we try to use socket */

	ERR_clear_error();
	ERR_remove_state(0);
	
	pthread_mutex_lock(&thread_launched_mutex);
	if (thread_launched)
	{
		close(quatra);
		thread_launched = 0;
		pthread_detach(pthread_self());
	}
	pthread_mutex_unlock(&thread_launched_mutex);

	return NULL;
}

void
listen_then_send(void)
{
	pthread_t recvanswer;
	SSL_SESSION *session = NULL;
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
		pthread_mutex_lock(&thread_launched_mutex);
		if (!thread_launched)
		{
			pthread_mutex_unlock(&thread_launched_mutex);
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

			if (ssl_connection)
			{
				session = SSL_get1_session(ssl_connection);
				SSL_free(ssl_connection);
				ssl_connection = NULL;
				ERR_clear_error();
			}
			if ((ssl_connection = SSL_new(global_ssl_context)) != NULL)
			{
				if (SSL_set_fd(ssl_connection, quatra) == 1)
				{
					SSL_set_connect_state(ssl_connection);
					if (session)
					{
						SSL_set_session(ssl_connection, session);
						SSL_SESSION_free(session);
						session = NULL;
					}

					memset(&ssl_exclusion, 0, sizeof(ssl_exclusion));

					pthread_mutex_lock(&thread_launched_mutex);
					if (pthread_create(&recvanswer, NULL, (void *(*)(void *)) &receive_then_answer, NULL) == 0)
					{
						thread_launched = 1;
						goto is_connected_now;
					}
					pthread_mutex_unlock(&thread_launched_mutex);
				}
				SSL_free(ssl_connection);
				ssl_connection = NULL;
			}
			ERR_clear_error();
			close(quatra);
			goto restart_loop;

			is_connected_now:
				;
		}
		pthread_mutex_unlock(&thread_launched_mutex);

		memcpy(buf2, &length, sizeof(length));
		memcpy(buf2 + sizeof(length), &port, sizeof(port));
		memcpy(buf2 + sizeof(length) + sizeof(port), buf, len);

		ssize_t ret = write_with_select(ssl_connection, &ssl_exclusion, buf2, len + 2*sizeof(short), TIMEOUT);

		if (ret < 0)		
		{
			char mustjoin = 0;
			pthread_mutex_lock(&thread_launched_mutex);
			if (thread_launched)
			{
				close(quatra);
				thread_launched = 0;
				mustjoin = 1;
			}
			pthread_mutex_unlock(&thread_launched_mutex);
			if (mustjoin)
			{
				void *thread_return;
				pthread_join(recvanswer, &thread_return);
			}

			/*
			session = SSL_get1_session(ssl_connection);
			SSL_free(ssl_connection);
			ssl_connection = NULL;
			ERR_clear_error();*/
		}
	}
}

int
main(int argc __attribute__ ((unused)), char *argv[])
{
	if (*(argv + 1) != NULL)
		parse_command_line(argv + 1);

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
	remote.sin_port = htons(remote_port);
	remote.sin_addr.s_addr = remote_ip;

	/* SSL INIT */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	CRYPTO_set_locking_callback(openssl_lock_callback);
	CRYPTO_set_id_callback((pthread_self));
	global_ssl_context = SSL_CTX_new(TLSv1_client_method());
	SSL_CTX_load_verify_locations(global_ssl_context, ca_file, NULL);
	SSL_CTX_use_certificate_chain_file(global_ssl_context, chain_file);
	SSL_CTX_use_PrivateKey_file(global_ssl_context, key_file, SSL_FILETYPE_PEM);
	SSL_CTX_check_private_key(global_ssl_context);
	SSL_CTX_set_verify(global_ssl_context, SSL_VERIFY_PEER, NULL);
	if (ERR_get_error() != 0)
	{
		fprintf(stderr, "Error with certificates\n");
		return EXIT_FAILURE;
	}
	/* END SSL INIT */

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
