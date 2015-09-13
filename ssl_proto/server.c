#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/dh.h>
#include <openssl/err.h>

#include "lib.h"

#define LISTEN_PORT 5353
#define BUFLEN 1500
#define TIMEOUT 60
/* ns.ens.fr */
#define NAMESERVER 129 + (199 << 8) + (96 << 16) + (11 << 24)

/* OpenSSL defines */
#ifndef SERVER_CHAIN_FILE
#define SERVER_CHAIN_FILE "server_chain.pem"
#endif /* SERVER_CHAIN_FILE */
#ifndef SERVER_PRIVATE_KEY_FILE
#define SERVER_PRIVATE_KEY_FILE "server_private.pem"
#endif /* SERVER_PRIVATE_KEY_FILE */
#ifndef CA_FILE
#define CA_FILE "ca.pem"
#endif /* CA_FILE */
#ifndef DH_PARAMS_FILE
#define DH_PARAMS_FILE "dh_params.pem"
#endif /* DH_PARAMS_FILE */

struct transmit_order {
	pthread_mutex_t *write_mutex;
	struct ssl_mutual_exclusion *ssl_exclusion;
	SSL *ssl_connection;
	size_t dns_len;
	void *buf;
	pthread_mutex_t *counter_mutex;
	pthread_cond_t *counter_cond;
	unsigned int *counter;
	uint16_t port;
};

struct sockaddr_in dns_server;

/* SSL thingies */
SSL_CTX *global_ssl_context;

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
		ssize_t ret = write_with_select(order->ssl_connection,
		                                order->ssl_exclusion,
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

	/* SSL Cleanup */
	ERR_clear_error();
	ERR_remove_state(0);

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

	struct ssl_mutual_exclusion ssl_exclusion;
	memset(&ssl_exclusion, 0, sizeof (ssl_exclusion));

	/* SSL INIT */
	SSL *ssl_connection = NULL;
	if ((ssl_connection = SSL_new(global_ssl_context)) == NULL ||
	     SSL_set_fd(ssl_connection, spkr_socket) != 1)
		goto cleanup;
	SSL_set_accept_state(ssl_connection);
	/* END SSL INIT */
	
	while(1)
	{
		uint16_t length;
		uint16_t port;
		char *dns_msg = my_malloc(BUFLEN);

		ssize_t len_read;
		len_read = read_with_select(ssl_connection,
		                            &ssl_exclusion,
		                            &length,
		                            sizeof(length),
		                            TIMEOUT);
		if (len_read < 0 || (length = ntohs(length)) > BUFLEN + sizeof(uint16_t))
			break;

		len_read = read_with_select(ssl_connection,
		                            &ssl_exclusion,
		                            &port,
		                            sizeof(port),
		                            TIMEOUT);
		if (len_read < 0)
			break;

		len_read = read_with_select(ssl_connection,
		                            &ssl_exclusion,
		                            dns_msg,
		                            length - sizeof(port),
		                            TIMEOUT);
		if (len_read < 0)
			break;

		struct transmit_order *order = my_malloc(sizeof(struct transmit_order));
		order->write_mutex = &write_mutex;
		order->ssl_exclusion = &ssl_exclusion;
		order->ssl_connection = ssl_connection;
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

	shutdown(spkr_socket, SHUT_WR);

	pthread_mutex_lock(&counter_mutex);
	while (thr_counter != 0)
		pthread_cond_wait(&counter_cond, &counter_mutex);
	pthread_mutex_unlock(&counter_mutex);
	/* there should be no worker threads left using socket now */

	cleanup:
	if (ssl_connection != NULL)
	{
		SSL_free(ssl_connection);
	}
	ERR_clear_error();
	ERR_remove_state(0);
	close(spkr_socket);
	return NULL;
}

int
main(void)
{
	int listen_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in listen_addr;
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_port = htons(LISTEN_PORT);
	listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(listen_socket,
	    (struct sockaddr *) &listen_addr,
	    sizeof listen_addr) < 0)
	{
		perror("Bind");
		return EXIT_FAILURE;
	}

	/* SSL INIT */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	CRYPTO_set_locking_callback(openssl_lock_callback);
	CRYPTO_set_id_callback((pthread_self));
	global_ssl_context = SSL_CTX_new(TLSv1_server_method());
	/* ERR_get_error will catch errors */
	SSL_CTX_load_verify_locations(global_ssl_context, CA_FILE, NULL);
	SSL_CTX_use_certificate_chain_file(global_ssl_context, SERVER_CHAIN_FILE);
	SSL_CTX_use_PrivateKey_file(global_ssl_context, SERVER_PRIVATE_KEY_FILE, SSL_FILETYPE_PEM);
	SSL_CTX_check_private_key(global_ssl_context);
	char ssl_cert_error = 0;
	FILE *client_ca_cert_file = fopen(CA_FILE, "r");
	if (client_ca_cert_file)
	{
		/* may I call x509_free after use ?? */
		X509 *client_ca_cert = NULL;
		client_ca_cert = PEM_read_X509(client_ca_cert_file,
		                               &client_ca_cert,
		                               NULL,
		                               NULL);
		if (client_ca_cert)
			SSL_CTX_add_client_CA(global_ssl_context, client_ca_cert);
			
		else
			ssl_cert_error = 1;
		fclose(client_ca_cert_file);
	}
	else
		ssl_cert_error = 1;
	SSL_CTX_set_verify(global_ssl_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	if (ssl_cert_error || ERR_get_error() != 0)
	{
		fprintf(stderr, "Error with certificates\n");
		return EXIT_FAILURE;
	}
	FILE *paramfile = fopen(DH_PARAMS_FILE, "r");
	if (paramfile)
	{
		/* may I call dh_free it after use ?? */
		DH *dhparm = NULL;
		dhparm = PEM_read_DHparams(paramfile, &dhparm, NULL, NULL);
		if (dhparm)
			SSL_CTX_set_tmp_dh(global_ssl_context, dhparm);
		fclose(paramfile);
		paramfile = NULL;
	}
	unsigned char sid_ctx[16];
	FILE *urandom = fopen("/dev/urandom", "r");
	if (urandom)
	{
		if (fread(sid_ctx, 16, 1, urandom) == 1)
			SSL_CTX_set_session_id_context(global_ssl_context,
			                               sid_ctx,
			                               16);
		fclose(urandom);
		urandom = NULL;
	}
	/* END SSL_INIT */
	
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

		int flags = fcntl(*spkr_socket_ptr, F_GETFL);
		fcntl(*spkr_socket_ptr, F_SETFL, flags | O_NONBLOCK);

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
