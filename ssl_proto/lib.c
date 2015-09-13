#include <stdlib.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "lib.h"

void *
my_malloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL)
		exit(EXIT_FAILURE);
	return ptr;
}

enum rw_action {
	READ,
	WRITE
};


static ssize_t
shutdown_with_select(SSL *ssl_connection, int tout)
{
	int fd = SSL_get_fd(ssl_connection);
	int ret;
	while ((ret = SSL_shutdown(ssl_connection)) != 1)
	{
		fd_set fdset;
		fd_set *read_fdset, *write_fdset;
		struct timeval timeout;
		switch (SSL_get_error(ssl_connection, ret))
		{
			case SSL_ERROR_WANT_READ:
				read_fdset = &fdset;
				write_fdset = NULL;
				break;

			case SSL_ERROR_WANT_WRITE:
				read_fdset = NULL;
				write_fdset = &fdset;
				break;

			default:
				return -1;
		}

		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);
		timeout.tv_sec = tout;
                timeout.tv_usec = 0;
		select(fd + 1, read_fdset, write_fdset, NULL, &timeout);
		if (ret > 0)
			continue;
		else if (ret <= 0)
			break;
	}
	shutdown(fd, SHUT_RDWR);
	return -1;
}

static ssize_t
read_write_with_select(SSL *ssl_connection,
                       struct ssl_mutual_exclusion *ssl_exclusion,
                       enum rw_action op,
                       void *buf,
                       size_t len,
                       int tout)
{
        size_t done = 0;
        fd_set fdset;
	fd_set *read_fdset, *write_fdset;
        struct timeval timeout;
	int sock = SSL_get_fd(ssl_connection);
	ERR_clear_error();
        while (done < len)
        {
		int ret;
		pthread_mutex_lock(&(ssl_exclusion->ssl_connection_mutex));
	restart_op:
		if (ssl_exclusion->connection_shutdown)
		{
			pthread_mutex_unlock(&(ssl_exclusion->ssl_connection_mutex));
			return -1;
		}
		switch (op)
		{
			case READ:
			ret = SSL_read(ssl_connection, buf, len - done);
			break;

			case WRITE:
			ret = SSL_write(ssl_connection, buf, len - done);
			break;

			default:
			ret = 0;
		}
		/* must not release mutex, a r/w select could return 
		 * before I wait for the condition */
		enum { READ, WRITE, NOTHING } wait_op = NOTHING;
		if (ret < 0)
		{
			switch(SSL_get_error(ssl_connection, ret))
			{
				case SSL_ERROR_WANT_READ:
					if (ssl_exclusion->someone_selects_read)
					{
						ssl_exclusion->num_wait_read_cond++;
						pthread_cond_wait(&(ssl_exclusion->read_cond), &(ssl_exclusion->ssl_connection_mutex));
						ssl_exclusion->num_wait_read_cond--;
						goto restart_op;
					}
					else
					{
						ssl_exclusion->someone_selects_read = 1;
						wait_op = READ;
						read_fdset = &fdset;
						write_fdset = NULL;
					}
					break;
				case SSL_ERROR_WANT_WRITE:
					if (ssl_exclusion->someone_selects_write)
					{
						ssl_exclusion->num_wait_write_cond++;
						pthread_cond_wait(&(ssl_exclusion->write_cond), &(ssl_exclusion->ssl_connection_mutex));
						ssl_exclusion->num_wait_write_cond--;
						goto restart_op;
					}
					else
					{
						ssl_exclusion->someone_selects_write = 1;
						wait_op = WRITE;
						read_fdset = NULL;
						write_fdset = &fdset;
					}
					break;	
				default:
					break;
					
			}
		}
		pthread_mutex_unlock(&(ssl_exclusion->ssl_connection_mutex));

		if (ret > 0)
		{
			done += ret;
			continue;
		}
		else if (wait_op == NOTHING)
			goto return_minus_one;

                FD_ZERO(&fdset);
                FD_SET(sock, &fdset);
                timeout.tv_sec = tout;
                timeout.tv_usec = 0;
		ret = select(sock + 1, read_fdset, write_fdset, NULL, &timeout);
		if (ret < 0)
		{
			goto return_minus_one;
		}
		else if (ret == 0)
		{
			/*  Can't afford the wait */
			/* nobody must touch the connection during whole shutdown */
			pthread_mutex_lock(&(ssl_exclusion->ssl_connection_mutex));
			ret = shutdown_with_select(ssl_connection, tout/10);
			ssl_exclusion->connection_shutdown = 1;
			if (ssl_exclusion->num_wait_write_cond > 0)
				pthread_cond_broadcast(&(ssl_exclusion->write_cond));
			if (ssl_exclusion->num_wait_read_cond > 0)
				pthread_cond_broadcast(&(ssl_exclusion->read_cond));
			pthread_mutex_unlock(&(ssl_exclusion->ssl_connection_mutex));
			return ret;
		}
		else /* ret > 0 */
		{
			pthread_mutex_lock(&(ssl_exclusion->ssl_connection_mutex));
			switch (wait_op)
			{
				case READ:
					ssl_exclusion->someone_selects_read = 0;
					if (ssl_exclusion->num_wait_read_cond > 0)
						pthread_cond_broadcast(&(ssl_exclusion->read_cond));
					break;
				case WRITE:
					ssl_exclusion->someone_selects_write = 0;
					if (ssl_exclusion->num_wait_write_cond > 0)
						pthread_cond_broadcast(&(ssl_exclusion->write_cond));
					break;
				default:
					break;
			}
			pthread_mutex_unlock(&(ssl_exclusion->ssl_connection_mutex));
		}
        }
        return done;

	return_minus_one:
	pthread_mutex_lock(&(ssl_exclusion->ssl_connection_mutex));
	ssl_exclusion->connection_shutdown = 1;
	if (ssl_exclusion->num_wait_write_cond > 0)
		pthread_cond_broadcast(&(ssl_exclusion->write_cond));
	if (ssl_exclusion->num_wait_read_cond > 0)
		pthread_cond_broadcast(&(ssl_exclusion->read_cond));
	pthread_mutex_unlock(&(ssl_exclusion->ssl_connection_mutex));
	return -1;
}

ssize_t
read_with_select(SSL *ssl_connection, struct ssl_mutual_exclusion *ssl_exclusion, void *buf, size_t len, int tout)
{
	return read_write_with_select(ssl_connection, ssl_exclusion, READ, buf, len, tout);
}

ssize_t
write_with_select(SSL *ssl_connection, struct ssl_mutual_exclusion *ssl_exclusion, void *buf, size_t len, int tout)
{
	return read_write_with_select(ssl_connection, ssl_exclusion, WRITE, buf, len, tout);
}


static pthread_mutex_t *openssl_mutex_table;

static void
openssl_lock_init(void)
{
	int nlocks = CRYPTO_num_locks();
	openssl_mutex_table = my_malloc(nlocks * sizeof(pthread_mutex_t));
	for (int i = 0; i < nlocks; i++)
		pthread_mutex_init(openssl_mutex_table + i, NULL);
		/* *(openssl_mutex_table + i) = PTHREAD_MUTEX_INITIALIZER;*/
}

void
openssl_lock_callback(int mode,
                      int n,
                      const char *file __attribute__ ((unused)),
                      int line __attribute__ ((unused)))
{
	static pthread_once_t init_lock_ctrl = PTHREAD_ONCE_INIT;
	pthread_once(&init_lock_ctrl, openssl_lock_init);

	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(openssl_mutex_table + n);
	else
		pthread_mutex_unlock(openssl_mutex_table + n);
}
