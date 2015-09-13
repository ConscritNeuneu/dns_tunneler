#ifndef LIB_H
#define LIB_H

#include <openssl/ssl.h>

struct ssl_mutual_exclusion {
	pthread_mutex_t ssl_connection_mutex;
	pthread_cond_t read_cond;
	pthread_cond_t write_cond;
	int num_wait_write_cond;
	int num_wait_read_cond;
	char someone_selects_write;
	char someone_selects_read;
	char connection_shutdown;
};

extern void * my_malloc(size_t size);
extern ssize_t read_with_select(SSL *ssl_connection, struct ssl_mutual_exclusion *ssl_exclusion, void *buf, size_t len, int tout);
extern ssize_t write_with_select(SSL *ssl_connection, struct ssl_mutual_exclusion *ssl_exclusion, void *buf, size_t len, int tout);
extern void openssl_lock_callback(int mode, int n, const char *file, int line);

#endif /* LIB_H */
