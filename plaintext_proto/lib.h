#ifndef LIB_H
#define LIB_H

extern void * my_malloc(size_t size);
extern ssize_t read_with_select(int sock, void *buf, size_t len, int tout);
extern ssize_t write_with_select(int sock, void *buf, size_t len, int tout);


#endif /* LIB_H */
