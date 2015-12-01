#ifndef __UTIL_H__
#define __UTIL_H__

#include "sysdef.h"

#define MALLOC(type, num)    (type *) alloc_buf((num) * sizeof(type))
#define FREE(p)              free_buf((p))
#define CLEAR(x)             memset(&(x), 0, sizeof(x))
#define SPACE(c)             ((c == '\0') || isspace (c))
#define STREQ(x, y)          (!strncmp((x), (y), strlen(y)))

void *alloc_buf (size_t size);

void free_buf(void *p);

FILE *open_file(const char *path, const char *mode);

void close_file(FILE *fp);

int read_file(void*buf, size_t len, FILE *fp);

int write_file(FILE *fp, void *buf, size_t len);

char *ignore_space(char *str);

int mac_str_to_bin(const char *str, char *mac);

#endif

