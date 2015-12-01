#ifndef __LIST_H__
#define __LIST_H__

#include "sysdef.h"

typedef struct list_s {
	char* index;
	void *entry;

    struct list_s *next;
}Node,*pNode;

pNode init_list();

pNode get_tail_list(struct list_s *l);

void insert_tail_list(struct list_s *l, pNode node);

void print_list_by_index(struct list_s *l);

void clear_list(struct list_s *l);

pNode rebuild_list_by_index(struct list_s *l);

void sort_list_by_index(struct list_s *l);

#endif
