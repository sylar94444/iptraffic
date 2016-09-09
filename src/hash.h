#ifndef __HASH_H__
#define __HASH_H__

#include "sysdef.h"
#include "list.h"

typedef int hashmap_iter;

/*
* These structures are the storage for the hashmap.  Entries are stored in
* struct hashentry_s (the key, data, and length), and all the "buckets" are
* grouped together in hashmap_s.  The hashmap_s.size member is for
* internal use.  It stores the number of buckets the hashmap was created
* with.
*/
struct hashentry_s {
    char *key;
    pNode data;

    struct hashentry_s *prev, *next;
};

struct hashbucket_s {
    struct hashentry_s *head, *tail;
};

struct hashmap_s {
    unsigned int size;
    hashmap_iter end_iterator;

    struct hashbucket_s *buckets;
};

/*
 * Simple CRC32 function
 */
int hf_crc32(const char *buf);
uint32_t hf_fnva(const char *buf);
          
/*
 * We're using a typedef here to "hide" the implementation details of the
 * hash map.  Sure, it's a pointer, but the struct is hidden in the C file.
 * So, just use the hashmap_t like it's a cookie. :)
 */
typedef struct hashmap_s *hashmap_t;

/*
 * hashmap_create() takes one argument, which is the number of buckets to
 * use internally.  hashmap_delete() is self explanatory.
 */
hashmap_t hashmap_create(unsigned int nbuckets);
int hashmap_delete(hashmap_t map);

/*
 * When the you insert a key/data pair into the hashmap it will the key
 * and data are duplicated, so you must free your copy if it was created
 * on the heap.  The key must be a NULL terminated string.  "data" must be
 * non-NULL and length must be greater than zero.
 *
 * Returns: negative on error
 *          0 upon successful insert
 */
int hashmap_insert(hashmap_t map, const char *key, pNode data);

/*
 * Get the first entry (assuming there is more than one) for a particular
 * key.  The data MUST be non-NULL.
 *
 * Returns: negative upon error
 *          zero if no entry is found
 *          length of data for the entry
 */
ssize_t hashmap_entry_by_key(hashmap_t map, const char *key,
                                     pNode *data);
/*
 * Go through the hashmap and remove the particular key.
 * NOTE: This will invalidate any iterators which have been created.
 *
 * Remove: negative upon error
 *         0 if the key was not found
 *         positive count of entries deleted
 */
ssize_t hashmap_remove(hashmap_t map, const char *key);


#endif
