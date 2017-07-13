#ifndef LRU_CACHE_H
#define LRU_CACHE_H

struct record_cache;

extern int record_cache_create(struct record_cache **dst, const size_t capacity,
                void (*free_cb) (void *element));

extern int record_cache_delete(struct record_cache *cache, int keep_data);
extern int record_cache_lookup(struct record_cache *cache, char *key, void *result);
extern int record_cache_insert(struct record_cache *cache, char *key, void *data);

#endif // LRU_CACHE_H
