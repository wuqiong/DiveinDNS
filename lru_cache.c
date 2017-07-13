#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lru_cache.h"
#include "uthash.h"

#ifdef USE_RWLOCK
#else
//USE_MUTEX
void * __gxx_personality_v0=0;
void * __gcc_personality_v0=0;
void * _Unwind_Resume =0;
#endif


/**
 * A cache entry
 */
struct record_cache_entry {
    char *key; /**<The key */
    void *data; /**<Payload */
    UT_hash_handle hh; /**<Hash Handle for uthash */
};
#define KEY_MAX_LENGTH		32

/**
 * A cache object
 */
struct record_cache {
    size_t max_entries; /**<Amount of entries this cache object can hold */
#ifdef USE_RWLOCK
    pthread_rwlock_t cache_lock; /**<A lock for concurrent access */
#else
    pthread_mutex_t cache_mutex;
#endif
    struct record_cache_entry *entries; /**<Head pointer for uthash */
    void (*free_cb) (void *element);/**<Callback function to free cache entries */
};

/** Creates a new cache object

    @param dst
    Where the newly allocated cache object will be stored in

    @param capacity
    The maximum number of elements this cache object can hold

    @return EINVAL if dst is NULL, ENOMEM if malloc fails, 0 otherwise
*/
int record_cache_create(struct record_cache **dst, const size_t capacity,
             void (*free_cb) (void *element))
{
    struct record_cache *new_cache = NULL;
    int rv;

    if (!dst)
        return EINVAL;

    if ((new_cache = malloc(sizeof(*new_cache))) == NULL)
        return ENOMEM;
#ifdef USE_RWLOCK
    if ((rv = pthread_rwlock_init(&(new_cache->cache_lock), NULL)) != 0)
        goto err_out;
#else
    if ((rv = pthread_mutex_init(&(new_cache->cache_mutex), NULL)) != 0)
        goto err_out;
#endif
    new_cache->max_entries = capacity;
    new_cache->entries = NULL;
    new_cache->free_cb = free_cb;
    *dst = new_cache;
    return 0;

err_out:
    if (new_cache)
        free(new_cache);
    return rv;
}

/** Frees an allocated cache object

    @param cache
    The cache object to free

    @param keep_data
    Whether to free contained data or just delete references to it

    @return EINVAL if cache is NULL, 0 otherwise
*/
int record_cache_delete(struct record_cache *cache, int keep_data)
{
    struct record_cache_entry *entry, *tmp;
    int rv;

    if (!cache)
        return EINVAL;
#ifdef USE_RWLOCK
    rv = pthread_rwlock_wrlock(&(cache->cache_lock));
#else
    rv = pthread_mutex_lock(&(cache->cache_mutex));
#endif
    if (rv)
        return rv;

    if (keep_data) {
        HASH_CLEAR(hh, cache->entries);
    } else {
        HASH_ITER(hh, cache->entries, entry, tmp) {
            HASH_DEL(cache->entries, entry);
            if (cache->free_cb)
                cache->free_cb(entry->data);
            free(entry);
        }
    }
#ifdef USE_RWLOCK
    (void)pthread_rwlock_unlock(&(cache->cache_lock));
    (void)pthread_rwlock_destroy(&(cache->cache_lock));
#ese
    (void)pthread_mutex_unlock(&(cache->cache_mutex));
    (void)pthread_mutex_destroy(&(cache->cache_mutex));
#endif
    free(cache);
    cache = NULL;
    return 0;
}

/** Checks if a given key is in the cache

    @param cache
    The cache object

    @param key
    The key to look-up

    @param result
    Where to store the result if key is found.

    A warning: Even though result is just a pointer,
    you have to call this function with a **ptr,
    otherwise this will blow up in your face.

    @return EINVAL if cache is NULL, 0 otherwise
*/
int record_cache_lookup(struct record_cache *cache, char *key, void *result)
{
    int rv;
    struct record_cache_entry *tmp = NULL;
    char **dirty_hack = result;

    if (!cache || !key || !result)
        return EINVAL;
#ifdef USE_RWLOCK
    rv = pthread_rwlock_wrlock(&(cache->cache_lock));
#else
    rv = pthread_mutex_lock(&(cache->cache_mutex));
#endif
    if (rv)
        return rv;

    HASH_FIND_STR(cache->entries, key, tmp);
    if (tmp) {
        size_t key_len = strnlen(tmp->key, KEY_MAX_LENGTH);
        HASH_DELETE(hh, cache->entries, tmp);
        HASH_ADD_KEYPTR(hh, cache->entries, tmp->key, key_len, tmp);
        *dirty_hack = tmp->data;
    } else {
        *dirty_hack = result = NULL;
    }
#ifdef USE_RWLOCK
    rv = pthread_rwlock_unlock(&(cache->cache_lock));
#else
    rv = pthread_mutex_unlock(&(cache->cache_mutex));
#endif
    return rv;
}

/** Inserts a given <key, value> pair into the cache

    @param cache
    The cache object

    @param key
    The key that identifies <value>

    @param data
    Data associated with <key>

    @return EINVAL if cache is NULL, ENOMEM if malloc fails, 0 otherwise
*/
int record_cache_insert(struct record_cache *cache, char *key, void *data)
{
    struct record_cache_entry *entry = NULL;
    struct record_cache_entry *tmp_entry = NULL;
    size_t key_len = 0;
    int rv;

    if (!cache || !data)
        return EINVAL;

    if ((entry = malloc(sizeof(*entry))) == NULL)
        return ENOMEM;
#ifdef USE_RWLOCK
    if ((rv = pthread_rwlock_wrlock(&(cache->cache_lock))) != 0)
        goto err_out;
#else
    if ((rv = pthread_mutex_lock(&(cache->cache_mutex))) != 0)
        goto err_out;
#endif
    entry->key = key;
    entry->data = data;
    key_len = strnlen(entry->key, KEY_MAX_LENGTH);
    HASH_ADD_KEYPTR(hh, cache->entries, entry->key, key_len, entry);

    if (HASH_COUNT(cache->entries) >= cache->max_entries) {
        HASH_ITER(hh, cache->entries, entry, tmp_entry) {
            HASH_DELETE(hh, cache->entries, entry);
            if (cache->free_cb)
                cache->free_cb(entry->data);
            else
                free(entry->data);
            /* free(key->key) if data has been copied */
            free(entry);
            break;
        }
    }

#ifdef USE_RWLOCK
    rv = pthread_rwlock_unlock(&(cache->cache_lock));
#else
    rv = pthread_mutex_unlock(&(cache->cache_mutex));
#endif
    return rv;

err_out:
    if (entry)
        free(entry);
#ifdef USE_RWLOCK
    (void)pthread_rwlock_unlock(&(cache->cache_lock));
#else
    (void)pthread_mutex_unlock(&(cache->cache_mutex));
#endif
    return rv;

}
