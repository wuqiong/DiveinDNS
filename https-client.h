#ifndef HTTPSCLIENT_H
#define HTTPSCLIENT_H

#ifdef WITH_HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "openssl_hostname_validation.h"
#endif

#include <evdns.h>
#include "lru_cache.h"

struct dns_record {
    char *key; //name
    char *value; //record
    time_t  expire_time;
};
extern struct record_cache *record_cache;

void free_record_entry(void *entry);

void
http_dns_resolve(struct event_base *base, const char *name, struct evdns_server_request *dns_req, char *cert_path);
#endif // HTTPSCLIENT_H

