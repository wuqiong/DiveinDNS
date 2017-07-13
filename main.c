#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <event2/event-config.h>
#include <event.h>
#include <evdns.h>
#include <evutil.h>



#include <sys/types.h>

#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <getopt.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/util.h>

#ifdef EVENT__HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "https-client.h"

#define u32 ev_uint32_t
#define u8 ev_uint8_t



//global
int need_daemon = 0;
int listen_port = 0;
int cache_size = 0;
char cert_path[256];


typedef struct dns_forword_context
{
    struct evdns_server_request *orig_req;
    const char *name;
}dns_forword_context;

struct event_base_context
{
    struct event_base *event_base;
    struct evdns_base *evdns_base;
    struct record_cache *record_cache;

}base_context;


void parse_argument(int argc, char * const argv[]);



static void
evdns_client_callback(int result, char type, int count, int ttl,
              void *addrs, void *orig) {

    dns_forword_context *fwd_context = (dns_forword_context *)orig;
    int i;

    if (result == DNS_ERR_TIMEOUT || result != DNS_ERR_NONE ) {
        goto out;
    }

    for (i = 0; i < count; ++i) {

        if (type == DNS_IPv4_A) {

            u32 ans = ((u32*)addrs)[i];
            evdns_server_request_add_a_reply(fwd_context->orig_req, fwd_context->name,
                                          1, &ans, ttl);

        } else if (type == DNS_IPv6_AAAA) {
            struct in6_addr *in6_addrs = addrs;
            evdns_server_request_add_aaaa_reply(fwd_context->orig_req, fwd_context->name,
                                                1, in6_addrs+i, ttl);
        }else if (type == DNS_PTR) {

            evdns_server_request_add_ptr_reply(fwd_context->orig_req, NULL, fwd_context->name,
                                               ((char**)addrs)[i], ttl);
        }
    }
out:
    evdns_server_request_respond(fwd_context->orig_req, 0);
    free(fwd_context);
}


static void
evdns_server_callback(struct evdns_server_request *req, void *data)
{
    int i;
    int request_forwarded = 0;
    struct event_base_context *base_context = (struct event_base_context*)data;
    struct evdns_base *evdns_base = base_context->evdns_base;
    struct event_base *event_base = base_context->event_base;


    for (i = 0; i < req->nquestions; ++i) {


        char *name = req->questions[i]->name;

        if (req->questions[i]->type == EVDNS_TYPE_A &&
            req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {

            struct dns_record *result = NULL;
            record_cache_lookup(record_cache, name, &result);
            if (result == NULL || result->expire_time < time(NULL)) {
                //cache miss
                fprintf(stdout,"DNS CACHE MISS: %s \n", name);
                http_dns_resolve(event_base, name, req, cert_path);
                request_forwarded = 1;
             }else{
                //cache hit
                fprintf(stdout,"DNS CACHE HIT: %s : %s  expire_time:%s",
                        name, result->value, ctime(&(result->expire_time)));
                int ttl = 0;
                int len = strlen(result->value);
                char *buffer = malloc(len+1);
                char formart[32];
                snprintf(formart,sizeof(formart)-1, "%%%d[^,],%%d",len);
                sscanf(result->value,formart, buffer, &ttl);
                //update ttl
                ttl = result->expire_time - time(NULL);
                //min ttl 60s
                ttl = ttl < 60 ?60:ttl;

                for (char *ip = strtok(buffer,";"); ip != NULL; ip = strtok(NULL, ";"))
                {
                  struct in_addr ans;
                  evutil_inet_pton(AF_INET, ip, &ans);
                  evdns_server_request_add_a_reply(req, name,
                                                       1, &ans, ttl);
                }
                free(buffer);
            }


        } else if (req->questions[i]->type == EVDNS_TYPE_AAAA &&
                   req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {

            dns_forword_context *fwd_context = calloc(1, sizeof(dns_forword_context));
            fwd_context->orig_req = req;
            fwd_context->name = name;
            evdns_base_resolve_ipv6(evdns_base, name, 0, evdns_client_callback, fwd_context);
            request_forwarded = 1;

        }
#if 0
        else if (req->questions[i]->type == EVDNS_TYPE_PTR &&
            req->questions[i]->dns_question_class == EVDNS_CLASS_INET) {

            dns_forword_context *fwd_context = calloc(1, sizeof(dns_forword_context));
            fwd_context->orig_req = req;
            fwd_context->name = name;
            struct in6_addr in6_addrs;
            struct in_addr in_addrs;

            if(evutil_inet_pton(AF_INET6, name, &in6_addrs)) {

                evdns_base_resolve_reverse_ipv6(evdns_base, &in6_addrs, 0, evdns_client_callback, fwd_context);
                request_forwarded = 1;

            }else if(evutil_inet_pton(AF_INET, name, &in_addrs)) {

                evdns_base_resolve_reverse(evdns_base, &in_addrs, 0, evdns_client_callback, fwd_context);
                request_forwarded = 1;
            }

        }
#endif
        else {
//            printf(" -- skipping %s [%d %d]\n", req->questions[i]->name,
//                   req->questions[i]->type, req->questions[i]->dns_question_class);
        }
    }


    if (!request_forwarded){
        evdns_server_request_respond(req, 0);
    }


}




int
main(int argc,  char * const argv[]) {

    int ret = 0;
    struct event_base *event_base = NULL;
    struct evdns_base *evdns_base = NULL;

    parse_argument(argc,argv);

#ifdef _WIN32
    {
        WSADATA WSAData;
        WSAStartup(0x101, &WSAData);
    }
#endif

    event_base = event_base_new();
    evdns_base = evdns_base_new(event_base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
    record_cache_create(&record_cache, cache_size, free_record_entry);

    base_context.evdns_base = evdns_base;
    base_context.event_base = event_base;


    evutil_socket_t ipv4_sock;

    //ipv4 sock
    struct sockaddr_in my_addr_in;
    ipv4_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (ipv4_sock == -1) {
        perror("socket");
        ret = -1;
        goto cleanup;
    }
    evutil_make_socket_nonblocking(ipv4_sock);
    my_addr_in.sin_family = AF_INET;
    my_addr_in.sin_port = htons(listen_port);
    my_addr_in.sin_addr.s_addr = INADDR_ANY;
    if (bind(ipv4_sock, (struct sockaddr*)&my_addr_in, sizeof(my_addr_in))<0) {
        perror("bind");
        ret = -2;
        goto cleanup;
    }
    //ipv4  dns server
    evdns_add_server_port_with_base(event_base, ipv4_sock, 0, evdns_server_callback, &base_context);


    //resolve configure

#ifdef _WIN32
    evdns_base_config_windows_nameservers(evdns_base);
#endif
    evdns_base_set_option(evdns_base, "randomize-case:", "0");//TurnOff DNS-0x20 encoding
    evdns_base_nameserver_ip_add(evdns_base, "180.76.76.76");//BaiduDNS
    evdns_base_nameserver_ip_add(evdns_base, "223.5.5.5");//AliDNS
    evdns_base_nameserver_ip_add(evdns_base, "223.6.6.6");//AliDNS
    evdns_base_nameserver_ip_add(evdns_base, "114.114.114.114");//114DNS
    evdns_base_nameserver_ip_add(evdns_base, "8.8.8.8");//GoogleDNS
    evdns_base_nameserver_ip_add(evdns_base, "119.29.29.29");//DnsPodDNS

#ifdef WITH_RESOLV
    evdns_base_resolv_conf_parse(evdns_base,
                                 DNS_OPTION_NAMESERVERS, "/etc/resolv.conf");
#ifdef EVDNS_BASE_CONFIG_WINDOWS_NAMESERVERS_IMPLEMENTED
    evdns_base_config_windows_nameservers(evdns_base);
#endif

#endif

    event_base_dispatch(event_base);



cleanup:
#ifdef WITH_HTTPS
    EVP_cleanup();
    ERR_free_strings();
#ifdef EVENT__HAVE_ERR_REMOVE_THREAD_STATE
    ERR_remove_thread_state(NULL);
#else
    ERR_remove_state(0);
#endif
    CRYPTO_cleanup_all_ex_data();
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
#endif
    evdns_base_free(evdns_base,1);
    event_base_free(event_base);

    (void)record_cache_delete(record_cache, 0);

#ifdef _WIN32
    WSACleanup();
#endif
    return ret;
}


void print_usage(const char *execname)
{
    printf("Usage: %s %s -p [port num] -s [cache size] -c [certificate filepath] -h\n",
           execname,
       #ifdef _WIN32
                  ""
       #else
                  "-d"
       #endif
           );
}

void parse_argument(int argc, char * const argv[])
{
    int option = 0;
    while ((option = getopt(argc, argv,"dp:s:c:h")) != -1) {
        switch (option) {
            case 'd' :
            {
                need_daemon = 1;
                break;
            }
            case 'p' :
            {
                listen_port = atoi(optarg);
                break;
            }
            case 's' :
            {
                cache_size = atoi(optarg);
                break;
            }
            case 'c' :
            {
                strncpy(cert_path,optarg,sizeof(cert_path)-1);
                break;
            }
            case 'h':
            default:
            {
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
        }
    }

    cache_size = cache_size <=0 ? 1024*1024 : cache_size;
    listen_port = listen_port <=0 ? 10053 : listen_port;
#ifndef _WIN32
#ifdef WITH_DAEMON
    if(need_daemon) daemon(1,0);
#endif
#endif
}


