

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define snprintf _snprintf
#define strcasecmp _stricmp
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#ifdef WITH_HTTPS
#include <event2/bufferevent_ssl.h>
#endif
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>


#include "https-client.h"

struct record_cache *record_cache;

typedef struct HTTP_Context
{
#ifdef WITH_HTTPS
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#endif
    struct bufferevent *bev;
    struct evhttp_connection *evcon;
    struct evhttp_uri *http_uri;
    const char *dns_name;
    struct evdns_server_request *httpdns_req;
} HTTP_Context;

void free_record_entry(void *entry)
{

    struct dns_record *record = entry;
    if (!record)
        return;
    if (record->value)
        free(record->value);
    if (record->key)
        free(record->key);
    free(record);
    record = NULL;
}

static void
http_request_done(struct evhttp_request *req, void *ctx)
{
    #define BUFFER_SIZE 256
    char buffer[BUFFER_SIZE] = "";
    int ttl = 0;

    HTTP_Context *httpContext = (HTTP_Context*)ctx;

    if (req == NULL) {
        int errcode = EVUTIL_SOCKET_ERROR();
#ifdef WITH_HTTPS
        //an error occurred, ssl error or socket error.
        struct bufferevent *bev = httpContext->bev;
        unsigned long oslerr;
        int openssl_err = 0;

        // ssl error?
        while ((oslerr = bufferevent_get_openssl_error(bev))) {
            ERR_error_string_n(oslerr, buffer, sizeof(buffer));
            fprintf(stderr, "ssl error: %s\n", buffer);
            openssl_err = 1;
        }
        // socket error?
        if (! openssl_err)
#endif
            fprintf(stderr, "socket error: %s (%d)\n",
                    evutil_socket_error_to_string(errcode),
                    errcode);
    }else {
        int response_code = evhttp_request_get_response_code(req);
        struct evbuffer* response_evbuffer = evhttp_request_get_input_buffer(req);
        size_t len = evbuffer_get_length(response_evbuffer);
        if(response_code == HTTP_OK && len > 0)
        {
                len = len > BUFFER_SIZE ? BUFFER_SIZE : len;
                int record_count = 0; //valid record count

                //split and response
                char *response_data = (char *) evbuffer_pullup(response_evbuffer, len);
                char formart[32];
                snprintf(formart,sizeof(formart)-1, "%%%d[^,],%%d",BUFFER_SIZE-1);
                sscanf(response_data,formart, buffer, &ttl);
                ttl = ttl==0?300:ttl;
                for (char *ip = strtok(buffer,";"); ip != NULL; ip = strtok(NULL, ";"))
                {
                  struct in_addr ans;
                  evutil_inet_pton(AF_INET, ip, &ans);
                  evdns_server_request_add_a_reply(httpContext->httpdns_req, httpContext->dns_name,
                                                       1, &ans, ttl);
                  record_count ++;
                }
                if(record_count)
                {
                    //insert to lru_cache
                    char *record_value = malloc(len+1);
                    evbuffer_copyout(response_evbuffer,record_value,len);
                    record_value[len] = '\0';
                    struct dns_record *dns_record = calloc(1,sizeof(struct  dns_record));
                    dns_record->key = strdup(httpContext->dns_name);
                    dns_record->value = record_value;
                    dns_record->expire_time = time(NULL) + ttl;
                    record_cache_insert(record_cache, dns_record->key, dns_record);
                }




        }

    }


    evdns_server_request_respond(httpContext->httpdns_req, 0);




    if (httpContext->http_uri)
        evhttp_uri_free(httpContext->http_uri);


#ifdef WITH_HTTPS
    if (httpContext->ssl_ctx)
        SSL_CTX_free(httpContext->ssl_ctx);
    if (httpContext->ssl)
        SSL_free(httpContext->ssl);
#endif
    if (httpContext)
        free(httpContext);
}



#ifdef WITH_HTTPS
static void
err_openssl(const char *func)
{
    fprintf (stderr, "%s failed:\n", func);

    /* This is the OpenSSL function that prints the contents of the
     * error stack to the specified file handle. */
    ERR_print_errors_fp (stderr);


}

/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
    char cert_str[256];
    const char *host = (const char *) arg;
    const char *res_str = "X509_verify_cert failed";
    HostnameValidationResult res = Error;

    /* This is the function that OpenSSL would call if we hadn't called
     * SSL_CTX_set_cert_verify_callback().  Therefore, we are "wrapping"
     * the default functionality, rather than replacing it. */
    int ok_so_far = 0;

    X509 *server_cert = NULL;



    ok_so_far = X509_verify_cert(x509_ctx);

    server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

    if (ok_so_far) {
        res = validate_hostname(host, server_cert);

        switch (res) {
        case MatchFound:
            res_str = "MatchFound";
            break;
        case MatchNotFound:
            res_str = "MatchNotFound";
            break;
        case NoSANPresent:
            res_str = "NoSANPresent";
            break;
        case MalformedCertificate:
            res_str = "MalformedCertificate";
            break;
        case Error:
            res_str = "Error";
            break;
        default:
            res_str = "WTF!";
            break;
        }
    }

    X509_NAME_oneline(X509_get_subject_name (server_cert),
                      cert_str, sizeof (cert_str));

    if (res == MatchFound) {
        //printf("https server '%s' has this certificate, which looks good to me:\n%s\n",host, cert_str);
        return 1;
    } else {
        //printf("Got '%s' for hostname '%s' and certificate:\n%s\n",res_str, host, cert_str);
        return 0;
    }
}
#endif


void
http_dns_resolve(struct event_base *base, const char *name, struct evdns_server_request *httpdns_req, char *cert_path)
{
    int r;

#ifdef WITH_HTTPS
//    const char *crt = "/etc/ssl/certs/ca-certificates.crt";
    char *crt;
    if(NULL == cert_path||strlen(cert_path)==0){
        crt = "/etc/ssl/certs/ca-certificates.crt";
    }else{
        crt = cert_path;
    }
#endif
    const char *scheme, *host, *path, *query;
    char url[256];
    char uri[256];
    int port;
    int retries = 2;
    int timeout = 8;

    struct evhttp_request *req;
    struct evkeyvalq *output_headers;




    HTTP_Context *httpContext;
    httpContext = calloc(1,sizeof(HTTP_Context));
    httpContext->dns_name = name;
    httpContext->httpdns_req = httpdns_req;
#if 0
    snprintf(url,sizeof(url)-1,"%s%s","http://119.29.29.29/d?ttl=1&dn=",name);
#else
    snprintf(url,sizeof(url)-1,"%s%s","https://dns.wuqiong.info/resolve.php?dn=",name);
#endif




#ifdef _WIN32
    {
        WORD wVersionRequested;
        WSADATA wsaData;
        int err;

        wVersionRequested = MAKEWORD(2, 2);

        err = WSAStartup(wVersionRequested, &wsaData);
        if (err != 0) {
            printf("WSAStartup failed with error: %d\n", err);
            goto error;
        }
    }
#endif // _WIN32

    httpContext->http_uri = evhttp_uri_parse(url);
    if (httpContext->http_uri == NULL) {
        goto error;
    }

    scheme = evhttp_uri_get_scheme(httpContext->http_uri);
    if (scheme == NULL || (
#ifdef WITH_HTTPS
                strcasecmp(scheme, "https") != 0 &&
#endif
                strcasecmp(scheme, "http") != 0
                )) {
        goto error;
    }

    host = evhttp_uri_get_host(httpContext->http_uri);
    if (host == NULL) {
        goto error;
    }

    port = evhttp_uri_get_port(httpContext->http_uri);
    if (port == -1) {
        port = (strcasecmp(scheme, "http") == 0) ? 80 : 443;
    }

    path = evhttp_uri_get_path(httpContext->http_uri);
    if (strlen(path) == 0) {
        path = "/";
    }

    query = evhttp_uri_get_query(httpContext->http_uri);
    if (query == NULL) {
        snprintf(uri, sizeof(uri) - 1, "%s", path);
    } else {
        snprintf(uri, sizeof(uri) - 1, "%s?%s", path, query);
    }
    uri[sizeof(uri) - 1] = '\0';

#ifdef WITH_HTTPS
    // Initialize OpenSSL
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();


    /* Create a new OpenSSL context */
    httpContext->ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!httpContext->ssl_ctx) {
        err_openssl("SSL_CTX_new");
        goto error;
    }

#ifndef _WIN32
    /* TODO: Add certificate loading on Windows as well */

    /* Attempt to use the system's trusted root certificates.
     * (This path is only valid for Debian-based systems.) */
    if (1 != SSL_CTX_load_verify_locations(httpContext->ssl_ctx, crt, NULL)) {
        err_openssl("SSL_CTX_load_verify_locations");
        goto error;
    }
    /* Ask OpenSSL to verify the server certificate.  Note that this
     * does NOT include verifying that the hostname is correct.
     * So, by itself, this means anyone with any legitimate
     * CA-issued certificate for any website, can impersonate any
     * other website in the world.  This is not good.  See "The
     * Most Dangerous Code in the World" article at
     * https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html
     */
    SSL_CTX_set_verify(httpContext->ssl_ctx, SSL_VERIFY_PEER, NULL);
    /* This is how we solve the problem mentioned in the previous
     * comment.  We "wrap" OpenSSL's validation routine in our
     * own routine, which also validates the hostname by calling
     * the code provided by iSECPartners.  Note that even though
     * the "Everything You've Always Wanted to Know About
     * Certificate Validation With OpenSSL (But Were Afraid to
     * Ask)" paper from iSECPartners says very explicitly not to
     * call SSL_CTX_set_cert_verify_callback (at the bottom of
     * page 2), what we're doing here is safe because our
     * cert_verify_callback() calls X509_verify_cert(), which is
     * OpenSSL's built-in routine which would have been called if
     * we hadn't set the callback.  Therefore, we're just
     * "wrapping" OpenSSL's routine, not replacing it. */
    SSL_CTX_set_cert_verify_callback(httpContext->ssl_ctx, cert_verify_callback,
                                     (void *) host);
#endif // not _WIN32



    // Create OpenSSL bufferevent and stack evhttp on top of it
    httpContext->ssl = SSL_new(httpContext->ssl_ctx);
    if (httpContext->ssl == NULL) {
        err_openssl("SSL_new()");
        goto error;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    // Set hostname for SNI extension
    SSL_set_tlsext_host_name(httpContext->ssl, host);
#endif

    if (strcasecmp(scheme, "https") == 0) {
        httpContext->bev = bufferevent_openssl_socket_new(base, -1, httpContext->ssl,
                                                          BUFFEREVENT_SSL_CONNECTING,
                                                          BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    } else
#endif
    {

        httpContext->bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    }

    if (httpContext->bev == NULL) {
        fprintf(stderr, "bufferevent_[openssl_]socket_new() failed\n");
        goto error;
    }
#ifdef WITH_HTTPS
    bufferevent_openssl_set_allow_dirty_shutdown(httpContext->bev, 1);
#endif

    // For simplicity, we let DNS resolution block. Everything else should be
    // asynchronous though.
    httpContext->evcon = evhttp_connection_base_bufferevent_new(base, NULL, httpContext->bev,
                                                                host, port);
    if (httpContext->evcon == NULL) {
        fprintf(stderr, "evhttp_connection_base_bufferevent_new() failed\n");
        goto error;
    }

    if (retries > 0) {
        evhttp_connection_set_retries(httpContext->evcon, retries);
    }
    if (timeout >= 0) {
        evhttp_connection_set_timeout(httpContext->evcon, timeout);
    }

    // Fire off the request
    req = evhttp_request_new(http_request_done, httpContext);
    if (req == NULL) {
        fprintf(stderr, "evhttp_request_new() failed\n");
        goto error;
    }

    output_headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(output_headers, "Host", host);
    evhttp_add_header(output_headers, "Connection", "close");



    r = evhttp_make_request(httpContext->evcon, req, EVHTTP_REQ_GET, uri);
    if (r != 0) {
        fprintf(stderr, "evhttp_make_request() failed\n");
        goto error;
    }

    return;

error:

    if (httpContext->evcon)
        evhttp_connection_free(httpContext->evcon);
    if (httpContext->http_uri)
        evhttp_uri_free(httpContext->http_uri);

#ifdef WITH_HTTPS
    if (httpContext->ssl_ctx)
        SSL_CTX_free(httpContext->ssl_ctx);
    if (httpContext->ssl)
        SSL_free(httpContext->ssl);
#endif
    if (httpContext)
        free(httpContext);


}
