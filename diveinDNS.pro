TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

DEFINES+=WITH_DAEMON

INCLUDEPATH += /usr/local/libevent/include


SOURCES += main.c \
    https-client.c \
    openssl_hostname_validation.c \
    hostcheck.c \
    lru_cache.c

HEADERS += \
    openssl_hostname_validation.h \
    hostcheck.h \
    https-client.h \
    lru_cache.h \
    uthash.h

LIBS += -L/usr/local/libevent/lib -levent -levent_extra -levent_openssl  -lssl -lcrypto -lpthread
