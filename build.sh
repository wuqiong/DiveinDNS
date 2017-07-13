export STAGING_DIR=$HOME/opensource/openwrt-cc/staging_dir
export PATH=$PATH:$STAGING_DIR/toolchain-mipsel_24kec+dsp_gcc-4.8-linaro_uClibc-0.9.33.2/bin/

LIBEVENT_INCLUDE="-I $HOME/libevent/include/"
LIBEVENT_LIB="-L $HOME/libevent/lib/"
LIBEVENT_LD="-levent -levent_openssl"

OPENSSL_INCLUDE="-I $HOME/opensource/openwrt-cc/build_dir/target-mipsel_24kec+dsp_uClibc-0.9.33.2/openssl-1.0.2h/include/"
OPENSSL_LIB="-L $HOME/opensource/openwrt-cc/build_dir/target-mipsel_24kec+dsp_uClibc-0.9.33.2/openssl-1.0.2h/"
OPENSSL_LD="-lssl -lcrypto"

CFLAGS="-DWITH_DAEMON -DWITH_HTTPS"


#-Wl,-Bstatic 
#-Wl,-Bdynamic

mipsel-openwrt-linux-gcc *.c  -std=c99 $CFLAGS  -D_XOPEN_SOURCE=600 \
   	$LIBEVENT_INCLUDE $OPENSSL_INCLUDE	\
   	$LIBEVENT_LIB $OPENSSL_LIB	\
	-Wl,-Bstatic \
	$LIBEVENT_LD \
	-ldl \
	-Wl,-Bdynamic \
	$OPENSSL_LD \
	-lpthread \
	 -o diveinDNS



mipsel-openwrt-linux-strip diveinDNS
