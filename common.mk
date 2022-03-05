SHELL = /bin/sh

prefix = /usr
bindir = $(prefix)/bin
sbindir = $(prefix)/sbin
libdir = $(prefix)/lib

INSTALL = /usr/bin/install
INSTALLDATA = /usr/bin/install -m 644
CC = gcc
LD = ld
RM = rm -f
RMDIR = rmdir -p --ignore-fail-on-non-empty

CFLAGS = -DDEBUG -g -Wall

PLATFORM := $(shell uname)
ifeq "$(PLATFORM)" "Linux"
CFLAGS_MAIN		= $(CFLAGS) -rdynamic \
		-DMASTERSERVER_LIB_DIR=\"/usr/lib/lasange/masterserver\"
CFLAGS_PLUGIN	= $(CFLAGS) -fPIC
CFLAGS_TESTS	= $(CFLAGS) -lm
LDFLAGS			= -lpthread -ldl
LDFLAGS_PLUGIN	= -shared -lm
endif

ifeq "$(PLATFORM)" "FreeBSD"
CFLAGS_MAIN		= $(CFLAGS) -rdynamic \
		-DMASTERSERVER_LIB_DIR=\"/usr/lib/lasange/masterserver\"
CFLAGS_PLUGIN	= $(CFLAGS) -fPIC
CFLAGS_TESTS	= $(CFLAGS) -lm
LDFLAGS			= -pthread
LDFLAGS_PLUGIN	= -shared -lm
endif

ifeq "$(PLATFORM)" "SunOS"
CFLAGS_MAIN		= $(CFLAGS) \
		-DMASTERSERVER_LIB_DIR=\"/usr/lib/lasange/masterserver\" \
		-DSOLARIS -D__EXTENSIONS__
CFLAGS_PLUGIN	= $(CFLAGS) -fPIC
CFLAGS_TESTS	= $(CFLAGS) -lm -lnsl -lsocket
LDFLAGS			= -lpthread -ldl -lsocket -lnsl
LDFLAGS_PLUGIN	= -shared -lm
endif

