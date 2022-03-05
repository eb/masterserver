SHELL = /bin/sh

prefix = /usr
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
sbindir = $(exec_prefix)/sbin

INSTALL = /usr/bin/install
INSTALLDATA = /usr/bin/install -m 644
CC = /usr/bin/gcc
LD = /usr/bin/ld
RM = /bin/rm -f
CFLAGS = -g -Wall -rdynamic
ALL_CFLAGS = -lpthread -ldl $(CFLAGS)

.PHONY: all clean install masterserver plugins uninstall

all: masterserver plugins

masterserver:
	$(CC) masterserver.c $(ALL_CFLAGS) -o masterserver

plugins:
	$(MAKE) -C plugins

clean:
	$(RM) masterserver
	$(MAKE) -C plugins clean

install: all
	$(INSTALL) masterserver $(bindir)/masterserver
	$(MAKE) -C plugins install

uninstall:
	$(RM) $(bindir)/masterserver
	$(MAKE) -C plugins uninstall

