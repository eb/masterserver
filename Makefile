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
RMDIR = /bin/rmdir -p --ignore-fail-on-non-empty
LDFLAGS = -lpthread -ldl
STD_CFLAGS = -rdynamic -DNDEBUG
DEBUG_CFLAGS = -g -Wall -rdynamic -DDEBUG # \
	-DMASTERSERVER_LIB_DIR=\"/usr/lib/lasange/masterserver\"
CFLAGS = $(DEBUG_CFLAGS)
OBJ_FILES = masterserver.o logging.o
PROGRAM = masterserver

.PHONY: all clean install masterserver plugins uninstall

all: masterserver plugins
.SUFFIXES = .c .o

.c.o:
	$(CC) $(CFLAGS) -c $<

masterserver.o: masterserver.c masterserver.h

logging.o: logging.c logging.h

masterserver: $(OBJ_FILES)
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJ_FILES)

plugins:
	$(MAKE) -C plugins

clean:
	$(RM) $(OBJ_FILES) $(PROGRAM)
	$(MAKE) -C plugins clean

install: all
	$(INSTALL) $(PROGRAM) $(bindir)/$(PROGRAM)
	$(MAKE) -C plugins install

uninstall:
	$(RM) $(bindir)/$(PROGRAM)
	$(MAKE) -C plugins uninstall
	$(RMDIR) /usr/lib/lasange/masterserver

