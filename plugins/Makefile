CC = /usr/bin/gcc
LD = /usr/bin/ld
INSTALL = /usr/bin/install
INSTALLDATA = /usr/bin/install -m 644
PLUGINS = libq3.c
OBJS = libq3.o
LIBS = libq3.so
CFLAGS = -g -Wall -fPIC
LDFLAGS = -shared
RM = /bin/rm -f
RMDIR = /bin/rmdir

.PHONY: all clean install

all:	$(LIBS)

%.o:	%.c
	$(CC) $(CFLAGS) -o $@ -c $<

%.so:	%.o
	$(LD) $(LDFLAGS) -o $@ $<

clean:
	$(RM) $(OBJS) $(LIBS)

install:
	$(INSTALL) -m 755 -d /usr/lib/lasange/masterserver
	$(INSTALLDATA) libq3.so /usr/lib/lasange/masterserver

uninstall:
	$(RM) /usr/lib/lasange/masterserver/libq3.so
	$(RMDIR) /usr/lib/lasange/masterserver
	$(RMDIR) /usr/lib/lasange

