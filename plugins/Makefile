CC = /usr/bin/gcc
LD = /usr/bin/ld
INSTALL = /usr/bin/install
INSTALLDATA = /usr/bin/install -m 644
PLUGINS = libq3.c libq2.c libh2.c libqw.c
OBJS = libq3.o libq2.o libh2.o libqw.o
LIBS = libq3.so libq2.so libh2.so libqw.so
CFLAGS = -g -Wall -fPIC -DDEBUG
LDFLAGS = -shared -lm
RM = /bin/rm -f
RMDIR = /bin/rmdir

.PHONY: all clean install

all:	$(LIBS)

%.o:	%.c
	$(CC) $(CFLAGS) -o $@ -c $<

%.so:	%.o
	$(CC) $(LDFLAGS) -o $@ $<

clean:
	$(RM) $(OBJS) $(LIBS)

install:
	$(INSTALL) -m 755 -d /usr/lib/lasange/masterserver
	$(INSTALLDATA) $(LIBS) /usr/lib/lasange/masterserver

uninstall:
	$(RM) /usr/lib/lasange/masterserver/libq3.so
	$(RM) /usr/lib/lasange/masterserver/libh2.so
	$(RM) /usr/lib/lasange/masterserver/libq2.so
	$(RM) /usr/lib/lasange/masterserver/libqw.so

