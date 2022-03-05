include ../common.mk

PLUGINS = libq3.c libq2.c libh2.c libqw.c libd3.c libef.c
OBJS = libq3.o libq2.o libh2.o libqw.o libd3.o libef.o
LIBS = libq3.so libq2.so libh2.so libqw.so libd3.so libef.so

.PHONY: all clean install

all:	$(LIBS)

%.o:	%.c
	$(CC) $(CFLAGS_PLUGIN) -o $@ -c $<

%.so:	%.o
	$(CC) $(LDFLAGS_PLUGIN) -o $@ $<

clean:
	$(RM) $(OBJS) $(LIBS)

install:
	$(INSTALL) -m 755 -d $(libdir)/lasange/masterserver
	$(INSTALLDATA) $(LIBS) $(libdir)/lasange/masterserver

uninstall:
	$(RM) $(libdir)/lasange/masterserver/libq3.so
	$(RM) $(libdir)/lasange/masterserver/libh2.so
	$(RM) $(libdir)/lasange/masterserver/libq2.so
	$(RM) $(libdir)/lasange/masterserver/libqw.so
	$(RM) $(libdir)/lasange/masterserver/libd3.so
	$(RM) $(libdir)/lasange/masterserver/libef.so

