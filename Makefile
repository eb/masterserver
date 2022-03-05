include common.mk

OBJ_FILES = masterserver.o logging.o
PROGRAM = masterserver

.PHONY: all clean install masterserver plugins uninstall

all: masterserver plugins
.SUFFIXES = .c .o

.c.o:
	$(CC) $(CFLAGS_MAIN) -c $< -o $@ 

masterserver.o: masterserver.c masterserver.h

logging.o: logging.c logging.h

masterserver: $(OBJ_FILES)
	$(CC) $(LDFLAGS) $(CFLAGS_MAIN) -o $@ $(OBJ_FILES)

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
	$(RMDIR) $(libdir)/lasange/masterserver

check:
	$(MAKE) -C tests all

