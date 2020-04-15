PYMODULES	= rpms.py \
		  process.py
PYAPP		= sidecar.py
BINDIR		= /usr/bin

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE -I. $(COPT)
CONSOLE		= sidecar-console
TESTAPPS	= test-queue \
		  test-socket
LIB		= libconsole.a
LIBSRCS		= mainloop.c \
		  endpoint.c \
		  queue.c \
		  buffer.c
LIBOBJS		= $(LIBSRCS:.c=.o)

PYVERS		= python2.7
PYLIBDIR	= /usr/lib/$(PYVERS)/site-packages/suse_sidecar

all: $(PYAPP) $(PYMODULES) $(CONSOLE)

tests:	$(TESTAPPS)

clean:
	rm -f $(CONSOLE) $(TESTAPPS)
	rm -f *.o *.a

install: $(PYAPP) $(PYMODULES) $(CONSOLE)
	install -m 755 -d $(DESTDIR)$(PYLIBDIR)
	touch $(DESTDIR)$(PYLIBDIR)/__init__.py
	install -m 444 $(PYMODULES) $(DESTDIR)$(PYLIBDIR)
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 $(PYAPP) $(DESTDIR)$(BINDIR)/suse-sidecar

$(LIB): $(LIBOBJS)
	$(AR) crv $@ $(LIBOBJS)

test-queue: test-queue.o test-common.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test-queue.o test-common.o -L. -lconsole

test-socket: test-socket.o test-common.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test-socket.o test-common.o -L. -lconsole

sidecar-console: $(LIBOBJS)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc -I. -MM *.c >.depend
