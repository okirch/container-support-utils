PYMODULES	= rpms.py \
		  process.py
PYAPP		= sidecar.py
BINDIR		= /usr/bin

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE -I. $(COPT)
CONSOLE		= sidecar-console
TESTAPPS	= test-queue \
		  test-socket \
		  test-shell
TESTSRCS	= test-common.c \
		  test-client.c
TESTOBJS	= $(TESTSRCS:.c=.o)
LIB		= libconsole.a
LIBSRCS		= shellproto.c \
		  forwarder.c \
		  shell.c \
		  mainloop.c \
		  endpoint.c \
		  queue.c \
		  buffer.c
LIBOBJS		= $(LIBSRCS:.c=.o)
LINK		= -L. -lconsole -lutil

PYVERS		= python2.7
PYLIBDIR	= /usr/lib/$(PYVERS)/site-packages/suse_sidecar

all: $(PYAPP) $(PYMODULES) $(TESTAPPS) $(CONSOLE)

tests:	$(TESTAPPS)
	@set -e; for t in $(TESTAPPS); do \
		echo "== $$t =="; \
		./$$t -s $$RANDOM; \
	done

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

test-queue: test-queue.o $(TESTOBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ test-queue.o $(TESTOBJS) $(LINK)

test-socket: test-socket.o $(TESTOBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ test-socket.o $(TESTOBJS) $(LINK)

test-shell: test-shell.o $(TESTOBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ test-shell.o $(TESTOBJS) $(LINK)

sidecar-console: sidecar-console.o $(LIB)
	$(CC) $(CFLAGS) -o $@ sidecar-console.o $(LINK)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc -I. -MM *.c >.depend
