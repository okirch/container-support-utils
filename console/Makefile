BINDIR		= /usr/bin

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE -I. $(COPT)
CONSOLE		= sidecar-console
CLIENT		= sidecar-shell
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
		  container.c \
		  filesystem.c \
		  mainloop.c \
		  endpoint.c \
		  queue.c \
		  buffer.c \
		  tracing.c
LIBOBJS		= $(LIBSRCS:.c=.o)
PIC_LIB		= libconsole-pic.a
PIC_LIBOBJS	= $(addprefix pic/,$(LIBOBJS))
LINK		= -L. -lconsole -lutil


all: $(TESTAPPS) $(CONSOLE) $(CLIENT) $(PIC_LIB)

tests:	$(TESTAPPS)
	@set -e; for t in $(TESTAPPS); do \
		echo "== $$t =="; \
		./$$t -s $$RANDOM; \
	done

clean:
	rm -f $(CONSOLE) $(CLIENT) $(TESTAPPS)
	rm -f *.o *.a
	rm -rf pic/

install: $(CONSOLE) $(CLIENT)
	@case "$(DESTDIR)" in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 $(CONSOLE) $(DESTDIR)$(BINDIR)
	install -m 555 $(CLIENT) $(DESTDIR)$(BINDIR)

$(LIB): $(LIBOBJS)
	$(AR) crv $@ $(LIBOBJS)

$(PIC_LIB): $(PIC_LIBOBJS)
	$(AR) crv $@ $(PIC_LIBOBJS)

test-queue: test-queue.o $(TESTOBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ test-queue.o $(TESTOBJS) $(LINK)

test-socket: test-socket.o $(TESTOBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ test-socket.o $(TESTOBJS) $(LINK)

test-shell: test-shell.o $(TESTOBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ test-shell.o $(TESTOBJS) $(LINK)

sidecar-console: sidecar-console.o $(LIB)
	$(CC) $(CFLAGS) -o $@ sidecar-console.o $(LINK)

sidecar-shell: sidecar-shell.o $(LIB)
	$(CC) $(CFLAGS) -o $@ sidecar-shell.o $(LINK)

pic/%.o: %.c
	@mkdir -p pic
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc -I. -MM *.c >.depend
	gcc -I. -MM *.c | sed 's:^[^ ]:pic/&:' >>.depend
