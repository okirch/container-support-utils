BINDIR		= /usr/bin

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE -I../console $(COPT)
NSEXEC		= ns-exec
LINK		= -L../console -lconsole -lutil
LIB		= ../console/libconsole.a

all: $(NSEXEC)

clean:
	rm -f $(NSEXEC)
	rm -f *.o *.a

install: $(NSEXEC)
	@case $(DESTDIR) in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 $(NSEXEC) $(DESTDIR)$(BINDIR)

ns-exec: ns-exec.o $(LIB)
	$(CC) $(CFLAGS) -o $@ ns-exec.o $(LINK)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc -I. -MM *.c >.depend
