BINDIR		= /usr/bin
MANDIR		= /usr/share/man/man1

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE -I../console $(COPT)
NSEXEC		= ns-exec
NSEXEC_SRCS	= ns-exec.c savelog-svc.c
NSEXEC_OBJS	= $(NSEXEC_SRCS:.c=.o)
SAVELOG		= savelog
SAVELOG_SRCS	= savelog.c savelog-clnt.c
SAVELOG_OBJS	= $(SAVELOG_SRCS:.c=.o)
LINK		= -L../console -lconsole -lutil
LIB		= ../console/libconsole.a

MANPAGES	= ns-exec.1

all: $(NSEXEC) $(SAVELOG)

clean:
	rm -f $(NSEXEC) $(SAVELOG)
	rm -f *.o *.a

install: $(NSEXEC)
	@case $(DESTDIR) in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 $(NSEXEC) $(DESTDIR)$(BINDIR)
	install -m 555 $(SAVELOG) $(DESTDIR)$(BINDIR)
	install -m 755 -d $(DESTDIR)$(MANDIR)
	install -m 444 $(MANPAGES) $(DESTDIR)$(MANDIR)

ns-exec: $(NSEXEC_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(NSEXEC_OBJS) $(LINK)

savelog: $(SAVELOG_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(SAVELOG_OBJS) $(LINK)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc $(CFLAGS) -MM *.c >.depend
