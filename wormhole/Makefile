BINDIR		= /usr/bin
MANDIR		= /usr/share/man/man1

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE -I../console $(COPT)
WORMHOLE	= wormhole
WORMHOLE_SRCS	= wormhole.c profiles.c
WORMHOLE_OBJS	= $(WORMHOLE_SRCS:.c=.o)
LINK		= -L../console -lconsole -lutil
LIB		= ../console/libconsole.a

#MANPAGES	= wormhole.1

all: $(WORMHOLE)

clean:
	rm -f $(WORMHOLE)
	rm -f *.o *.a

install: $(WORMHOLE)
	@case "$(DESTDIR)" in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 4555 $(WORMHOLE) $(DESTDIR)$(BINDIR)
ifneq ($(MANPAGES),)
	install -m 755 -d $(DESTDIR)$(MANDIR)
	install -m 444 $(MANPAGES) $(DESTDIR)$(MANDIR)
endif

wormhole: $(WORMHOLE_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(WORMHOLE_OBJS) $(LINK)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc $(CFLAGS) -MM *.c >.depend
