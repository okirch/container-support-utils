BINDIR		= /usr/bin
SBINDIR		= /usr/sbin
MANDIR		= /usr/share/man/man1

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE -I../console $(COPT)
WORMHOLE	= wormhole
WORMHOLE_SRCS	= wormhole.c \
		  profiles.c \
		  util.o
WORMHOLE_OBJS	= $(WORMHOLE_SRCS:.c=.o)
WORMHOLED	= wormholed
WORMHOLED_SRCS	= wormholed.c \
		  profiles.c \
		  util.o
WORMHOLED_OBJS	= $(WORMHOLED_SRCS:.c=.o)
LINK		= -L../console -lconsole -lutil
LIB		= ../console/libconsole.a

#MAN1PAGES	= wormhole.1
#MAN8PAGES	= wormholed.8

all: $(WORMHOLE) $(WORMHOLED)

clean:
	rm -f $(WORMHOLE)
	rm -f *.o *.a

install: $(WORMHOLE) $(WORMHOLED)
	@case "$(DESTDIR)" in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 4555 $(WORMHOLE) $(DESTDIR)$(BINDIR)
	install -m 555 $(WORMHOLED) $(DESTDIR)$(SBINDIR)
ifneq ($(MAN1PAGES),)
	install -m 755 -d $(DESTDIR)$(MANDIR)
	install -m 444 $(MAN1PAGES) $(DESTDIR)$(MANDIR)
endif

$(WORMHOLE): $(WORMHOLE_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(WORMHOLE_OBJS) $(LINK)

$(WORMHOLED): $(WORMHOLED_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(WORMHOLED_OBJS) $(LINK)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc $(CFLAGS) -MM *.c >.depend
