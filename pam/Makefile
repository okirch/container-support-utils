PAMLIBDIR	= /lib64/security
MANDIR		= /usr/share/man/man8

COPT		= -g
CFLAGS		= -Wall -fPIC -D_GNU_SOURCE -I../console $(COPT)

PAM_CONTAINER	= pam_container.so
PAM_SRCS	= pam_container.c
PAM_OBJS	= $(PAM_SRCS:.c=.o)
LINK		= -L../console -lconsole-pic \
		  -lpam_misc -lpam -lutil
LIB		= ../console/libconsole.a

# MANPAGES	= pam_container.8

all: $(PAM_CONTAINER)

clean:
	rm -f $(PAM_CONTAINER)
	rm -f *.o

install: $(PAM_CONTAINER)
	@case "$(DESTDIR)" in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(PAMLIBDIR)
	install -m 555 $(PAM_CONTAINER) $(DESTDIR)$(PAMLIBDIR)
ifneq ($(MANPAGES),)
	install -m 755 -d $(DESTDIR)$(MANDIR)
	install -m 444 $(MANPAGES) $(DESTDIR)$(MANDIR)
endif

$(PAM_CONTAINER): $(PAM_OBJS)
	$(CC) -shared -o $@ $(CFLAGS) $(PAM_OBJS) $(LINK)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc $(CFLAGS) -MM *.c >.depend
