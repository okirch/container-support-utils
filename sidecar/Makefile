PYMODULES	= rpms.py \
		  process.py
PYAPP		= sidecar.py
BINDIR		= /usr/bin

PYVERS		= python2.7
PYLIBDIR	= /usr/lib/$(PYVERS)/site-packages/suse_sidecar

all:: $(PYAPP) $(PYMODULES)

clean:: ;

install:: $(PYAPP) $(PYMODULES)
	@case $(DESTDIR) in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(PYLIBDIR)
	touch $(DESTDIR)$(PYLIBDIR)/__init__.py
	install -m 444 $(PYMODULES) $(DESTDIR)$(PYLIBDIR)
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 $(PYAPP) $(DESTDIR)$(BINDIR)/suse-sidecar

