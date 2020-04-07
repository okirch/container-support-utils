PYMODULES	= rpms.py \
		  process.py
PYAPP		= sidecar.py
BINDIR		= /usr/bin

PYVERS		= python2.7
PYLIBDIR	= /usr/lib/$(PYVERS)/site-packages/suse_sidecar

install:
	install -m 755 -d $(DESTDIR)$(PYLIBDIR)
	touch $(DESTDIR)$(PYLIBDIR)/__init__.py
	install -m 444 $(PYMODULES) $(DESTDIR)$(PYLIBDIR)
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 $(PYAPP) $(DESTDIR)$(BINDIR)/suse-sidecar
