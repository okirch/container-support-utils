PYMODULES	= rpms.py \
		  process.py
PYAPP		= sidecar.py
BINDIR		= /usr/bin

PYVERS		= python2.7
PYLIBDIR	= /usr/lib/$(PYVERS)/site-packages/suse_sidecar

SUBDIRS		= console ns-exec

all:: $(PYAPP) $(PYMODULES)

clean:: ;

install:: $(PYAPP) $(PYMODULES)
	install -m 755 -d $(DESTDIR)$(PYLIBDIR)
	touch $(DESTDIR)$(PYLIBDIR)/__init__.py
	install -m 444 $(PYMODULES) $(DESTDIR)$(PYLIBDIR)
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 $(PYAPP) $(DESTDIR)$(BINDIR)/suse-sidecar

all clean install::
	@for d in $(SUBDIRS); do make -C $$d $@; done

archive:
	@tag=$$(git tag --sort=-taggerdate | head -1); \
	version=$$(echo $$tag | sed 's/^v//'); \
	name="container-support-utils-$$version"; \
	echo "Creating $$name.tar.bz2"; \
	git archive --format=tar --prefix=$$name/ -o $$name.tar $$tag; \
	bzip2 -f $$name.tar
