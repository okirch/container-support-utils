SUBDIRS		= console ns-exec pam sidecar

all clean install::
	@for d in $(SUBDIRS); do make -C $$d $@; done

archive:
	@tag=$$(git tag --sort=-taggerdate | head -1); \
	version=$$(echo $$tag | sed 's/^v//'); \
	name="container-support-utils-$$version"; \
	echo "Creating $$name.tar.bz2"; \
	git archive --format=tar --prefix=$$name/ -o $$name.tar $$tag; \
	bzip2 -f $$name.tar
