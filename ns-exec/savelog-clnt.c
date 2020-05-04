/*
 * savelog-clnt.c
 *
 * Client side of the savelog facility.
 */

#include <sys/stat.h>
#include <sys/sendfile.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "savelog.h"

#include "tracing.h"


static int
savelog_dirfd_get(void)
{
	const char *description;
	unsigned long dev, ino;
	int fd;
	struct stat stb;

	if ((description = getenv("SAVELOG_DIRFD")) == NULL)
		return -1;

	trace("Trying to parse SAVELOG_DIRFD=%s\n", description);
	if (sscanf(description, "%d,%lu/%lu", &fd, &dev, &ino) != 3)
		return -1;

	if (fstat(fd, &stb) < 0)
		return -1;

	if (stb.st_dev != dev || stb.st_ino != ino)
		return -1;

	return fd;
}

static char *
savelog_dirfd_make_name(const char *pathname)
{
	char *rv, *s;

	while (pathname[0] == '/')
		++pathname;

	rv = strdup(pathname);

	for (s = rv; *s; ++s)
		if (*s == '/')
			*s = '-';

	return rv;
}

static int
savelog_dirfd_open(int dirfd, const char *pathname)
{
	char *outname, *realname, *s;
	int outfd = -1;

	realname = realpath(pathname, NULL);

	for (outname = realname; *outname == '/'; ++outname)
		;

	if (*outname == '\0') {
		log_error("Invalid output filename \"%s\"\n", realname);
		goto failed;
	}

	for (s = outname; *s; ) {
		char *begin;

		while (*s == '/')
			++s;

		begin = s;
		s = begin + strcspn(begin, "/");
		if (*s == '\0')
			break;

		*s = '\0';
		if (mkdirat(dirfd, outname, 0755) < 0) {
			if (errno != EEXIST) {
				log_error("Unable to create %s in savelog directory: %s\n", outname);
				goto failed;
			}
		}

		*s = '/';
	}

	if ((outfd = openat(dirfd, outname, O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0) {
		log_error("savelog: unable to open \"%s\": %m\n", outname);
		goto failed;
	}

failed:
	free(realname);
	return outfd;
}

static int
savelog_dirfd_send(struct savelog *savelog, const char *pathname)
{
	char *outname;
	int infd = -1, outfd = -1;
	unsigned long total = 0, size;
	struct stat stb;
	off_t offset = 0;
	int n, rv = -1;

	outname = savelog_dirfd_make_name(pathname);

	trace("Trying to save %s to dir @fd=%d\n", pathname, savelog->fd);
	if ((infd = open(pathname, O_RDONLY)) < 0) {
		log_error("savelog: unable to open \"%s\": %m\n", pathname);
		goto failed;
	}

	if (fstat(infd, &stb) < 0) {
		log_error("savelog: unable to stat \"%s\": %m\n", pathname);
		goto failed;
	}
	size = stb.st_size;

	if ((outfd = savelog_dirfd_open(savelog->fd, pathname)) < 0)
		goto failed;

	while (total < size) {
		n = sendfile(outfd, infd, &offset, size - total);
		if (n < 0) {
			log_error("sendfile: %m\n");
			goto failed;
		}

		total += n;
	}

	rv = 0;

failed:
	if (infd >= 0)
		close(infd);
	if (outfd >= 0)
		close(outfd);
	if (outname)
		free(outname);
	return rv;
}

struct savelog *
savelog_connect(void)
{
	struct savelog *ret;

	ret = calloc(1, sizeof(*ret));
	if ((ret->fd = savelog_dirfd_get()) >= 0) {
		ret->send = savelog_dirfd_send;
		return ret;
	}

	free(ret);
	return NULL;
}
