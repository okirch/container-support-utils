/*
 * savelog-svc.c
 *
 * Server side of the savelog facility.
 */

#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include "tracing.h"


int
savelog_dir_init(const char *pathname)
{
	struct stat stb;
	char description[128];
	int fd;

	fd = open(pathname, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		log_error("Unable to open directory \"%s\": %m\n", pathname);
		return -1;
	}

	if (fstat(fd, &stb) < 0) {
		close(fd);
		return -1;
	}

	if (fd < 128) {
		dup2(fd, 128);
		close(fd);
		fd = 128;
	}

	snprintf(description, sizeof(description), "%d,%lu/%lu", fd, stb.st_dev, stb.st_ino);
	setenv("SAVELOG_DIRFD", description, 1);
	trace("Exporting SAVELOG_DIRFD=\"%s\"\n", description);

	return 0;
}

int
savelog_init(const char *destination)
{
	return savelog_dir_init(destination);
}
