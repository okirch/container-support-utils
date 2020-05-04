/*
 * savelog-svc.c
 *
 * Service side of the savelog facility.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include <libtar.h>

#include "tracing.h"


static TAR *		tar_f;

extern int		(*savelog_store_fn)(const char *pathname);
extern void		(*savelog_close_fn)(void);

extern int		savelog_export_sockname(int fd);
extern int		savelog_connect_sockname(int fd);
extern void		savelog_close_fds(int except_fd);

extern int		unix_sender_uid(struct msghdr *msg);
extern const char *	unix_path_print(struct sockaddr_un *sun, socklen_t len);

/*
 * Savelog tar facility.
 *
 * In the master, we open a tar archive for writing.
 * This object is passed to the child process, which creates
 * a proxy process that listens on a UNIX domain socket.
 * The savelog utility, when invoked from the shell inside the
 * container environment, will contact that proxy service to
 * have the indicated file(s) saved to the tar archive.
 */
static int
savelog_tar_store(const char *pathname)
{
	const char *savename;
	struct stat stb;
	int fd;
	int rv = -1;

	if ((fd = open(pathname, O_RDONLY)) < 0) {
		log_error("savelog: unable to open \"%s\": %m\n", pathname);
		return -1;
	}

	if (fstat(fd, &stb) < 0) {
		log_error("savelog: unable to stat \"%s\": %m\n", pathname);
		goto out;
	}

	if (!S_ISREG(stb.st_mode)) {
		log_error("savelog: refusing to save \"%s\": not a regular file\n", pathname);
		goto out;
	}

	savename = pathname;
	while (*savename == '/')
		++savename;

	if (tar_append_file(tar_f, pathname, savename) < 0) {
		log_error("savelog: unable to save \"%s\" to tar file: %m\n", pathname);
		goto out;
	}

	trace("Successfully appended %s to tarfile.\n", pathname);
	rv = 0;

out:
	close(fd);
	return rv;
}

int
savelog_tar_init(const char *pathname)
{
	if (tar_open(&tar_f, pathname, NULL, O_WRONLY | O_CREAT | O_TRUNC, 0644, TAR_GNU) < 0) {
		log_error("Unable to open tar file \"%s\": %m\n", pathname);
		return -1;
	}

	/* Mark it as close-on-exec. */
	fcntl(tar_fd(tar_f), F_SETFD, FD_CLOEXEC);

	savelog_store_fn = savelog_tar_store;
	return 0;
}

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
