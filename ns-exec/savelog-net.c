/*
 * savelog-net.c
 *
 * Network "protocol" for savelog
 */

#include <sys/socket.h>
#include <sys/un.h>
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

#include <libtar.h>

#include "tracing.h"


extern int		(*savelog_store_fn)(const char *pathname);
extern void		(*savelog_close_fn)(void);

extern int		savelog_export_sockname(int fd);
extern int		savelog_connect_sockname(int fd);
extern void		savelog_close_fds(int except_fd);

static int		unix_sender_uid(struct msghdr *msg);
static const char *	unix_path_print(struct sockaddr_un *sun, socklen_t len);

int			(*savelog_store_fn)(const char *pathname);
void			(*savelog_close_fn)(void);

static int		savelog_busy = 0;

static void
savelog_sighup_handler(int signo)
{
	trace("savelog proxy received SIGHUP, shutting down\n");
	if (!savelog_busy && savelog_close_fn)
		savelog_close_fn();

	exit(0);
}

void
savelog_proxy_mainloop(int fd)
{
	if (savelog_close_fn) {
		struct sigaction act;

		memset(&act, 0, sizeof(act));
		act.sa_handler = savelog_sighup_handler;
		sigaction(SIGHUP, &act, NULL);
	}

	while (1) {
		char pathbuf[PATH_MAX + 1];
		union {
			unsigned char _[1024];
			struct cmsghdr _align;
		} controlbuf;
		struct iovec iov = { .iov_base = pathbuf, .iov_len = sizeof(pathbuf) };
		struct msghdr msg;
		int uid;
		int n;

		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = &controlbuf;
		msg.msg_controllen = sizeof(controlbuf);

		n = recvmsg(fd, &msg, 0);
		if (n < 0)
			continue;
		if (iov.iov_len < n)
			continue; /* this would typically be an assert, but assert doesn't play nicely with a closed fd 2 */

		if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
			log_error("%s: ignoring truncated message\n", __func__);
			continue;
		}

		uid = unix_sender_uid(&msg);
		if (uid < 0) {
			log_error("%s: no or bad sender credentials\n", __func__);
			continue;
		}

		if (n == 0)
			continue;

		assert(n <= PATH_MAX);
		pathbuf[n] = '\0';

		if (uid != 0) {
			log_error("%s: request to send \"%s\" by user id %d\n", pathbuf, uid);
			continue;
		}

		savelog_busy++;

		savelog_store_fn(pathbuf);

		savelog_busy--;
	}
}

int
savelog_proxy_start(void)
{
	struct sockaddr_un sun;
	int sock_fd = -1, one = 1;
	pid_t pid;
	int rv = -1;

	if (savelog_store_fn == NULL)
		return 0;

	if ((sock_fd = socket(PF_LOCAL, SOCK_DGRAM, 0)) < 0) {
		log_error("Unable to open AF_LOCAL dgram socket: %m\n");
		return -1;
	}

	if (setsockopt(sock_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
		log_error("Unable to set SO_PASSCRED on AF_LOCAL dgram socket: %m\n");
		goto out;
	}

	sun.sun_family = AF_LOCAL;
	if (bind(sock_fd, &sun, sizeof(sa_family_t)) < 0) {
		log_error("Unable to autobind AF_LOCAL dgram socket: %m\n");
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		log_error("Unable to fork savelog proxy: %m\n");
		goto out;
	}

	if (pid == 0) {
		savelog_close_fds(sock_fd);
		savelog_proxy_mainloop(sock_fd);
		exit(99);
	}

	if (savelog_export_sockname(sock_fd) < 0)
		goto out;

	rv = 0;

out:
	if (sock_fd >= 0)
		close(sock_fd);

	return rv;
}

int
savelog_proxy_connect(void)
{
	int sock_fd = -1, one = 1;
	int rv = -1;

	if ((sock_fd = socket(PF_LOCAL, SOCK_DGRAM, 0)) < 0) {
		log_error("Unable to open AF_LOCAL dgram socket: %m\n");
		return -1;
	}

	if (setsockopt(sock_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) < 0) {
		log_error("Unable to set SO_PASSCRED on AF_LOCAL dgram socket: %m\n");
		goto out;
	}

	if (savelog_connect_sockname(sock_fd) < 0) {
		log_error("Cannot connect savelog service; no or bad address\n");
		return -1;
	}

	return sock_fd;

out:
	if (sock_fd >= 0)
		close(sock_fd);

	return rv;
}


void
savelog_post_nsenter_cb(void)
{
	if (savelog_proxy_start() < 0)
		exit(1);
}

#ifndef offsetof
#define offsetof(__type, __member) \
	((unsigned long) (&(((__type *) 0)->__member)))
#endif

static const char *
unix_path_print(struct sockaddr_un *sun, socklen_t len)
{
	static const unsigned int PATH_OFFSET = offsetof(struct sockaddr_un, sun_path);
	static char namebuf[256];
	unsigned int path_len;

	if (len <= PATH_OFFSET) {
		log_error("%s: address too short (%u < %u)\n", __func__, len, PATH_OFFSET);
		return NULL;
	}

	path_len = len - PATH_OFFSET;
	strncpy(namebuf + 1, sun->sun_path + 1, path_len);
	namebuf[0] = '@';
	namebuf[path_len] = '\0';

	return namebuf;
}

static int
unix_path_parse(struct sockaddr_un *sun, const char *name)
{
	static const unsigned int PATH_OFFSET = offsetof(struct sockaddr_un, sun_path);
	unsigned int len;

	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_LOCAL;

	if (!name || name[0] != '@' || name[1] == '\0')
		return -1;
	++name;

	len = strlen(name);
	if (len >= sizeof(sun->sun_path) - 1)
		return -1; /* too long */

	memcpy(sun->sun_path + 1, name, len);
	return PATH_OFFSET + 1 + len;
}

static int
unix_sender_uid(struct msghdr *msg)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
			struct ucred *uc = (struct ucred *) CMSG_DATA(cmsg);

			return uc->uid;
		}
	}

	return -1;
}

void
savelog_close_fds(int except_fd)
{
	int fd = getdtablesize();

#if 0
	while (--fd >= 0) {
		if (fd != except_fd)
			close(fd);
	}
#else
	struct stat stb1, stb2;

	if (fstat(0, &stb1) < 0)
		return;

	while (--fd >= 0) {
		if (fstat(fd, &stb2) >= 0
		 && stb1.st_dev == stb2.st_dev
		 && stb1.st_ino == stb2.st_ino)
			close(fd);
	}
#endif
}

int
savelog_export_sockname(int fd)
{
	struct sockaddr_un sun;
	const char *name;
	socklen_t ulen;

	ulen = sizeof(sun);
	if (getsockname(fd, (struct sockaddr *) &sun, &ulen) < 0) {
		log_error("Unable to obtain AF_LOCAL dgram socket name: %m\n");
		return -1;
	}

	if ((name = unix_path_print(&sun, ulen)) == NULL)
		return -1;

	setenv("SAVELOG_SOCKET", name, 1);
	return 0;
}

int
savelog_connect_sockname(int fd)
{
	struct sockaddr_un sun;
	const char *name;
	int ulen;

	if (!(name = getenv("SAVELOG_SOCKET"))) {
		log_error("SAVELOG_SOCKET not set\n");
		return -1;
	}

	if ((ulen = unix_path_parse(&sun, name)) < 0) {
		log_error("Unable to parse savelog socket addr \"%s\"\n", name);
		return -1;
	}

	if (connect(fd, (struct sockaddr *) &sun, ulen) < 0) {
		log_error("Unable to connect to savelog service at \"%s\": %m\n", name);
		return -1;
	}

	return 0;
}

static int
savelog_proxy_send(const char *pathname)
{
	char *abspath = NULL;
	int sock_fd = -1, rv = -1;

	if (pathname[0] != '/') {
		char cwd[PATH_MAX], fullpath[PATH_MAX];

		if (getcwd(cwd, sizeof(cwd)) < 0) {
			log_error("getcwd: %m\n");
			return -1;
		}

		snprintf(fullpath, sizeof(fullpath), "%s/%s", cwd, pathname);
		if ((abspath = realpath(fullpath, NULL)) == NULL) {
			log_error("realpath: %m\n");
			return -1;
		}

		pathname = abspath;
	}

	sock_fd = savelog_proxy_connect();
	if (sock_fd < 0)
		goto out;

	if (send(sock_fd, pathname, strlen(pathname), 0) < 0) {
		log_error("send: %m\n");
		goto out;
	}

	rv = 0;
out:
	if (sock_fd >= 0)
		close(sock_fd);

	if (abspath)
		free(abspath);

	return rv;
}

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
savelog_dirfd_send(int dirfd, const char *pathname)
{
	char *outname;
	int infd = -1, outfd = -1;
	unsigned long total = 0, size;
	struct stat stb;
	off_t offset = 0;
	int n, rv = -1;

	outname = savelog_dirfd_make_name(pathname);

	trace("Trying to save %s to dir @fd=%d\n", pathname, dirfd);
	if ((infd = open(pathname, O_RDONLY)) < 0) {
		log_error("savelog: unable to open \"%s\": %m\n", pathname);
		goto failed;
	}

	if (fstat(infd, &stb) < 0) {
		log_error("savelog: unable to stat \"%s\": %m\n", pathname);
		goto failed;
	}
	size = stb.st_size;

	if ((outfd = savelog_dirfd_open(dirfd, pathname)) < 0)
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

int
savelog_send_file(const char *pathname)
{
	int dirfd;

	if ((dirfd = savelog_dirfd_get()) >= 0)
		return savelog_dirfd_send(dirfd, pathname);

	return savelog_proxy_send(pathname);
}
