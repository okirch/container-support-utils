/*
 * wormholed - server process
 *
 *   Copyright (C) 2020 Olaf Kirch <okir@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <syslog.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <libgen.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>

#include "tracing.h"
#include "wormhole.h"
#include "profiles.h"
#include "runtime.h"

struct wormhole_socket {
	int		fd;
	struct wormhole_socket_ops {
		bool	(*poll)(struct wormhole_socket *, struct pollfd *);
		bool	(*process)(struct wormhole_socket *, struct pollfd *);
	} * ops;

	uid_t		uid;
	gid_t		gid;
};

struct option wormhole_options[] = {
	{ "foreground",	no_argument,		NULL,	'F' },
	{ "runtime",	required_argument,	NULL,	'R' },
	{ NULL }
};

static const char *		opt_runtime = "default";
static bool			opt_foreground = false;

static int			wormhole_daemon(int argc, char **argv);

static struct wormhole_socket *	wormhole_listen(const char *path);
static struct wormhole_socket *	wormhole_accept_connection(int fd);
static void			wormhole_process_connection(int fd);
static void			wormhole_socket_free(struct wormhole_socket *conn);

int
main(int argc, char **argv)
{
	int c;

	/* Someone trying to invoke us without argv0 doesn't deserve
	 * an error message. */
	if (argc == 0)
		return 2;

	while ((c = getopt_long(argc, argv, "", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'F':
			opt_foreground = true;
			break;
		case 'R':
			opt_runtime = optarg;
			break;
		default:
			log_error("Usage message goes here.");
			return 2;
		}
	}

	if (!wormhole_select_runtime(opt_runtime))
		log_fatal("Unable to set up requested container runtime");

	return wormhole_daemon(argc - optind, argv + optind);
}

int
wormhole_daemon(int argc, char **argv)
{
	struct wormhole_socket *srv_sock;

	srv_sock = wormhole_listen(WORMHOLE_SOCKET_PATH);
	if (srv_sock == NULL) {
		log_error("Cannot set up server socket %s", WORMHOLE_SOCKET_PATH);
		return 1;
	}

	log_info("wormhole daemon: listening on %s", WORMHOLE_SOCKET_PATH);

	if (!opt_foreground) {
		if (daemon(false, false) < 0) {
			log_error("cannot background server process: %m");
			return 1;
		}

		set_syslog("wormholed", LOG_DAEMON);
	}

	while (true) {
		struct wormhole_socket *conn;
		pid_t pid;

		conn = wormhole_accept_connection(srv_sock->fd);
		if (conn == NULL)
			continue;

		pid = fork();
		if (pid == 0) {
			wormhole_process_connection(conn->fd);
			exit(0);
		}

		if (pid < 0)
			log_error("failed to fork child process: %m");
		wormhole_socket_free(conn);
	}

	return 0;
}

static struct wormhole_socket *
wormhole_socket_new(int fd, uid_t uid, gid_t gid)
{
	struct wormhole_socket *conn;

	conn = calloc(1, sizeof(*conn));
	conn->fd = fd;
	conn->uid = uid;
	conn->gid = gid;

	return conn;
}

static struct wormhole_socket *
wormhole_listen(const char *path)
{
	struct sockaddr_un sun;
	int fd;

	if (unlink(path) < 0) {
		log_error("unlink(%s) failed: %m", path);
		return NULL;
	}

	if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
		log_error("unable to create PF_LOCAL stream socket: %m");
		return NULL;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, path);
	if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		log_error("cannot bind to %s: %m", path);
		close(fd);
		return NULL;
	}

	chmod(path, 0666);

	if (listen(fd, 10) < 0) {
		log_error("cannot listen on socket: %m");
		close(fd);
		return NULL;
	}

	return wormhole_socket_new(fd, 0, 0);
}

struct wormhole_socket *
wormhole_accept_connection(int fd)
{
	int cfd;
	struct ucred cred;
        socklen_t clen;

	cfd = accept(fd, NULL, NULL);
	if (cfd < 0) {
		log_error("failed to accept incoming connection: %m");
		return NULL;
	}

	clen = sizeof(cred);
	if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) < 0) {
		log_error("failed to get client credentials: %m");
		close(cfd);
		return NULL;
	}

	return wormhole_socket_new(cfd, cred.uid, cred.gid);
}

void
wormhole_process_connection(int fd)
{
	struct profile *profile;
	char namebuf[1024];
	union {
		struct cmsghdr align;
		char buf[1024];
	} u;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int n, nsfd;

	alarm(5);

	if ((n = recv(fd, namebuf, sizeof(namebuf) - 1, 0)) < 0)
		log_fatal("recv: %m");
	namebuf[n] = '\0';

	profile = profile_find(namebuf);
	if (profile == NULL)
		log_fatal("no profile for %s", namebuf);

	if (profile_setup(profile) < 0)
		log_fatal("Failed to set up environment for %s", profile->name);

	nsfd = open("/proc/self/ns/mnt", O_RDONLY);
	if (nsfd < 0)
		log_fatal("Cannot open /proc/self/ns/mnt: %m");

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = profile->command;
	iov.iov_len = strlen(profile->command);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

        msg.msg_control = u.buf;
        msg.msg_controllen = sizeof(u.buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &nsfd, sizeof(int));
	msg.msg_controllen = CMSG_SPACE(sizeof(int));

	if (sendmsg(fd, &msg, 0) < 0)
		log_fatal("sendmsg: %m");

	log_info("served request for a \"%s\" namespace", profile->name);
	return;
}

void
wormhole_socket_free(struct wormhole_socket *conn)
{
	if (conn->fd >= 0)
		close(conn->fd);
	free(conn);
}
