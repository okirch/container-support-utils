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
#include "util.h"

struct option wormhole_options[] = {
	{ "foreground",	no_argument,	NULL,	'F' },
	{ NULL }
};

static bool			opt_foreground = false;

static int			wormhole_daemon(int argc, char **argv);
static void			wormhole_process_connection(int fd);

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
		default:
			log_error("Usage message goes here.");
			return 2;
		}
	}

	return wormhole_daemon(argc - optind, argv + optind);
}

int
wormhole_daemon(int argc, char **argv)
{
	struct sockaddr_un sun;
	int fd;

	if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
		log_error("unable to create PF_LOCAL stream socket: %m");
		return 1;
	}

	if (unlink(WORMHOLE_SOCKET_PATH) < 0) {
		log_error("unlink(" WORMHOLE_SOCKET_PATH ") failed: %m");
		return 1;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, WORMHOLE_SOCKET_PATH);
	if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		log_error("cannot bind to %s: %m", WORMHOLE_SOCKET_PATH);
		return 1;
	}

	chmod(WORMHOLE_SOCKET_PATH, 0666);

	if (listen(fd, 10) < 0) {
		log_error("cannot listen on socket: %m");
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
		pid_t pid;
		int cfd;

		cfd = accept(fd, NULL, NULL);
		if (cfd < 0) {
			log_error("failed to accept incoming connection: %m");
			continue;
		}

		pid = fork();
		if (pid == 0) {
			wormhole_process_connection(cfd);
			exit(0);
		}

		if (pid < 0)
			log_error("failed to fork child process: %m");
		close(cfd);
	}

	return 0;
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
