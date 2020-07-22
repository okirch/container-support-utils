/*
 * wormhole
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
#include "profiles.h"

#define WORMHOLE_SOCKET_PATH	"/var/run/wormhole.sock"

struct option wormhole_options[] = {
	{ "daemon",	no_argument,	NULL,	'D' },
	{ "foreground",	no_argument,	NULL,	'F' },
	{ "client",	no_argument,	NULL,	'C' },
	{ "direct",	no_argument,	NULL,	'N' },
	{ NULL }
};

static bool			opt_foreground = false;

static int			wormhole_direct(int argc, char **argv);
static int			wormhole_client(int argc, char **argv);
static int			wormhole_daemon(int argc, char **argv);
static void			wormhole_process_connection(int fd);

static int			frob_arguments(int, char **, int);

int
main(int argc, char **argv)
{
	int (*fn)(int, char **) = wormhole_client;
	bool need_to_frob = false;
	int c;

	while ((c = getopt_long(argc, argv, "", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'C':
			fn = wormhole_client;
			need_to_frob = true;
			break;
		case 'D':
			fn = wormhole_daemon;
			break;
		case 'F':
			opt_foreground = true;
			break;
		case 'N':
			fn = wormhole_direct;
			need_to_frob = true;
			break;

		default:
			fprintf(stderr, "Usage message goes here.\n");
			return 2;
		}
	}

	if (need_to_frob)
		argc = frob_arguments(argc, argv, optind);
	return fn(argc, argv);
}

int
frob_arguments(int argc, char **argv, int optind)
{
	int i;

	for (i = 1; optind < argc; ++i, ++optind)
		argv[i] = argv[optind];
	argv[i] = NULL;
	return i;
}

int
wormhole_direct(int argc, char **argv)
{
	struct profile *profile;

	if (argc == 0) {
		fprintf(stderr, "sneaky invocation detected. countermeasures initiated.\n");
		return 2;
	}

	profile = profile_find(argv[0]);
	if (profile == NULL) {
		fprintf(stderr, "no profile for %s.\n", argv[0]);
		return 2;
	}

	if (profile_setup(profile) < 0) {
		fprintf(stderr, "Failed to set up environment for %s\n", profile->name);
		return 2;
	}

	/* Drop uid/gid back to those of the calling user. */
	setgid(getgid());
	setuid(getuid());

	printf("I should now execute %s\n", profile->command);
	execv(profile->command, argv);

	fprintf(stderr, "Unable to execute %s: %m\n", profile->command);
	return 12;
}

int
wormhole_daemon(int argc, char **argv)
{
	struct sockaddr_un sun;
	int fd;

	if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return 1;
	}

	unlink(WORMHOLE_SOCKET_PATH);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, WORMHOLE_SOCKET_PATH);
	if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		perror("bind");
		return 1;
	}

	chmod(WORMHOLE_SOCKET_PATH, 0666);

	if (listen(fd, 10) < 0) {
		perror("listen");
		return 1;
	}

	if (!opt_foreground) {
		set_syslog("wormholed", LOG_DAEMON);
		if (daemon(false, false) < 0) {
			perror("listen");
			return 1;
		}
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

int
wormhole_client(int argc, char **argv)
{
	struct sockaddr_un sun;
	char pathbuf[PATH_MAX];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr align;
		char buf[1024];
	} u;
	int fd, nsfd = -1;

	if (argc == 0) {
		fprintf(stderr, "No argv[0]. How come?\n");
		return 2;
	}
	if (1) {
		int i;
		for (i = 0; i < argc; ++i)
			printf("argv[%d] = %s\n", i, argv[i]);
	}

	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 2;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, WORMHOLE_SOCKET_PATH);
	if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		perror("connect");
		return 1;
	}

	if (send(fd, argv[0], strlen(argv[0]), 0) < 0) {
		perror("send");
		return 1;
	}

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = pathbuf;
	iov.iov_len = sizeof(pathbuf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

        msg.msg_control = u.buf;
        msg.msg_controllen = sizeof(u.buf);

	if (recvmsg(fd, &msg, 0) < 0) {
		perror("recvmsg");
		return 1;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			memcpy(&nsfd, CMSG_DATA(cmsg), sizeof(int));
		}
	}

	if (nsfd < 0) {
		fprintf(stderr, "Server did not send us a namespace FD\n");
		return 2;
	}

	if (setns(nsfd, CLONE_NEWNS) < 0) {
		perror("setns");
		return 2;
	}

	/* Drop uid/gid back to those of the calling user. */
	setgid(getgid());
	setuid(getuid());

	printf("I should now execute %s\n", pathbuf);
	execv(pathbuf, argv);

	fprintf(stderr, "Unable to execute %s: %m\n", pathbuf);
	return 12;
}
