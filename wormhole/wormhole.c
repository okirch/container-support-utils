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
#include "wormhole.h"
#include "protocol.h"
#include "socket.h"
#include "util.h"
#include "buffer.h"

struct option wormhole_options[] = {
	{ NULL }
};

int
main(int argc, char **argv)
{
	const char *basename;
	int c;

	/* Someone trying to invoke us without argv0 doesn't deserve
	 * an error message. */
	if (argc == 0)
		return 2;

	basename = const_basename(argv[0]);
	if (basename == NULL)
		return 2;

	if (strcmp(basename, "wormhole") != 0)
		return wormhole_client(argc, argv);

	while ((c = getopt_long(argc, argv, "", wormhole_options, NULL)) != EOF) {
		switch (c) {
		default:
			log_error("Usage message goes here.");
			return 2;
		}
	}

	return wormhole_client(argc - optind, argv + optind);
}

static int
wormhole_send_command(int fd, const char *cmd)
{
	struct buf *bp;
	int rv = 0;

	bp = wormhole_message_build(WORMHOLE_OPCODE_COMMAND, cmd, strlen(cmd));
	rv = send(fd, buf_head(bp), buf_available(bp), 0);
	if (rv < 0)
		log_error("send: %m");

	buf_free(bp);
	return rv;
}

int
wormhole_client(int argc, char **argv)
{
	struct sockaddr_un sun;
	char pathbuf[PATH_MAX];
	int fd, nsfd = -1;

	if (1)
		printf("Executed as: %s\n", concat_argv(argc, argv));

	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		log_error("socket: %m");
		return 2;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, WORMHOLE_SOCKET_PATH);
	if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		log_error("connect: %m");
		return 1;
	}

	if (wormhole_send_command(fd,  argv[0]) < 0)
		return 1;

	if (wormhole_socket_recvmsg(fd, pathbuf, sizeof(pathbuf), &nsfd) < 0) {
		log_error("recvmsg: %m");
		return 1;
	}

	if (nsfd < 0) {
		log_error("Server did not send us a namespace FD");
		return 2;
	}

	if (setns(nsfd, CLONE_NEWNS) < 0) {
		log_error("setns: %m");
		return 2;
	}

	/* Drop uid/gid back to those of the calling user. */
	setgid(getgid());
	setuid(getuid());

	printf("I should now execute %s\n", pathbuf);
	execv(pathbuf, argv);

	log_error("Unable to execute %s: %m", pathbuf);
	return 12;
}
