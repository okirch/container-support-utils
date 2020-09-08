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

#include <sys/socket.h> /* only for send() call below - fix this */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <stdlib.h>
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

	basename = wormhole_const_basename(argv[0]);
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

	bp = wormhole_message_build_command_request(cmd);
	rv = send(fd, buf_head(bp), buf_available(bp), 0);
	if (rv < 0)
		log_error("send: %m");

	buf_free(bp);
	return rv;
}

static struct buf *
wormhole_recv_response(int sock_fd, int *resp_fd)
{
	struct buf *bp = buf_alloc();

	*resp_fd = -1;
	while (!wormhole_message_complete(bp)) {
		int received, fd;

		received = wormhole_socket_recvmsg(sock_fd, buf_tail(bp), buf_tailroom(bp), &fd);
		if (received < 0) {
			log_error("recvmsg: %m");
			goto failed;
		}

		if (received == 0) {
			log_error("%s: EOF on socket while waiting for complete message", __func__);
			goto failed;
		}

		__buf_advance_tail(bp, received);
		if (fd >= 0)
			*resp_fd = fd;
	}

	return bp;

failed:
	if (*resp_fd >= 0) {
		close(*resp_fd);
		*resp_fd = -1;
	}
	buf_free(bp);
	return NULL;
}

static bool
wormhole_recv_command_status(int sock_fd, char *cmdbuf, size_t cmdsize, int *resp_fd)
{
	struct wormhole_message_parsed *pmsg = NULL;
	struct buf *bp;

	if (!(bp = wormhole_recv_response(sock_fd, resp_fd)))
		goto failed;

	pmsg = wormhole_message_parse(bp, 0);
	if (pmsg == NULL) {
		log_error("Unable to parse server response!");
		goto failed;
	}

	switch (pmsg->hdr.opcode) {
	case WORMHOLE_OPCODE_STATUS:
		if (pmsg->payload.status.status != WORMHOLE_STATUS_OK) {
			log_error("Server returns error status %d!", pmsg->payload.command.status);
			goto failed;
		}
		cmdbuf[0] = '\0';
		break;

	case WORMHOLE_OPCODE_COMMAND_STATUS:
		if (pmsg->payload.command.status != WORMHOLE_STATUS_OK) {
			log_error("Server returns error status %d!", pmsg->payload.command.status);
			goto failed;
		}

		strncpy(cmdbuf, pmsg->payload.command.string, cmdsize - 1);
		break;

	default:
		log_error("Unexpected opcode %d in server response!", pmsg->hdr.opcode);
		goto failed;
	}

	return true;

failed:
	if (pmsg)
		wormhole_message_free_parsed(pmsg);
	if (bp)
		buf_free(bp);
	return false;
}

int
wormhole_client(int argc, char **argv)
{
	char pathbuf[PATH_MAX];
	wormhole_socket_t *s;
	int fd, nsfd = -1;

	s = wormhole_connect(WORMHOLE_SOCKET_PATH, NULL);
	if (s == NULL) {
		log_error("Unable to connect to wormhole daemon");
		return 2;
	}

	fd = s->fd;

	if (wormhole_send_command(fd, argv[0]) < 0)
		return 1;

	if (!wormhole_recv_command_status(fd, pathbuf, sizeof(pathbuf), &nsfd))
		return 1;

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
