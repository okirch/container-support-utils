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
#include "socket.h"
#include "protocol.h"
#include "buffer.h"

struct wormhole_request {
	struct wormhole_request *next;

	int		version;
	int		opcode;

	void *		payload;
	size_t		payload_len;

	unsigned int	socket_id;
	uid_t		client_uid;
	bool		reply_sent;
};

struct option wormhole_options[] = {
	{ "foreground",	no_argument,		NULL,	'F' },
	{ "runtime",	required_argument,	NULL,	'R' },
	{ "debug",	no_argument,		NULL,	'd' },
	{ NULL }
};

static const char *		opt_runtime = "default";
static bool			opt_foreground = false;

static int			wormhole_daemon(int argc, char **argv);

extern bool			wormhole_message_consume(struct wormhole_socket *s, struct buf *bp);

static struct wormhole_request *wormhole_incoming_requests;
static struct wormhole_request *wormhole_pending_requests;

static struct wormhole_request *wormhole_request_new(const struct wormhole_message *msg, const void *payload);
static void			wormhole_request_free(struct wormhole_request *);

static void			wormhole_enqueue_request_incoming(struct wormhole_request *req);
static void			wormhole_enqueue_request_pending(struct wormhole_request *req);
static void			wormhole_process_request(struct wormhole_request *req);

int
main(int argc, char **argv)
{
	int c;

	/* Someone trying to invoke us without argv0 doesn't deserve
	 * an error message. */
	if (argc == 0)
		return 2;

	while ((c = getopt_long(argc, argv, "d", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'F':
			opt_foreground = true;
			break;
		case 'R':
			opt_runtime = optarg;
			break;
		case 'd':
			tracing_enable();
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
	static struct wormhole_app_ops app_ops = {
		.new_socket = wormhole_install_socket,
		.received = wormhole_message_consume,
	};
	struct wormhole_socket *srv_sock;

	srv_sock = wormhole_listen(WORMHOLE_SOCKET_PATH, &app_ops);
	if (srv_sock == NULL) {
		log_error("Cannot set up server socket %s", WORMHOLE_SOCKET_PATH);
		return 1;
	}
	wormhole_install_socket(srv_sock);

	log_info("wormhole daemon: listening on %s", WORMHOLE_SOCKET_PATH);

	if (!opt_foreground) {
		if (daemon(false, false) < 0) {
			log_error("cannot background server process: %m");
			return 1;
		}

		set_syslog("wormholed", LOG_DAEMON);
	}

	while (wormhole_sockets) {
		struct pollfd poll_array[WORMHOLE_SOCKET_MAX];
		struct wormhole_socket *sock_array[WORMHOLE_SOCKET_MAX];
		struct wormhole_socket **pos, *s;
		int i, nfd = 0;
		struct wormhole_socket *conn;
		struct wormhole_request *req;
		pid_t pid;

		for (pos = &wormhole_sockets; (s = *pos) != NULL; ) {
			assert(nfd < WORMHOLE_SOCKET_MAX);

			if (!s->ops->poll(s, poll_array + nfd)) {
				wormhole_socket_free(s);
				continue;
			}

			poll_array[nfd].fd = s->fd;
			sock_array[nfd] = s;
			nfd += 1;

			pos = &s->next;
		}

		if (poll(poll_array, nfd, -1) < 0) {
			log_error("poll: %m");
			continue;
		}

		for (i = 0; i < nfd; ++i) {
			s = sock_array[i];
			if (!s->ops->process(s, poll_array + i)) {
				/* should drop the socket */
			}
		}

		while ((req = wormhole_incoming_requests) != NULL) {
			wormhole_incoming_requests = req->next;
			req->next = NULL;

			trace("dequeuing req %p", req);
			wormhole_process_request(req);

			if (req->reply_sent) {
				wormhole_request_free(req);
			} else {
				wormhole_enqueue_request_pending(req);
			}
		}

		continue;
		conn = wormhole_accept_connection(srv_sock->fd);
		if (conn == NULL)
			continue;

		pid = fork();
		if (pid == 0) {
			exit(0);
		}

		if (pid < 0)
			log_error("failed to fork child process: %m");
		wormhole_socket_free(conn);
	}

	return 0;
}

bool
wormhole_message_consume(struct wormhole_socket *s, struct buf *bp)
{
	struct wormhole_message msg;
	const void *payload;
	struct wormhole_request *req;

	if (!wormhole_message_dissect(bp, &msg, &payload))
		return false;

	if (WORMHOLE_PROTOCOL_MAJOR(msg.version) != WORMHOLE_PROTOCOL_VERSION_MAJOR) {
		log_error("incompatible protocol message (version 0x%x) from uid %d",
				msg.version, s->uid);
		/* Mark socket for closing */
		return false;
	}

	req = wormhole_request_new(&msg, payload);
	if (req) {
		req->socket_id = s->id;
		req->client_uid = s->uid;
		wormhole_enqueue_request_incoming(req);
	}

	return true;
}

struct wormhole_request *
wormhole_request_new(const struct wormhole_message *msg, const void *payload)
{
	struct wormhole_request *r;

	/* Note the +1. This makes sure that any string arguments are NUL terminated */
	r = calloc(1, sizeof(*r) + msg->payload_len + 1);

	r->opcode = msg->opcode;
	r->version = msg->version;

	if (msg->payload_len) {
		r->payload = (void *) (r + 1);
		r->payload_len = msg->payload_len;
		memcpy(r->payload, payload, r->payload_len);
	}

	trace("received message opcode=%d payload=%u bytes", r->opcode, r->payload_len);
	return r;
}

void
wormhole_request_free(struct wormhole_request *req)
{
	memset(req, 0xA5, sizeof(*req));
	free(req);
}

static void
wormhole_request_list_insert(struct wormhole_request **list, struct wormhole_request *req)
{
	req->next = *list;
	*list = req;
}

void
wormhole_enqueue_request_incoming(struct wormhole_request *req)
{
	wormhole_request_list_insert(&wormhole_incoming_requests, req);
}

void
wormhole_enqueue_request_pending(struct wormhole_request *req)
{
	wormhole_request_list_insert(&wormhole_pending_requests, req);
}

static bool
__wormhole_respond(struct wormhole_request *req, struct buf *bp, int fd)
{
	struct wormhole_socket *s;
	bool ok = false;

	s = wormhole_socket_find(req->socket_id);
	if (s != NULL) {
		wormhole_socket_enqueue(s, bp, fd);
		ok = true;
	} else {
		/* Client disconnected while we were processing the
		 * request. Pretend we sent the reply. */
		buf_free(bp);
	}

	req->reply_sent = true;
	return ok;
}

static void
wormhole_respond_with_fd(struct wormhole_request *req, int fd)
{
	struct wormhole_socket *s;
	struct buf *bp;

	s = wormhole_socket_find(req->socket_id);
	if (s == NULL)
		return;

	bp = wormhole_message_build_status(WORMHOLE_STATUS_OK);
	wormhole_socket_enqueue(s, bp, fd);

	req->reply_sent = true;
}

static void
wormhole_respond(struct wormhole_request *req, int status)
{
	__wormhole_respond(req, wormhole_message_build_status(status), -1);
}

void
wormhole_process_command(struct wormhole_request *req)
{
	const char *name;
	struct wormhole_environment *env;
	struct profile *profile;

	name = (const char *) (req->payload);
	trace("Processing request for command \"%s\" from uid %d", name, req->client_uid);

	profile = profile_find(name);
	if (profile == NULL) {
		log_error("no profile for %s", name);
		wormhole_respond(req, WORMHOLE_STATUS_ERROR);
		return;
	}

	env = wormhole_environment_find(profile->name);
	if (env->nsfd < 0) {
		if (env->setup_ctx.child_pid != 0) {
			trace("setup for \"%s\" is in process, delaying", env->name);
			return;
		}

		wormhole_environment_async_setup(env, profile);
		return;
	}

	log_info("served request for a \"%s\" namespace", profile->name);
	wormhole_respond_with_fd(req, env->nsfd);
}

void
wormhole_process_request(struct wormhole_request *req)
{
	switch (req->opcode) {
	case WORMHOLE_OPCODE_COMMAND:
		wormhole_process_command(req);
		break;

	default:
		log_error("Unknown opcode %d from uid %d", req->opcode, req->client_uid);
		wormhole_respond(req, WORMHOLE_STATUS_ERROR);
		break;
	}
}
