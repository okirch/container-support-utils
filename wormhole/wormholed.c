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

#include <sys/poll.h>
#include <syslog.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>

#include "tracing.h"
#include "wormhole.h"
#include "profiles.h"
#include "runtime.h"
#include "socket.h"
#include "protocol.h"
#include "buffer.h"
#include "util.h"

typedef struct wormhole_request wormhole_request_t;
struct wormhole_request {
	wormhole_request_t *next;

	int		version;
	int		opcode;

	struct wormhole_message_parsed *message;

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
static void			wormhole_reap_children(void);

static bool			wormhole_message_consume(wormhole_socket_t *s, struct buf *bp, int fd);

static wormhole_request_t *	wormhole_request_list;

static wormhole_request_t *	wormhole_request_new(struct wormhole_message_parsed *pmsg);
static void			wormhole_request_free(wormhole_request_t *);

static void			wormhole_enqueue_request_incoming(wormhole_request_t *req);
static void			wormhole_process_pending_requests(void);
static void			wormhole_process_request(wormhole_request_t *req);

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
	wormhole_socket_t *srv_sock;

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

	wormhole_install_sigchild_handler();

	while (wormhole_sockets) {
		struct pollfd poll_array[WORMHOLE_SOCKET_MAX];
		wormhole_socket_t *sock_array[WORMHOLE_SOCKET_MAX];
		wormhole_socket_t **pos, *s;
		int i, nfd = 0;

		wormhole_reap_children();

		wormhole_process_pending_requests();

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
			if (errno != EINTR)
				log_error("poll: %m");
			continue;
		}

		for (i = 0; i < nfd; ++i) {
			s = sock_array[i];
			if (!s->ops->process(s, poll_array + i)) {
				/* should drop the socket */
			}
		}
	}

	return 0;
}

static void
wormhole_reap_children(void)
{
	pid_t pid;
	int st;

	while ((pid = wormhole_get_exited_child(&st)) > 0) {
		wormhole_environment_async_complete(pid, st);
	}
}

bool
wormhole_message_consume(wormhole_socket_t *s, struct buf *bp, int fd)
{
	struct wormhole_message_parsed *pmsg;
	wormhole_request_t *req;

	if (!wormhole_message_complete(bp))
		return false;

	if (!(pmsg = wormhole_message_parse(bp, s->uid))) {
		log_error("Bad message from uid %d", s->uid);
		/* Mark socket for closing */
		return false;
	}

	req = wormhole_request_new(pmsg);
	if (req) {
		req->socket_id = s->id;
		req->client_uid = s->uid;
		wormhole_enqueue_request_incoming(req);

		trace("received message opcode=%d, uid=%d", req->opcode, req->client_uid);
	}

	return true;
}

wormhole_request_t *
wormhole_request_new(struct wormhole_message_parsed *pmsg)
{
	wormhole_request_t *r;

	r = calloc(1, sizeof(*r));
	r->opcode = pmsg->hdr.opcode;
	r->version = pmsg->hdr.version;
	r->message = pmsg;

	return r;
}

void
wormhole_request_free(wormhole_request_t *req)
{
	wormhole_message_free_parsed(req->message);
	memset(req, 0xA5, sizeof(*req));
	free(req);
}

static void
wormhole_request_list_insert(wormhole_request_t **list, wormhole_request_t *req)
{
	req->next = *list;
	*list = req;
}

void
wormhole_enqueue_request_incoming(wormhole_request_t *req)
{
	wormhole_request_list_insert(&wormhole_request_list, req);
}

static bool
__wormhole_respond(wormhole_request_t *req, struct buf *bp, int fd)
{
	wormhole_socket_t *s;
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
wormhole_respond(wormhole_request_t *req, int status)
{
	__wormhole_respond(req, wormhole_message_build_status(status), -1);
}

void
wormhole_process_command(wormhole_request_t *req)
{
	const char *name;
	struct wormhole_environment *env;
	struct profile *profile;

	name = req->message->payload.command.string;
	trace("Processing request for command \"%s\" from uid %d", name, req->client_uid);

	profile = profile_find(name);
	if (profile == NULL) {
		log_error("no profile for %s", name);
		wormhole_respond(req, WORMHOLE_STATUS_ERROR);
		return;
	}

	env = wormhole_environment_find(profile->name);

	/* If the setup command exited with an error status, return a failure indication
	 * to the client. */
	if (env->failed) {
		log_info("request for namespace \"%s\": failed", profile->name);
		wormhole_respond(req, WORMHOLE_STATUS_ERROR);
		return;
	}

	if (env->nsfd < 0) {
		wormhole_socket_t *setup_sock;

		if (env->setup_ctx.child_pid != 0) {
			trace("setup for \"%s\" is in process, delaying", env->name);
			return;
		}

		/* The profile setup starts a process in the background,
		 * connected via a socketpair. When it completes, it passes
		 * a namespace fd back to the daemon process.
		 */
		setup_sock = wormhole_environment_async_setup(env, profile);

		/* set up a socket to recv the namespace FD from the child
		 * process. */
		wormhole_install_socket(setup_sock);
		env->setup_ctx.sock_id = setup_sock->id;
		return;
	}

	__wormhole_respond(req,
		wormhole_message_build_command_status(WORMHOLE_STATUS_OK, profile->command),
		env->nsfd);

	log_info("served request for a \"%s\" namespace", profile->name);
}

void
wormhole_process_request(wormhole_request_t *req)
{
	switch (req->opcode) {
	case WORMHOLE_OPCODE_COMMAND_REQUEST:
		wormhole_process_command(req);
		break;

	default:
		log_error("Unknown opcode %d from uid %d", req->opcode, req->client_uid);
		wormhole_respond(req, WORMHOLE_STATUS_ERROR);
		break;
	}
}

void
wormhole_process_pending_requests(void)
{
	wormhole_request_t **pos, *req;

	for (pos = &wormhole_request_list; (req = *pos) != NULL; ) {
		/* See if we can complete the request. */
		wormhole_process_request(req);

		if (req->reply_sent) {
			*pos = req->next;
			wormhole_request_free(req);
			continue;
		}

		pos = &req->next;
	}
}
