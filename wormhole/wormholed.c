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
#include "config.h"
#include "runtime.h"
#include "socket.h"
#include "protocol.h"
#include "buffer.h"
#include "server.h"
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
	{ "name",	required_argument,	NULL,	'N' },
	{ "debug",	no_argument,		NULL,	'd' },
	{ NULL }
};

static const char *		opt_server_path;
static const char *		opt_runtime = "default";
static const char *		opt_socket_name = WORMHOLE_SOCKET_PATH;
static bool			opt_foreground = false;

static int			wormhole_daemon(const char *socket_path);
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
	struct wormhole_config *config;
	int c;

	opt_server_path = argv[0];

	while ((c = getopt_long(argc, argv, "dFR:N:", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'F':
			opt_foreground = true;
			break;
		case 'R':
			opt_runtime = optarg;
			break;
		case 'N':
			opt_socket_name = optarg;
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

	if (!(config = wormhole_config_load(WORMHOLE_CONFIG_PATH)))
		log_fatal("Unable to load configuration file");

	if (!wormhole_profiles_configure(config))
		log_fatal("Bad configuration, cannot continue.");

	return wormhole_daemon(opt_socket_name);
}

int
wormhole_daemon(const char *socket_path)
{
	static struct wormhole_app_ops app_ops = {
		.new_socket = wormhole_install_socket,
		.received = wormhole_message_consume,
	};
	wormhole_socket_t *srv_sock;

	srv_sock = wormhole_listen(socket_path, &app_ops);
	if (srv_sock == NULL) {
		log_error("Cannot set up server socket %s", socket_path);
		return 1;
	}
	wormhole_install_socket(srv_sock);

	log_info("wormhole daemon: listening on %s", socket_path);

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
				/* remove socket from linked list and free it. */
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
				wormhole_socket_free(s);
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
		if (fd >= 0)
			close(fd);
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
	wormhole_environment_t *env;
	wormhole_profile_t *profile;
	wormhole_socket_t *setup_sock;
	int nsfd;

	name = req->message->payload.command.string;
	trace("Processing request for command \"%s\" from uid %d", name, req->client_uid);

	profile = wormhole_profile_find(name);
	if (profile == NULL) {
		log_error("no profile for %s", name);
		wormhole_respond(req, WORMHOLE_STATUS_ERROR);
		return;
	}

	nsfd = wormhole_profile_namespace_fd(profile);
	if (nsfd >= 0) {
		__wormhole_respond(req,
			wormhole_message_build_command_status(WORMHOLE_STATUS_OK, wormhole_profile_command(profile)),
			nsfd);
		log_info("served request for a \"%s\" namespace", profile->name);
		return;
	}

	if (!(env = profile->environment)) {
		/* For profiles that do not reference an environment, the call to
		 * wormhole_profile_namespace_fd() should have returned a valid file
		 * descriptor, namely an fd for our host namespace.
		 * If we get here nevertheless, something is very wrong. */
		log_error("Profile %s: no environment associated", profile->name);
		wormhole_respond(req, WORMHOLE_STATUS_ERROR);
		return;
	}

	/* If the setup command exited with an error status, return a failure indication
	 * to the client. */
	if (env->failed) {
		log_info("request for namespace \"%s\": failed", profile->name);
		wormhole_respond(req, WORMHOLE_STATUS_ERROR);
		return;
	}

	if (env->setup_ctx.child_pid != 0) {
		trace("setup for \"%s\" is in process, delaying", env->name);
		return;
	}

	/* The profile setup starts a process in the background,
	 * connected via a socketpair. When it completes, it passes
	 * a namespace fd back to the daemon process.
	 */
	setup_sock = wormhole_environment_async_setup(env, profile);
	if (setup_sock == NULL) {
		log_error("Profile %s: unable to create setup process", profile->name);
		wormhole_respond(req, WORMHOLE_STATUS_ERROR);
		env->failed = true;
	} else {
		wormhole_install_socket(setup_sock);
	}
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

/* We should encapsulate the setns stuff somewhere */
#include <sched.h>

bool
wormhole_start_sub_daemon(wormhole_environment_t *env)
{
	const char *argv[16];
	int argc;
	char namebuf[128];
	pid_t pid;

	snprintf(namebuf, sizeof(namebuf), "@wormhole/%s", env->name);
	env->sub_daemon.socket_name = strdup(namebuf);

	trace("Starting daemon process %s", namebuf);

	pid = fork();
	if (pid < 0) {
		log_error("Failed to start daemon process %s: fork: %m", namebuf);
		return false;
	}

	if (pid > 0) {
		env->sub_daemon.pid = pid;
		return true;
	}

	/* Change to the namespace */
	if (setns(env->nsfd, CLONE_NEWNS) < 0) {
                log_error("setns: %m");
                exit(2);
        }

	/* FIXME: we should probably create a separate cgroup for
	 * each wormhole environment. This would help with a clean
	 * shutdown. */

	argc = 0;
	argv[argc++] = opt_server_path;
	argv[argc++] = "--name";
	argv[argc++] = namebuf;
	argv[argc++] = "--foreground";
	argv[argc++] = "--runtime";
	argv[argc++] = opt_runtime;
	argv[argc] = NULL;

	execv(opt_server_path, (char **) argv);
	log_error("Failed to start %s: %m", opt_server_path);

	exit(22);
}
