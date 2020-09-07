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
#include "protocol.h"
#include "buffer.h"

struct wormhole_socket {
	struct wormhole_socket **prevp;
	struct wormhole_socket *next;

	unsigned int	id;
	int		fd;

	const struct wormhole_socket_ops {
		bool	(*poll)(struct wormhole_socket *, struct pollfd *);
		bool	(*process)(struct wormhole_socket *, struct pollfd *);
	} * ops;

	/* FIXME: add idle timeout */
	time_t		timeout;

	uid_t		uid;
	gid_t		gid;

	bool		recv_closed;
	bool		send_closed;

	struct buf *	recvbuf;
	struct buf *	sendbuf;
};

struct option wormhole_options[] = {
	{ "foreground",	no_argument,		NULL,	'F' },
	{ "runtime",	required_argument,	NULL,	'R' },
	{ "debug",	no_argument,		NULL,	'd' },
	{ NULL }
};

#define WORMHOLE_SOCKET_MAX	1024

static const char *		opt_runtime = "default";
static bool			opt_foreground = false;

static int			wormhole_daemon(int argc, char **argv);

static struct wormhole_socket * wormhole_sockets = NULL;
static unsigned int		wormhole_socket_count = 0;

static struct wormhole_socket *	wormhole_listen(const char *path);
static struct wormhole_socket *	wormhole_accept_connection(int fd);
static void			wormhole_install_socket(struct wormhole_socket *);
static void			wormhole_uninstall_socket(struct wormhole_socket *);
static struct wormhole_socket *	wormhole_socket_find(unsigned int id);
static void			wormhole_socket_free(struct wormhole_socket *conn);
static struct wormhole_socket *	wormhole_connected_socket_new(int fd, uid_t uid, gid_t gid);
static void			wormhole_drop_recvbuf(struct wormhole_socket *s);
static void			wormhole_drop_sendbuf(struct wormhole_socket *s);

extern bool			wormhole_message_consume(struct wormhole_socket *s, struct buf *bp);

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

static struct wormhole_request *wormhole_incoming_requests;
static struct wormhole_request *wormhole_pending_requests;

static struct wormhole_request *wormhole_request_new(const struct wormhole_message *msg, const void *payload);
static void			wormhole_request_free(struct wormhole_request *);

static void			wormhole_enqueue_request_incoming(struct wormhole_request *req);
static void			wormhole_enqueue_request_pending(struct wormhole_request *req);
static void			wormhole_process_request(struct wormhole_request *req);

static struct wormhole_socket *	__wormhole_socket_accept(int fd, struct wormhole_socket *(*factory)(int, uid_t, gid_t));

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
	struct wormhole_socket *srv_sock;

	srv_sock = wormhole_listen(WORMHOLE_SOCKET_PATH);
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

void
wormhole_install_socket(struct wormhole_socket *s)
{
	struct wormhole_socket **pos;

	/* brutal for now */
	assert(wormhole_socket_count < WORMHOLE_SOCKET_MAX);

	if (s->prevp != NULL) {
		log_error("%s: cannot install socket twice", __func__);
		return;
	}

	for (pos = &wormhole_sockets; *pos; pos = &((*pos)->next))
		;

	*pos = s;
	s->prevp = pos;

	wormhole_socket_count++;
}

void
wormhole_uninstall_socket(struct wormhole_socket *s)
{
	if (s->prevp == NULL)
		return;

	*(s->prevp) = s->next;
	if (s->next)
		s->next->prevp = s->prevp;

	s->prevp = NULL;
	s->next = NULL;

	wormhole_socket_count--;
}

static struct wormhole_socket *
wormhole_socket_find(unsigned int id)
{
	struct wormhole_socket *s;
	for (s = wormhole_sockets; s; s = s->next) {
		if (s->id == id)
			return s;
	}
	return NULL;
}

static struct wormhole_socket *
wormhole_socket_new(const struct wormhole_socket_ops *ops, int fd, uid_t uid, gid_t gid)
{
	static unsigned int __wormhole_socket_id = 1;
	struct wormhole_socket *conn;

	conn = calloc(1, sizeof(*conn));
	conn->ops = ops;
	conn->id = __wormhole_socket_id++;
	conn->fd = fd;
	conn->uid = uid;
	conn->gid = gid;

	return conn;
}

/*
 * Listening socket
 */
static bool
__wormhole_passive_socket_poll(struct wormhole_socket *s, struct pollfd *pfd)
{
	pfd->events = POLLIN;
	return true;
}

static bool
__wormhole_passive_socket_process(struct wormhole_socket *s, struct pollfd *pfd)
{
	if (pfd->revents & POLLIN) {
		struct wormhole_socket *new_sock;

		new_sock = __wormhole_socket_accept(s->fd, wormhole_connected_socket_new);
		if (new_sock)
			wormhole_install_socket(new_sock);
	}

	return true;
}

static struct wormhole_socket_ops __wormhole_passive_socket_ops = {
	.poll		= __wormhole_passive_socket_poll,
	.process	= __wormhole_passive_socket_process,
};

static struct wormhole_socket *
wormhole_listen(const char *path)
{
	struct sockaddr_un sun;
	int fd;

	if (unlink(path) < 0 && errno != ENOENT) {
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

	return wormhole_socket_new(&__wormhole_passive_socket_ops, fd, 0, 0);
}

static struct wormhole_socket *
__wormhole_socket_accept(int fd, struct wormhole_socket *(*factory)(int, uid_t, gid_t))
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

	return factory(cfd, cred.uid, cred.gid);
}

struct wormhole_socket *
wormhole_accept_connection(int fd)
{
	return __wormhole_socket_accept(fd, wormhole_connected_socket_new);
}

/*
 * Connected socket send/recv functions
 */
static bool
__wormhole_socket_recv(struct wormhole_socket *s, struct buf *bp)
{
	unsigned char data[512];
	unsigned int room;
	int n;

	room = buf_tailroom(bp);
	if (room == 0) {
		log_error("%s: recv buffer overflow", __func__);
		return false;
	}

	if (room > sizeof(data))
		room = sizeof(data);

	n = recv(s->fd, data, room, 0);
	if (n < 0) {
		log_error("recv error on socket: %m");
		return false;
	}
	if (n == 0) {
		s->recv_closed = true;
		return true;
	}

	buf_put(bp, data, n);
	return true;
}

static bool
__wormhole_socket_send(struct wormhole_socket *s, struct buf *bp)
{
	unsigned int avail;
	int n;

	avail = buf_available(bp);
	n = send(s->fd, buf_head(bp), avail, 0);
	if (n < 0) {
		log_error("send error on socket: %m");
		return false;
	}

	__buf_advance_head(bp, n);
	return true;
}

/*
 * Connected stream socket
 */
static bool
__wormhole_connected_socket_poll(struct wormhole_socket *s, struct pollfd *pfd)
{
	pfd->events = 0;
	if (s->sendbuf) {
		pfd->events = POLLOUT;
	} else if (!s->recv_closed) {
		pfd->events = POLLIN;
	}
	return !!(pfd->events);
}

static bool
__wormhole_connected_socket_process(struct wormhole_socket *s, struct pollfd *pfd)
{
	if (pfd->revents & POLLHUP)
		s->recv_closed = true;
	if (pfd->revents & POLLIN) {
		if (!s->recvbuf)
			s->recvbuf = buf_alloc();

		if (!__wormhole_socket_recv(s, s->recvbuf))
			return false;

		/* See whether we have a complete message, and if so, process it */
		wormhole_message_consume(s, s->recvbuf);

		// buf_compact(s->recvbuf);
		if (buf_available(s->recvbuf) == 0)
			wormhole_drop_recvbuf(s);
	}

	if (pfd->revents & POLLOUT) {
		if (!s->sendbuf) {
			log_error("%s: POLLOUT signaled but no sendbuf", __func__);
			return false;
		}

		if (!__wormhole_socket_send(s, s->sendbuf))
			return false;

		if (buf_available(s->sendbuf) == 0)
			wormhole_drop_sendbuf(s);
	}

	return true;
}

static struct wormhole_socket_ops __wormhole_connected_socket_ops = {
	.poll		= __wormhole_connected_socket_poll,
	.process	= __wormhole_connected_socket_process,
};

static struct wormhole_socket *
wormhole_connected_socket_new(int fd, uid_t uid, gid_t gid)
{
	return wormhole_socket_new(&__wormhole_connected_socket_ops, fd, uid, gid);
}

#include <netinet/in.h>

bool
wormhole_message_consume(struct wormhole_socket *s, struct buf *bp)
{
	struct wormhole_message msg;
	void *payload;
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

static struct buf *
wormhole_build_status(const struct wormhole_request *req, unsigned int status)
{
	uint32_t status32;

	status32 = htonl(status);
	return wormhole_message_build(WORMHOLE_OPCODE_STATUS, &status32, sizeof(status32));
}

static bool
__wormhole_socket_send_with_fd(struct wormhole_socket *s, struct buf *bp, int fd)
{
	union {
		struct cmsghdr align;
		char buf[1024];
	} u;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = (void *) buf_head(bp);
	iov.iov_len = buf_available(bp);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (fd >= 0) {
		msg.msg_control = u.buf;
		msg.msg_controllen = sizeof(u.buf);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
		msg.msg_controllen = CMSG_SPACE(sizeof(int));
	}

	if (sendmsg(s->fd, &msg, 0) < 0)
		log_fatal("sendmsg: %m");

	return true;
}

void
wormhole_send_response_with_fd(const struct wormhole_request *req, int fd)
{
	struct wormhole_socket *s;
	struct buf *bp;

	s = wormhole_socket_find(req->socket_id);
	if (s == NULL)
		return;

	bp = wormhole_build_status(req, WORMHOLE_STATUS_OK);
	if (!__wormhole_socket_send_with_fd(s, bp, fd)) {
		/* Mark socket for closing */
	}

	buf_free(bp);
}

void
wormhole_send_status(struct wormhole_request *req, int status)
{
	struct wormhole_socket *s;

	s = wormhole_socket_find(req->socket_id);
	if (s == NULL)
		return;

	assert(s->sendbuf == NULL);
	s->sendbuf = wormhole_build_status(req, status);

	req->reply_sent = true;
}

void
wormhole_process_command(struct wormhole_request *req)
{
	const char *name;
	struct profile *profile;
	int nsfd;

	name = (const char *) (req->payload);
	trace("Processing request for command \"%s\" from uid %d", name, req->client_uid);

	profile = profile_find(name);
	if (profile == NULL) {
		log_error("no profile for %s", name);
		wormhole_send_status(req, WORMHOLE_STATUS_ERROR);
		return;
	}

	if (profile_setup(profile) < 0)
		log_fatal("Failed to set up environment for %s", profile->name);

	nsfd = open("/proc/self/ns/mnt", O_RDONLY);
	if (nsfd < 0)
		log_fatal("Cannot open /proc/self/ns/mnt: %m");

	wormhole_send_response_with_fd(req, nsfd);
	req->reply_sent = true;

	log_info("served request for a \"%s\" namespace", profile->name);
}

void
wormhole_process_request(struct wormhole_request *req)
{
	switch (req->opcode) {
	case WORMHOLE_OPCODE_COMMAND:
		wormhole_process_command(req);
		break;

	default:
		wormhole_send_status(req, WORMHOLE_STATUS_ERROR);
		break;
	}
}

void
wormhole_drop_recvbuf(struct wormhole_socket *s)
{
	if (s->recvbuf) {
		buf_free(s->recvbuf);
		s->recvbuf = NULL;
	}
}

void
wormhole_drop_sendbuf(struct wormhole_socket *s)
{
	if (s->sendbuf) {
		buf_free(s->sendbuf);
		s->sendbuf = NULL;
	}
}

void
wormhole_socket_free(struct wormhole_socket *s)
{
	wormhole_uninstall_socket(s);

	if (s->fd >= 0)
		close(s->fd);

	wormhole_drop_recvbuf(s);
	wormhole_drop_sendbuf(s);
	free(s);
}
