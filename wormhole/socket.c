/*
 * wormhole - socket code
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

static struct wormhole_socket *	__wormhole_socket_accept(int fd, struct wormhole_socket *(*factory)(int, uid_t, gid_t));

struct wormhole_socket * wormhole_sockets = NULL;
unsigned int             wormhole_socket_count = 0;

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

struct wormhole_socket *
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
	struct wormhole_socket *s;

	s = calloc(1, sizeof(*s));
	s->ops = ops;
	s->id = __wormhole_socket_id++;
	s->fd = fd;
	s->uid = uid;
	s->gid = gid;

	s->sendfd = -1;
	s->recvfd = -1;

	return s;
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
		if (new_sock) {
			new_sock->app_ops = s->app_ops;
			if (new_sock->app_ops && new_sock->app_ops->new_socket)
				new_sock->app_ops->new_socket(new_sock);
		}
	}

	return true;
}

static struct wormhole_socket_ops __wormhole_passive_socket_ops = {
	.poll		= __wormhole_passive_socket_poll,
	.process	= __wormhole_passive_socket_process,
};

struct wormhole_socket *
wormhole_listen(const char *path, struct wormhole_app_ops *app_ops)
{
	struct wormhole_socket *s;
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

	s = wormhole_socket_new(&__wormhole_passive_socket_ops, fd, 0, 0);
	s->app_ops = app_ops;
	return s;
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
		s->app_ops->received(s, s->recvbuf);

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

struct wormhole_socket *
wormhole_connected_socket_new(int fd, uid_t uid, gid_t gid)
{
	return wormhole_socket_new(&__wormhole_connected_socket_ops, fd, uid, gid);
}

void
wormhole_drop_recvbuf(struct wormhole_socket *s)
{
	if (s->recvbuf) {
		buf_free(s->recvbuf);
		s->recvbuf = NULL;
	}
	if (s->recvfd >= 0) {
		close(s->recvfd);
		s->recvfd = -1;
	}
}

void
wormhole_drop_sendbuf(struct wormhole_socket *s)
{
	if (s->sendbuf) {
		buf_free(s->sendbuf);
		s->sendbuf = NULL;
	}
	if (s->sendfd >= 0) {
		close(s->sendfd);
		s->sendfd = -1;
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
