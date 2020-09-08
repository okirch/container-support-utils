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
#include <sys/stat.h>
#include <sys/poll.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
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
static int scm_rights_process(struct cmsghdr *cmsg, int *recv_fd);

extern int
wormhole_socket_recvmsg(int fd, void *buffer, size_t buf_sz, int *fdp)
{
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr align;
		char buf[1024];
	} u;
	int n, ndropped = 0;

	if (fdp)
		*fdp = -1;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = buffer;
	iov.iov_len = buf_sz;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	n = recvmsg(fd, &msg, 0);
	if (n < 0)
		return n;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
			ndropped += scm_rights_process(cmsg, fdp);
	}

	if (ndropped) {
		log_warning("Bad SCM_RIGHTS control message(s), dropped %d file descriptors", ndropped);
		return -1;
	}

	return n;
}

static int
scm_rights_process(struct cmsghdr *cmsg, int *recv_fd)
{
	int cmsg_data_len = cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr));
	int *fd_array = (int *) CMSG_DATA(cmsg);
	int fd_count = cmsg_data_len / sizeof(int);
	int k;
	int ndropped = 0;

	for (k = 0; k < fd_count; ++k) {
		int fd = fd_array[k];

		if (recv_fd == NULL || *recv_fd >= 0) {
			ndropped ++;
			close(fd);
		} else {
			*recv_fd = fd;
		}
	}

	return ndropped;
}

static bool
__wormhole_socket_recv(struct wormhole_socket *s, struct buf *bp, int *fdp)
{
	int n;

	n = wormhole_socket_recvmsg(s->fd, buf_tail(bp), buf_tailroom(bp), fdp);
	if (n < 0) {
		log_error("recv error on socket: %m");
		return false;
	}

	if (n == 0) {
		s->recv_closed = true;
		return true;
	}

	__buf_advance_tail(bp, n);
	return true;
}

int
wormhole_socket_sendmsg(int sock_fd, void *payload, unsigned int payload_len, int fd)
{
	union {
		struct cmsghdr align;
		char buf[1024];
	} u;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = payload;
	iov.iov_len = payload_len;

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

	return sendmsg(sock_fd, &msg, 0);
}

static bool
__wormhole_socket_send(struct wormhole_socket *s, struct buf *bp, int fd)
{
	int sent;

	sent = wormhole_socket_sendmsg(s->fd, (void *) buf_head(bp), buf_available(bp), fd);
	if (sent < 0) {
		log_error("sendmsg failed: %m");
		/* mark socket as dead */
		return false;
	}

	__buf_advance_head(bp, sent);
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

		if (!__wormhole_socket_recv(s, s->recvbuf, &s->recvfd))
			return false;

		/* See whether we have a complete message, and if so, process it */
		if (s->recvbuf && buf_available(s->recvbuf))
			s->app_ops->received(s, s->recvbuf, s->recvfd);

		/* We consumed the fd that came with this message. */
		wormhole_drop_recvfd(s);

		// buf_compact(s->recvbuf);
		if (buf_available(s->recvbuf) == 0)
			wormhole_drop_recvbuf(s);
	}

	if (pfd->revents & POLLOUT) {
		if (!s->sendbuf) {
			log_error("%s: POLLOUT signaled but no sendbuf", __func__);
			return false;
		}

		if (!__wormhole_socket_send(s, s->sendbuf, s->sendfd))
			return false;

		/* As long as we sent anything, we assume the sendfd went
		 * with it. */
		wormhole_drop_sendfd(s);

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

struct wormhole_socket *
wormhole_connect(const char *path, struct wormhole_app_ops *app_ops)
{
	struct wormhole_socket *s;
	struct sockaddr_un sun;
	int fd;

	if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
		log_error("unable to create PF_LOCAL stream socket: %m");
		return NULL;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, path);
	if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		log_error("cannot connect to %s: %m", path);
		close(fd);
		return NULL;
	}

	s = wormhole_connected_socket_new(fd, 0, 0);
	s->app_ops = app_ops;
	return s;
}


void
wormhole_socket_enqueue(struct wormhole_socket *s, struct buf *bp, int fd)
{
	assert(s->ops == &__wormhole_connected_socket_ops);
	assert(s->sendbuf == NULL);
	assert(s->sendfd < 0);

	s->sendbuf = bp;

	if (fd >= 0)
		s->sendfd = dup(fd);
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
wormhole_drop_recvfd(struct wormhole_socket *s)
{
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
}

void
wormhole_drop_sendfd(struct wormhole_socket *s)
{
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

	wormhole_drop_recvfd(s);
	wormhole_drop_sendfd(s);
	free(s);
}
