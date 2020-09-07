/*
 * wormhole - socket handling
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

#ifndef _WORMHOLE_SOCKET_H
#define _WORMHOLE_SOCKET_H

#include "buffer.h"

struct wormhole_socket {
	struct wormhole_socket **prevp;
	struct wormhole_socket *next;

	unsigned int	id;
	int		fd;

	const struct wormhole_socket_ops {
		bool	(*poll)(struct wormhole_socket *, struct pollfd *);
		bool	(*process)(struct wormhole_socket *, struct pollfd *);
	} *ops;

	struct wormhole_app_ops {
		void	(*new_socket)(struct wormhole_socket *);
		bool	(*received)(struct wormhole_socket *, struct buf *);
	} *app_ops;

	/* FIXME: add idle timeout */
	time_t		timeout;

	uid_t		uid;
	gid_t		gid;

	bool		recv_closed;
	bool		send_closed;

	struct buf *	recvbuf;
	int		recvfd;

	struct buf *	sendbuf;
};

#define WORMHOLE_SOCKET_MAX	1024

extern struct wormhole_socket * wormhole_sockets;
extern unsigned int		wormhole_socket_count;

extern struct wormhole_socket *	wormhole_listen(const char *path, struct wormhole_app_ops *app_ops);
extern struct wormhole_socket *	wormhole_accept_connection(int fd);
extern struct wormhole_socket *	wormhole_socket_find(unsigned int id);
extern void			wormhole_socket_free(struct wormhole_socket *conn);
extern struct wormhole_socket *	wormhole_connected_socket_new(int fd, uid_t uid, gid_t gid);
extern void			wormhole_drop_recvbuf(struct wormhole_socket *s);
extern void			wormhole_drop_sendbuf(struct wormhole_socket *s);

extern void			wormhole_install_socket(struct wormhole_socket *);
extern void			wormhole_uninstall_socket(struct wormhole_socket *);


#endif // _WORMHOLE_SOCKET_H
