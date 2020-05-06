/*
 * forwarder.h
 *
 * Forward data between a pty/tty and another endpoint (which can be
 * a tty or a network connection).
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

#ifndef _FORWARDER_H
#define _FORWARDER_H

#include <sys/resource.h>
#include <netinet/in.h>

#include "endpoint.h"

struct io_window {
	unsigned int	rows, cols;
};

enum {
	SESSION_AUTH_INIT = 0,
	SESSION_AUTH_AUTHENTICATED,
	SESSION_AUTH_FAILED,
	SESSION_AUTH_3MONKEYS,
};

struct io_forwarder {
	struct endpoint *	socket;
	struct endpoint *	pty;

	struct console_slave *	process;

	struct io_session_auth {
		int		state;
		const char *	secret;
	} auth;
	struct io_window	window;
};

extern struct io_forwarder *	io_forwarder_setup(struct endpoint *socket, int tty_fd, struct console_slave *process);
extern struct event *		io_forwarder_window_event(unsigned int rows, unsigned int cols);

extern void			io_shell_service_install(struct endpoint *ep, struct io_session_auth *);
extern struct io_forwarder *	io_shell_service_create(struct endpoint *socket,
					struct console_slave *process,
					const char *auth_secret);

#endif /* _FORWARDER_H */
