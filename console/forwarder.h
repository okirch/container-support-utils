/*
 * forwarder.h
 *
 * Forward data between a pty/tty and another endpoint (which can be
 * a tty or a network connection).
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
