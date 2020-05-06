/*
 * shell.h
 *
 * PTY and shell session handling
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

#ifndef _SHELL_H
#define _SHELL_H

#include <sys/resource.h>
#include <netinet/in.h>

#include "endpoint.h"

struct container;

struct export_dir {
	const char *		host_path;
	const char *		container_path;
};

#define EXPORT_DIR_MAX		16
struct export_dir_array {
	struct export_dir	dirs[EXPORT_DIR_MAX];
	unsigned int		count;
};

struct export_state;

#define SHELL_MAX_ARGS	16
struct shell_settings {
	const char *		command;
	char *			argv[SHELL_MAX_ARGS];
	struct container *	container;

	struct export_dir_array	export;

	void			(*pre_nsenter_cb)(void);
	void			(*post_nsenter_cb)(void);
};


struct console_slave {
	int		master_fd;
	char *		tty_name;
	pid_t		child_pid;
	pid_t		child_pgrp;

	struct console_slave *next;
	int		exit_status;
	struct rusage	rusage;
};

extern struct console_slave *	start_shell(const struct shell_settings *settings, bool raw_mode);

extern void			process_hangup(struct console_slave *process);
extern int			process_kill(struct console_slave *proc);
extern int			process_wait(struct console_slave *proc);
extern int			process_killsignal(const struct console_slave *proc);
extern int			process_exitstatus(const struct console_slave *proc);
extern void			process_free(struct console_slave *proc);

extern int			tty_get_window_size(int fd, unsigned int *rows, unsigned int *cols);
extern int			tty_set_window_size(int fd, unsigned int rows, unsigned int cols);
extern int			tty_redirect_null(int tty_fd);

extern void			export_dir_array_append(struct export_dir_array *, const char *, const char *);
extern void			export_dir_array_destroy(struct export_dir_array *);

struct io_session_auth;

extern void			io_shell_service_install(struct endpoint *ep, struct io_session_auth *);
extern struct io_forwarder *	io_shell_service_create(struct endpoint *socket,
					struct console_slave *process,
					const char *auth_secret);

#define IO_SHELL_MAX_ARGS	16
struct io_session_settings {
	struct shell_settings	shell;
	const char *		auth_secret;
};

extern struct endpoint *	io_shell_service_create_listener(const struct io_session_settings *,
						struct sockaddr_in *listen_addr);

extern struct endpoint *	io_shell_client_create(const struct sockaddr_in *svc_addr, int tty_fd,
						const char *secret,
						bool debug);


#endif /* _SHELL_H */
