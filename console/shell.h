/*
 * shell.h
 *
 * PTY and shell session handling
 */

#ifndef _SHELL_H
#define _SHELL_H

#include <sys/resource.h>
#include <netinet/in.h>

#include "endpoint.h"

struct container;

#define SHELL_MAX_ARGS	16
struct shell_settings {
	const char *		command;
	char *			argv[SHELL_MAX_ARGS];
	struct container *	container;
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
