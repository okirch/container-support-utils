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

struct console_slave {
	int		master_fd;
	char *		tty_name;
	pid_t		child_pid;

	struct console_slave *next;
	int		exit_status;
	struct rusage	rusage;
};

extern struct console_slave *	start_shell(const char *cmd, char * const * argv, int procfd, bool raw_mode);

extern void			process_hangup(struct console_slave *process);
extern int			process_kill(struct console_slave *proc);
extern int			process_wait(struct console_slave *proc);
extern int			process_killsignal(const struct console_slave *proc);
extern int			process_exitstatus(const struct console_slave *proc);
extern void			process_free(struct console_slave *proc);

/*
 * Doesn't really belong here
 */
struct io_forwarder {
	struct endpoint *	socket;
	struct endpoint *	pty;

	struct console_slave *	process;
};

extern struct io_forwarder *	io_forwarder_setup(struct endpoint *socket, int tty_fd, struct console_slave *process);

extern void			io_shell_service_install(struct endpoint *ep);
extern struct io_forwarder *	io_shell_service_create(struct endpoint *socket, struct console_slave *process);

#define IO_SHELL_MAX_ARGS	16
struct io_shell_session_settings {
	const char *		command;
	char *			argv[IO_SHELL_MAX_ARGS];

	int			procfd;
};

extern struct endpoint *	io_shell_service_create_listener(const struct io_shell_session_settings *,
						struct sockaddr_in *listen_addr);

extern struct endpoint *	io_shell_client_create(const struct sockaddr_in *svc_addr, int tty_fd);


#endif /* _SHELL_H */
