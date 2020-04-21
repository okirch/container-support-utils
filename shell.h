/*
 * shell.h
 *
 * PTY and shell session handling
 */

#ifndef _SHELL_H
#define _SHELL_H

#include <sys/resource.h>
#include "endpoint.h"

struct console_slave {
	int		master_fd;
	char *		tty_name;
	pid_t		child_pid;

	struct io_callback exit_callback;

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

/*
 * Doesn't really belong here
 */
struct io_forwarder {
	struct endpoint *	socket;
	struct endpoint *	pty;

	struct console_slave *	process;
};

extern struct io_forwarder *	io_forwarder_setup(struct endpoint *socket, struct console_slave *process);

extern void			io_shell_service_install(struct endpoint *ep);
extern struct io_forwarder *	io_shell_service_create(struct endpoint *socket, struct console_slave *process);

#endif /* _SHELL_H */
