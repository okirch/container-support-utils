/*
 * shell.h
 *
 * PTY and shell session handling
 */

#ifndef _SHELL_H
#define _SHELL_H

#include <sys/resource.h>

struct console_slave {
	int		master_fd;
	char *		tty_name;
	pid_t		child_pid;

	struct console_slave *next;
	int		exit_status;
	struct rusage	rusage;
};

extern struct console_slave *	start_shell(const char *cmd, char * const * argv, int procfd);

extern int			process_kill(struct console_slave *proc);
extern int			process_wait(struct console_slave *proc);
extern int			process_killsignal(const struct console_slave *proc);
extern int			process_exitstatus(const struct console_slave *proc);

#endif /* _SHELL_H */
