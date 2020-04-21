/*
 * shell.c
 *
 * PTY and shell session handling
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <termios.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pty.h>

#include "shell.h"
#include "buffer.h"

static struct console_slave *	processes;

static const struct console_slave *
process_exited(pid_t pid, int status, const struct rusage *rusage)
{
	struct console_slave *p;

	for (p = processes; p; p = p->next) {
		if (p->child_pid == pid) {
			p->exit_status = status;
			p->rusage = *rusage;
			p->child_pid = 0;

			return p;
		}
	}

	/* Oops, spurious child exit */
	return NULL;
}

static void
reaper(int sig)
{
	struct rusage rusage;
	int status;
	pid_t pid;

	while ((pid = wait3(&status, WNOHANG, &rusage)) > 0)
		process_exited(pid, status, &rusage);
}

static void
install_sigchild_handler(void)
{
	static bool handler_installed = false;
	struct sigaction act;

	if (handler_installed)
		return;

	memset(&act, 0, sizeof(act));
	act.sa_handler = reaper;
	act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	sigaction(SIGCHLD, &act, NULL);

	handler_installed = true;
}

struct console_slave *
start_shell(const char *cmd, char * const * argv, int procfd, bool raw_mode)
{
	struct console_slave *ret;
	char slave_name[PATH_MAX];
	int mfd;
	pid_t pid;

	install_sigchild_handler();

	pid = forkpty(&mfd,
			slave_name, /* an API from the stone age */
			NULL, NULL);

	if (pid == 0) {
#ifndef TIOCTTY
		if (raw_mode) {
			struct termios tc;

			tcgetattr(0, &tc);
			cfmakeraw(&tc);
			tcsetattr(0, TCSANOW, &tc);
		}
#endif

		/* TBD: set name spaces from procfd */

		/* FIXME: close everything above fd 2 */

		execv(cmd, argv);
		fprintf(stderr, "unable to execute %s: %m\n", cmd);
		exit(55);
	}

#ifdef TIOCTTY
	if (raw_mode)
		ioctl(mfd, TIOCTTY, 1);
#endif

	ret = calloc(1, sizeof(*ret));
	ret->master_fd = mfd;
	ret->tty_name = strdup(slave_name);
	ret->child_pid = pid;

	ret->next = processes;
	processes = ret;

	return ret;
}

void
process_hangup(struct console_slave *process)
{
	int fd;

	if (process->master_fd < 0)
		return;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		perror("/dev/null");
		exit(66);
	}

	dup2(fd, process->master_fd);
}

static int
__process_wait(struct console_slave *proc)
{
	struct rusage rusage;
	int status, rv;

	if (proc->child_pid == 0)
		return 0;

	rv = wait4(proc->child_pid, &status, 0, &rusage);
	if (rv < 0) {
		fprintf(stderr, "%s(%u): %m\n", __func__, proc->child_pid);
		return -1;
	}

	process_exited(rv, status, &rusage);

	return 0;
}

static void
__block_sigchild(sigset_t *old_set)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, old_set);
}

static void
__unblock_sigchild(sigset_t *old_set)
{
	sigprocmask(SIG_SETMASK, old_set, NULL);
}

int
process_wait(struct console_slave *proc)
{
	sigset_t oset;
	int rv;

	__block_sigchild(&oset);

	rv = __process_wait(proc);

	__unblock_sigchild(&oset);
	return rv;
}

int
process_killsignal(const struct console_slave *proc)
{
	if (proc->child_pid > 0)
		return -1;
	if (!WIFSIGNALED(proc->exit_status))
		return -1;
	return WTERMSIG(proc->exit_status);
}

int
process_exitstatus(const struct console_slave *proc)
{
	if (proc->child_pid > 0)
		return -1;
	if (!WIFEXITED(proc->exit_status))
		return -1;
	return WEXITSTATUS(proc->exit_status);
}

static int
__process_kill(struct console_slave *proc)
{
	if (proc->child_pid > 0)
		return kill(proc->child_pid, SIGKILL);

	return 0;
}

int
process_kill(struct console_slave *proc)
{
	sigset_t oset;
	int rv;

	__block_sigchild(&oset);

	rv = __process_kill(proc);

	__unblock_sigchild(&oset);
	return rv;
}

void
process_free(struct console_slave *proc)
{
	struct console_slave **pos, *rovr;
	sigset_t oset;

	assert(proc->child_pid == 0);

	__block_sigchild(&oset);
	for (pos = &processes; (rovr = *pos) != NULL; pos = &rovr->next) {
		if (rovr == proc) {
			*pos = rovr->next;
			break;
		}
	}
	__unblock_sigchild(&oset);

	free(proc);
}
