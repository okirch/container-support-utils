/*
 * shell.c
 *
 * PTY and shell session handling
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
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
#include <errno.h>
#include <sched.h>

#include "shell.h"
#include "buffer.h"
#include "tracing.h"

static struct console_slave *	processes;

static int			shell_set_namespaces_from(int procfd);

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

		/* set name spaces from procfd */
		if (procfd >= 0) {
			if (shell_set_namespaces_from(procfd) < 0)
				log_fatal("unable to set namespaces\n");
		}

		/* FIXME: close everything above fd 2 */

		execv(cmd, argv);
		log_fatal("unable to execute %s: %m\r\n", cmd);
	}

#ifdef TIOCTTY
	if (raw_mode)
		ioctl(mfd, TIOCTTY, 1);
#endif

	fcntl(mfd, F_SETFD, FD_CLOEXEC);

	ret = calloc(1, sizeof(*ret));
	ret->master_fd = mfd;
	ret->tty_name = strdup(slave_name);
	ret->child_pid = pid;
	ret->child_pgrp = pid;	 /* child_pid gets cleared when the child exits; child_pgrp does not */

	ret->next = processes;
	processes = ret;

	return ret;
}

int
shell_open_namespace_dir(pid_t container_pid, const char *command)
{
	char procpath[PATH_MAX], cmdpath[PATH_MAX];
	int fd;

	snprintf(procpath, sizeof(procpath), "/proc/%d/ns", container_pid);
	fd = open(procpath, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		log_error("%s: %m\n", procpath);
		return -1;
	}

	trace("successfully opened %s.\n", procpath);

	if (command) {
		snprintf(cmdpath, sizeof(cmdpath), "../root/%s", command);
		if (faccessat(fd, cmdpath, X_OK, AT_SYMLINK_NOFOLLOW) < 0) {
			log_error("unable to access %s in container %d: %m\n",
					command, container_pid);
			close(fd);
			return -1 ;
		}

		trace("okay: container seems to have %s in its filesystem namespace.\n", command);
	}

	fcntl(fd, F_SETFD, FD_CLOEXEC);

	return fd;
}

static bool
shell_is_namespace_member(int procfd, const char *name)
{
	char pathbuf[PATH_MAX];
	struct stat stb1, stb2;

	if (fstatat(procfd, name, &stb1, 0) < 0) {
		log_error("Cannot stat namespace file %s: %m\n", name);
		return false;
	}

	snprintf(pathbuf, sizeof(pathbuf), "/proc/self/ns/%s", name);
	if (stat(pathbuf, &stb2) < 0) {
		log_error("Cannot stat namespace file %s: %m\n", pathbuf);
		return false;
	}

	return stb1.st_dev == stb2.st_dev && stb1.st_ino == stb2.st_ino;
}

int
shell_set_namespaces_from(int procfd)
{
	struct nsname {
		const char *	name;
		int		id;
		bool		join;
	} nsnames[] = {
		{ "cgroup", CLONE_NEWCGROUP },
		{ "ipc",  CLONE_NEWIPC },
		{ "mnt", CLONE_NEWNS },
		{ "net", CLONE_NEWNET },
		{ "pid", CLONE_NEWPID },
		{ "user", CLONE_NEWUSER },
		{ "uts", CLONE_NEWUTS },
		{ NULL }
	};
	struct nsname *ns;

	trace("child process joining namespaces of conainer\n");
#if 0
	unshare(CLONE_NEWNS);
#endif

	for (ns = nsnames; ns->name; ++ns)
		ns->join = !shell_is_namespace_member(procfd, ns->name);

	for (ns = nsnames; ns->name; ++ns) {
		int fd;

		if (!ns->join) {
			trace("  %s: already a member\n", ns->name);
			continue;
		}

		if ((fd = openat(procfd, ns->name, O_RDONLY)) < 0) {
			log_error("Unable to open namespace %s: %m.\n", ns->name);
			return -1;
		}

		if (setns(fd, ns->id) < 0) {
			log_error("Unable to attach to namespace %s: %m.\n", ns->name);
			close(fd);
			return -1;
		}

		trace("  %s: OK\n", ns->name);
		close(fd);
	}

	chdir("/");
	return 0;
}

int
tty_get_window_size(int fd, unsigned int *rows, unsigned int *cols)
{
	struct winsize win;

	if (ioctl(fd, TIOCGWINSZ, &win) < 0) {
		log_error("ioctl(TIOCGWINSZ): %m");
		return -1;
	}

	*rows = win.ws_row;
	*cols = win.ws_col;
	return 0;
}

int
tty_set_window_size(int fd, unsigned int rows, unsigned int cols)
{
	struct winsize win;

	memset(&win, 0, sizeof(win));
	win.ws_row = rows;
	win.ws_col = cols;

	if (ioctl(fd, TIOCSWINSZ, &win) < 0) {
		log_error("ioctl(TIOCSWINSZ): %m");
		return -1;
	}

	return 0;
}

int
tty_redirect_null(int tty_fd)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		log_error("/dev/null: %m");
		return -1;
	}

	dup2(fd, tty_fd);
	close(fd);
	return 0;
}

void
process_hangup(struct console_slave *process)
{
	trace("%s(pgrp=%d, fd=%d)\n", __func__, process->child_pgrp, process->master_fd);
	/* FIXME: send a signal to the process group */
	if (process->child_pgrp) {
		if (kill(-process->child_pgrp, SIGTERM) < 0 && errno != ESRCH)
			log_error("%s: cannot send SIGTERM to pgrp %d: %m\n", __func__, process->child_pgrp);
	}

	if (process->master_fd >= 0
	 && tty_redirect_null(process->master_fd))
		log_fatal("%s: cannot redirect PTY master fd\n", __func__);
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
