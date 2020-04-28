/*
 * container.c
 *
 * -
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

#include "container.h"
#include "tracing.h"




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
