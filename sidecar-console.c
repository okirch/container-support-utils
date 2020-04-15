/*
 * sidecar-console
 *
 * This utility helps you run a shell command in a container of your
 * choice, and talk to it through a socket connection.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <buffer.h>

struct connection {
	int		fd;
	struct queue	sendq;
};

struct console_slave {
	int		master_fd;
	char *		tty_name;
	pid_t		child_pid;
};

static void
fatal(const char *msg)
{
	fprintf(stderr, msg);
	exit(1);
}

struct console_slave *
start_shell(void)
{
	struct console_slave *ret;
	char *slave_name;
	pid_t pid;
	int mfd;

	ret = calloc(1, sizeof(*ret));

	if ((mfd = getpt()) < 0)
		fatal("getpt: %m");
	ret->master_fd = mfd;

	fcntl(mfd, F_SETFD, FD_CLOEXEC);

	if (grantpt(mfd) < 0)
		fatal("grantpt: %m");

	slave_name = ptsname(mfd);
	if (slave_name == NULL)
		fatal("ptsname: %m");
	ret->tty_name = strdup(slave_name);

	pid = fork();
	if (pid < 0)
		fatal("fork: %m");

	if (pid == 0) {
		int tty, fd;

		close(mfd);

		tty = open(slave_name, O_RDWR, 0);
		if (tty < 0) {
			perror(slave_name);
			exit(50);
		}

		for (fd = 0; fd < 3; ++fd) {
			if (tty != fd && dup2(tty, fd) < 0) {
				perror("unable to dup tty fd");
				exit(51);
			}
		}

		if (tty >= 3)
			close(tty);

		execl("/bin/bash", "/bin/bash", NULL);
		perror("unable to exec /bin/bash");
		exit(55);
	}

	ret->child_pid = pid;
	return ret;
}
