/*
 * ns-exec
 *
 * This utility lets you run a shell command in a container of your
 * choice.
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>

#include "shell.h"
#include "container.h"
#include "tracing.h"
#include "savelog.h"

static bool		opt_debug = false;
static const char *	opt_container_id = NULL;
static const char *	opt_savelog_destination = NULL;
static bool		window_size_changed;

extern int		savelog_init(const char *destination);


static struct shell_settings shell_settings = {
	.command	= "/bin/bash",
	.argv		= { "-sh", NULL },
};

enum {
	OPT_SAVELOGS	= 256,
};

static struct option	long_options[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "debug",		no_argument,		NULL,	'd' },
	{ "container",		required_argument,	NULL,	'C' },
	{ "logfile",		required_argument,	NULL,	'L' },
	{ "shell",		required_argument,	NULL,	'S' },
	{ "export",		required_argument,	NULL,	'E' },
	{ "savelogs",		required_argument,	NULL,	OPT_SAVELOGS },
	{ NULL }
};

static void
usage(const char *argv0, int exitval)
{
	fprintf(stderr,
		"Usage:\n"
		"%s ... options\n"
		"  -C container-id\n"
		"  --container container-id\n"
		"           Run the shell in the context of the specified container.\n"
		"           The id can be a PID, or container's nodename.\n"
		"\n"
		"  -d, --debug\n"
		"           enable debugging\n"
		"\n"
		"  -L filename\n"
		"  -logfile filename\n"
		"           write all messages to logfile\n"
		"\n"
		"  -S shell-binary\n"
		"  --shell shell-binary\n"
		"           Specify a different shell binary.\n"
		"           The default shell is /bin/bash.\n"
		"\n"
		"  -E host-path:container-path\n"
		"  --export host-path:container-path\n"
		"           Mount the specified host-path inside the container at container-path.\n"
		"           The destination mount point must exist.\n"
		"           This option can be given several times in order to export more than one directory.\n"
		"\n"
		"  -h, --help\n"
		"           display this message.\n"
		"\n"
		"If no -C option is specified, %s will list all containers visible in the current context.\n"
		, argv0, argv0);
	exit(exitval);
}

static void
parse_export_option(char *arg)
{
	char *host_path, *container_path;
	char *s;

	host_path = arg;

	if (!(s = strchr(arg, ':')))
		log_fatal("export option requires <dir1>:<dir2> syntax\n");
	*s++ = '\0';

	container_path = s;

	if (container_path[0] != '/')
		log_fatal("export option: mount point must be an absolute path\n");

	export_dir_array_append(&shell_settings.export, host_path, container_path);
}


static bool
parse_options(int argc, char **argv)
{
	const char *opt_logfile = NULL;
	int c;

	while ((c = getopt_long(argc, argv, "hdC:L:E:S:", long_options, NULL)) != EOF) {
		switch (c) {
		case 'C':
			opt_container_id = optarg;
			break;

		case 'h':
			usage(argv[0], 0);

		case 'd':
			opt_debug = true;
			break;

		case 'L':
			opt_logfile = optarg;
			break;

		case 'E':
			parse_export_option(optarg);
			break;

		case 'S':
			shell_settings.command = optarg;
			break;

		case OPT_SAVELOGS:
			opt_savelog_destination = optarg;
			break;

		default:
			usage(argv[0], 1);
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Unexpected extra arguments on command line\n");
		return false;
	}

	if (opt_debug && !opt_logfile)
		opt_logfile = "ns-exec.log";

	if (opt_logfile)
		set_logfile(opt_logfile);
	if (opt_debug)
		tracing_enable();

	return true;
}

struct iostate {
	int		fd;
	const char *	desc;
	struct queue	sendq;
	struct queue *	recvq;
};

static void
iostate_init(struct iostate *s, int fd, const char *desc, struct queue *recvq)
{
	memset(s, 0, sizeof(*s));
	s->fd = fd;
	s->desc = desc;

	queue_init(&s->sendq);
	s->recvq = recvq;
}

static void
iostate_poll(struct iostate *s, struct pollfd *pfd)
{
	pfd->fd = s->fd;
	pfd->events = 0;

	/* If _our_ queue has data, check for POLLOUT */
	if (queue_available(&s->sendq))
		pfd->events |= POLLOUT;

	/* If the _other_ queue has room, check for POLLIN */
	if (queue_tailroom(s->recvq))
		pfd->events |= POLLIN;
}

static bool
iostate_poll_result(struct iostate *s, const struct pollfd *pfd)
{
	if (pfd->revents == POLLERR) {
		trace("POLLERR on %s\n", s->desc);
		return false;
	}

	if (pfd->revents == POLLHUP) {
		trace("POLLHUP on %s\n", s->desc);
		return false;
	}

	if (pfd->revents & POLLIN) {
		unsigned int count = queue_tailroom(s->recvq);
		void *buf;
		int n;

		buf = alloca(count);
		n = read(s->fd, buf, count);
		if (n == 0) {
			trace("EOF on %s\n", s->desc);
			return false;
		}

		queue_append(s->recvq, buf, n);
	}

	if (pfd->revents & POLLOUT) {
		unsigned int count = queue_available(&s->sendq);
		const void *p;
		void *buf;
		int n;

		if (count > 4096)
			count = 4096;

		buf = alloca(count);
		p = queue_peek(&s->sendq, buf, count);

		n = write(s->fd, p, count);
		if (n > 0)
			queue_advance_head(&s->sendq, n);
	}

	return true;
}

static int
doio_shell(int tty_fd, int pty_fd)
{
	struct iostate iostate[2];

	iostate_init(&iostate[0], tty_fd, "tty", &iostate[1].sendq);
	iostate_init(&iostate[1], pty_fd, "pty master", &iostate[0].sendq);

	while (true) {
		struct pollfd pfd[2];
		unsigned int i;

		if (window_size_changed) {
			unsigned int rows, cols;

			window_size_changed = false;

			trace("propagating window size\n");
			if (tty_get_window_size(tty_fd, &rows, &cols) < 0) {
				log_error("could not get window size for %s\n", iostate[0].desc);
				continue;
			}

			if (tty_set_window_size(pty_fd, rows, cols) < 0) {
				log_error("could not set window size for %s\n", iostate[1].desc);
				continue;
			}
		}


		for (i = 0; i < 2; ++i)
			iostate_poll(&iostate[i], &pfd[i]);

		if (poll(pfd, 2, -1) < 0) {
			if (errno != EINTR)
				log_fatal("error in poll()");
			continue;
		}

		for (i = 0; i < 2; ++i) {
			if (!iostate_poll_result(&iostate[i], &pfd[i]))
				return -1;
		}
	}

	return 0;
}

static int
open_tty(struct termios *saved_termios)
{
	int fd = 0;
	struct termios tc;

	trace("%s(%d)\n", __func__, fd);
	if (!isatty(fd)) {
		log_error("Standard input does not seem to be a tty.\n");
		return -1;
	}

	if (tcgetattr(fd, &tc) < 0) {
		log_error("tcgetattr: %m");
		return -1;
	}

	if (saved_termios)
		*saved_termios = tc;

	cfmakeraw(&tc);
	if (tcsetattr(fd, TCSANOW, &tc) < 0) {
		log_error("tcsetattr: %m");
		return -1;
	}

	logging_notify_raw_tty(true);
	return fd;
}

static void
restore_tty(int fd, const struct termios *saved_termios)
{
	if (tcsetattr(fd, TCSANOW, saved_termios) < 0) {
		log_error("tcsetattr: %m");
	}
	logging_notify_raw_tty(false);
}

static void
sigwinch_handler(int sig)
{
	/* Tell mainloop to invoke the config_changed callbacks on all
	 * sockets/ttys. */
	window_size_changed = true;
}

static void
install_sigwinch_handler(void)
{
	struct sigaction act;

	act.sa_handler = sigwinch_handler;
	act.sa_flags = SA_RESTART;

	sigaction(SIGWINCH, &act, NULL);

	window_size_changed = true;
}

static void
run_shell(const char *container_id)
{
	struct termios terminal_settings;
	struct console_slave *console;
	int tty_fd;

	if (container_id != 0) {
		struct container *container;

		container = container_open(container_id);
		if (container == NULL)
			log_fatal("could not access container namespace dir\n");
		if (!container_has_command(container, shell_settings.command)) {
			if (access(shell_settings.command, R_OK) >= 0)
				log_warning("container does not have %s - will try to substitute mine\n", shell_settings.command);
			else
				log_fatal("container does not have %s, and I cannot provide it\n", shell_settings.command);
		}
		shell_settings.container = container;
	}

	if ((tty_fd = open_tty(&terminal_settings)) < 0)
		exit(1);
	install_sigwinch_handler();

	/* The ptsname of a pty slave differs between contexts. Currently,
	 * we are using forkpty(), which makes the slave something like
	 * pts/42, then change to the container context. In the new context,
	 * the slave will show up as pts/0 - which confuses the hell out of
	 * ttyname().
	 * Workaround: unset HOSTNAME and HOST so that bash at least rebuilds
	 * PS1.
	 */
	unsetenv("HOSTNAME");
	unsetenv("HOST");

	console = start_shell(&shell_settings, false);
	if (console == NULL)
		log_fatal("Unable to start shell");

	if (shell_settings.container) {
		container_close(shell_settings.container);
		shell_settings.container = NULL;
	}

	doio_shell(tty_fd, console->master_fd);

	restore_tty(tty_fd, &terminal_settings);

	process_hangup(console);
}

static void
list_containers(void)
{
	static const unsigned int MAX_CONTAINERS = 128;
	struct container_info containers[MAX_CONTAINERS], *info;
	int i, count;

	if ((count = container_list(containers, MAX_CONTAINERS)) < 0)
		log_fatal("Failed to get list of containers.\n");

	if (count == 0) {
		printf("No containers found.\n");
		return;
	}

	printf("%5s %s\n", "PID", "HOSTNAME");
	for (i = 0, info = containers; i < count; ++i, ++info) {
		printf("%5u %s\n", info->pid, info->hostname? : "<not set>");
	}
}

int
main(int argc, char **argv)
{
	if (!parse_options(argc, argv))
		return 1;

	if (opt_container_id == 0) {
		list_containers();
		return 0;
	}

	if (opt_savelog_destination
	 && savelog_init(opt_savelog_destination) < 0)
		exit(1);


	run_shell(opt_container_id);
	return 0;
}
