/*
 * ns-exec
 *
 * This utility lets you run a shell command in a container of your
 * choice.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <termios.h>
#include <signal.h>
#include <errno.h>

#include "shell.h"
#include "container.h"
#include "tracing.h"

static bool		opt_debug = false;
static const char *	opt_container_id = 0;
static bool		window_size_changed;

static void
usage(const char *argv0, int exitval)
{
	fprintf(stderr,
		"Usage:\n"
		"%s [-d] [-L filename] [-C pid-of-container]\n\n"
		"  -C pid-of-container\n"
		"           Run the shell in the context of the specified container\n"
		"  -d       enable debugging\n"
		"  -L filename\n"
		"           write all messages to logfile\n"
		, argv0);
	exit(exitval);
}

static bool
parse_options(int argc, char **argv)
{
	const char *opt_logfile = NULL;
	int c;

	while ((c = getopt(argc, argv, "dC:L:")) != EOF) {
		switch (c) {
		case 'C':
			opt_container_id = optarg;
			break;

		case 'd':
			opt_debug = true;
			break;

		case 'L':
			opt_logfile = optarg;
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

	return fd;
}

static void
restore_tty(int fd, const struct termios *saved_termios)
{
	if (tcsetattr(fd, TCSANOW, saved_termios) < 0) {
		log_error("tcsetattr: %m");
	}
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
	char *argv[] = { "-sh", NULL };
	struct console_slave *console;
	struct container *container = NULL;
	int tty_fd;

	if (container_id != 0) {
		container = container_open(container_id);
		if (container == NULL || !container_has_command(container, "/bin/bash"))
			log_fatal("could not access container namespace dir\n");
	}

	if ((tty_fd = open_tty(&terminal_settings)) < 0)
		exit(1);
	install_sigwinch_handler();

	/* If the container does not have /dev/pts mounted, tty(1) will print
	 * "not a tty" when inspecting fd 1, and bash will not believe that it's
	 * a login shell...
	 * Workaround: unset HOSTNAME and HOST so that bash at least rebuilds
	 * PS1.
	 * Ultimate fix: mount /dev/pts in the shell's namespace.
	 */
	unsetenv("HOSTNAME");
	unsetenv("HOST");

	console = start_shell("/bin/bash", argv, container, false);
	if (console == NULL)
		log_fatal("Unable to start shell");

	doio_shell(tty_fd, console->master_fd);

	restore_tty(tty_fd, &terminal_settings);

	process_kill(console);
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

	run_shell(opt_container_id);
	return 0;
}
