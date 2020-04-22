/*
 * sidecar-shell
 *
 * Utility that talks to a shell running in the sidecar-console
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>

#include "shell.h"
#include "tracing.h"

static unsigned int	opt_port = 24666;

static int		open_tty(struct termios *saved_termios);
static void		restore_tty(int fd, const struct termios *saved_termios);
static void		install_sigwinch_handler(void);

static void
usage(const char *argv0, int exitval)
{
	fprintf(stderr,
		"Usage:\n"
		"%s [-d] [-L filename] [-p port]\n\n"
		"  -p port  specify an alternate port to connect to\n"
		"  -d       enable debugging\n"
		"  -L filename\n"
		"           write all messages to logfile\n"
		, argv0);
	exit(exitval);
}

static bool
parse_options(int argc, char **argv)
{
	bool opt_debug = false;
	const char *opt_logfile = NULL;
	int c;

	while ((c = getopt(argc, argv, "dL:p:")) != EOF) {
		switch (c) {
		case 'd':
			opt_debug = true;
			break;

		case 'L':
			opt_logfile = optarg;
			break;

		case 'p':
			opt_port = strtoul(optarg, NULL, 0);
			break;

		default:
			usage(argv[0], 1);
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Unexpected extra arguments on command line\n");
		return false;
	}

	if (opt_logfile)
		set_logfile(opt_logfile);
	if (opt_debug)
		tracing_enable();

	return true;
}

int
main(int argc, char **argv)
{
	struct termios terminal_settings;
	struct endpoint *ep;
	struct sockaddr_in sin;
	int tty_fd;

	if (!parse_options(argc, argv))
		return 1;

	if ((tty_fd = open_tty(&terminal_settings)) < 0)
		exit(1);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(opt_port);

	ep = io_shell_client_create(&sin, 0);
	if (ep == NULL) {
		log_error("Unable to create shell client\n");
		return 1;
	}

	install_sigwinch_handler();

	io_mainloop(-1);

	restore_tty(tty_fd, &terminal_settings);

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
	io_mainloop_config_changed();
}

static void
install_sigwinch_handler(void)
{
	struct sigaction act;

	act.sa_handler = sigwinch_handler;
	act.sa_flags = SA_RESTART;

	sigaction(SIGWINCH, &act, NULL);
}
