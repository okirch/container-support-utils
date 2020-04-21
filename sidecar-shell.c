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

static unsigned int	opt_port = 24666;

static int		open_tty(struct termios *saved_termios);
static void		restore_tty(int fd, const struct termios *saved_termios);
static void		install_sigwinch_handler(void);

int
main(void)
{
	struct termios terminal_settings;
	struct endpoint *ep;
	struct sockaddr_in sin;
	int tty_fd;

	if ((tty_fd = open_tty(&terminal_settings)) < 0)
		exit(1);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(opt_port);

	ep = io_shell_client_create(&sin, 0);

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
		fprintf(stderr, "Standard input does not seem to be a tty.\n");
		return -1;
	}

	if (tcgetattr(fd, &tc) < 0) {
		perror("tcgetattr");
		return -1;
	}

	if (saved_termios)
		*saved_termios = tc;

	cfmakeraw(&tc);
	if (tcsetattr(fd, TCSANOW, &tc) < 0) {
		perror("tcsetattr");
		return -1;
	}

	return fd;
}

static void
restore_tty(int fd, const struct termios *saved_termios)
{
	if (tcsetattr(fd, TCSANOW, saved_termios) < 0) {
		perror("tcsetattr");
	}
}

static void
sigwinch_handler(int sig)
{
}

static void
install_sigwinch_handler(void)
{
	struct sigaction act;

	act.sa_handler = sigwinch_handler;
	act.sa_flags = SA_RESTART;

	sigaction(SIGWINCH, &act, NULL);
}
