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
#include <assert.h>

#include "shell.h"
#include "tracing.h"

static bool		opt_debug = false;
static unsigned int	opt_port = 24666;
static const char *	opt_secret = NULL;

static struct io_shell_session_settings *my_session_settings(void);

static void
usage(const char *argv0, int exitval)
{
	fprintf(stderr,
		"Usage:\n"
		"%s [-d] [-L filename] [-p port] [-s secret]\n\n"
		"  -p port  specify an alternate port to connect to\n"
		"  -s secret\n"
		"           specify the authentication nonce to present to the server\n"
		"           Defaults to contents of SIDECAR_SECRET environment var.\n"
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

	while ((c = getopt(argc, argv, "dL:p:s:")) != EOF) {
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

		case 's':
			opt_secret = optarg;
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
	struct sockaddr_in sin;
	struct endpoint *ep;

	if (!parse_options(argc, argv))
		return 1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(opt_port);

	ep = io_shell_service_create_listener(my_session_settings(), &sin);
	if (opt_debug)
		endpoint_set_debug(ep, "shell-svc-listener", -1);
	io_register_endpoint(ep);

	io_mainloop(-1);

	fprintf(stderr, "io_mainloop() returned unexpectedly\n");
	return 1;
}

struct io_shell_session_settings *
my_session_settings(void)
{
	static struct io_shell_session_settings shell_settings = {
		.command	= "/bin/bash",
		.argv		= { "-sh", NULL },
		.procfd		= -1,
        };

	if (opt_secret == NULL)
		opt_secret = getenv("SIDECAR_SECRET");

	shell_settings.auth_secret = opt_secret;
	return &shell_settings;
}
