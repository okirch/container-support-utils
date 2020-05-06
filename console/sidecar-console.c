/*
 * sidecar-console
 *
 * This utility helps you run a shell command in a container of your
 * choice, and talk to it through a socket connection.
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
#include <assert.h>

#include "shell.h"
#include "container.h"
#include "tracing.h"

static bool		opt_debug = false;
static unsigned int	opt_port = 24666;
static const char *	opt_secret = NULL;
static const char *	opt_container_id = 0;

static struct io_session_settings *my_session_settings(void);

static void
usage(const char *argv0, int exitval)
{
	fprintf(stderr,
		"Usage:\n"
		"%s [-d] [-L filename] [-p port] [-s secret] [-C pid-of-container]\n\n"
		"  -p port  specify an alternate port to connect to\n"
		"  -s secret\n"
		"           specify the authentication nonce to present to the server\n"
		"           Defaults to contents of SIDECAR_SECRET environment var.\n"
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

	while ((c = getopt(argc, argv, "dC:L:p:s:")) != EOF) {
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

struct io_session_settings *
my_session_settings(void)
{
	static struct io_session_settings session_settings = {
		.shell = {
			.command	= "/bin/bash",
			.argv		= { "-sh", NULL },
			.container	= NULL,
		},
        };

	if (opt_secret == NULL)
		opt_secret = getenv("SIDECAR_SECRET");
	session_settings.auth_secret = opt_secret;

	if (opt_container_id) {
		struct container *con;

		con = container_open(opt_container_id);
		if (con == NULL)
			log_fatal("abort.\n");

		if (!container_has_command(con, session_settings.shell.command))
			log_fatal("giving up.\n");

		session_settings.shell.container = con;
	}
	return &session_settings;
}
