/*
 * savelog
 *
 * Utility to save logfiles through ns-exec, for future inspection.
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
#include <getopt.h>

#include "tracing.h"
#include "savelog.h"

static bool	opt_force = false;

static struct option	long_options[] = {
	{ "force",		no_argument,		NULL,	'f' },
	{ "help",		no_argument,		NULL,	'h' },
	{ "debug",		no_argument,		NULL,	'd' },
	{ NULL }
};

static void
usage(const char *argv0, int exitval)
{
	fprintf(stderr,
		"Usage:\n"
		"%s [-dfh] <pathname>\n"
		"\n"
		"  -d, --debug\n"
		"           enable debugging\n"
		"\n"
		"  -f, --force\n"
		"           overwrite saved logfiles if they exist\n"
		"\n"
		"  -h, --help\n"
		"           display this message.\n"
		, argv0);
	exit(exitval);
}

static int
parse_options(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv, "dhf", long_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			tracing_enable();
			break;

		case 'f':
			opt_force = true;
			break;

		case 'h':
			usage(argv[0], 0);

		default:
			usage(argv[0], 1);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing filename arguments on command line\n");
		usage(argv[0], 1);
	}
	return optind;
}

int
main(int argc, char **argv)
{
	struct savelog *savelog;
	int nameidx;

	if ((nameidx = parse_options(argc, argv)) < 0)
		return 1;

	if (!(savelog = savelog_connect()))
		log_fatal("No savelog facility available in this session\n");

	savelog->overwrite = opt_force;

	while (nameidx < argc) {
		const char *fname = argv[nameidx++];

		if (savelog_send_file(savelog, fname) < 0) {
			log_error("Failed to save \"%s\"\n", fname);
			return 1;
		}

		printf("Stored %s\n", fname);
	}

	return 0;
}
