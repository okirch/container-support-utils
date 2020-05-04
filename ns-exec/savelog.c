/*
 * savelog
 *
 * Utility to save logfiles through ns-exec, for future inspection.
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#include "tracing.h"
#include "savelog.h"

static bool	opt_force = false;

static void
usage(const char *argv0, int exitval)
{
	fprintf(stderr,
		"Usage:\n"
		"%s [-dfh] <pathname>\n"
		, argv0);
	exit(exitval);
}

static int
parse_options(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "dhf")) != EOF) {
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
