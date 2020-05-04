/*
 * savelog
 *
 * Utility to save logfiles through ns-exec, for future inspection.
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#include "tracing.h"

extern int		savelog_send_file(const char *path);

static void
usage(const char *argv0, int exitval)
{
	fprintf(stderr,
		"Usage:\n"
		"%s <pathname>\n"
		, argv0);
	exit(exitval);
}

static int
parse_options(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "dh")) != EOF) {
		switch (c) {
		case 'd':
			tracing_enable();
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
	int nameidx;

	if ((nameidx = parse_options(argc, argv)) < 0)
		return 1;

	while (nameidx < argc) {
		const char *fname = argv[nameidx++];

		if (savelog_send_file(fname) < 0) {
			log_error("Failed to save \"%s\"\n", fname);
			return 1;
		}

		printf("Stored %s\n", fname);
	}

	return 0;
}
