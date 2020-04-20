/*
 * Common test facilities
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include "buffer.h"
#include "testing.h"

const char	test_pattern[] = 
	"0123456789abcdefghijklmnopqrstuvwxyz"
	"=()[]{}/_-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	",;.:<|>#*~!$%&?"
	;
const unsigned int test_pattern_len = sizeof(test_pattern) - 1;

bool			test_tracing;
bool			test_progress;

static bool		done = false;

/*
 * Command line handling
 */
bool
parse_int_arg(const char *name, const char *arg, int *opt_valp)
{
	const char *s;
	long l;

	l = strtol(arg, (char **) &s, 0);
	if (*s) {
		fprintf(stderr, "Bad value \"%s\" for option %s\n", arg, name);
		return false;
	}

	*opt_valp = l;
	return true;
}

static void
test_usage(int exitval, const struct test_app *app)
{
	bool has_names = (app->test_cases[0].name != NULL);

	fprintf(stderr, "%s [-h] [-t timeout] [-s seed] [-d]%s\n", app->name,
			has_names? " [test-name ...]" : "");
	fprintf(stderr,
		"-h        show this message\n"
		"-t timeout\n"
		"          Test case duration in seconds\n"
		"-s seed\n"
		"          Initialize random number generator with seed\n"
		"-d        Show progress of test (some test cases only)\n"
		"-p        Enable debugging to trace the test progress\n");

	if (has_names) {
		const struct test_case_info *tc;
		unsigned int i;

		fprintf(stderr,
			"\n"
			"Valid test names:\n");
		for (i = 0, tc = app->test_cases; i < TEST_CASE_MAX; ++i, ++tc) {
			if (tc->name)
				fprintf(stderr, "  %s\n", tc->name);
		}
	}
	exit(exitval);
}

static int
test_case_id(const struct test_app *app, const char *test_name)
{
	const struct test_case_info *tc;
	unsigned int i;

	for (i = 0, tc = app->test_cases; i < TEST_CASE_MAX; ++i, ++tc) {
		if (tc->name && !strcasecmp(test_name, tc->name))
			return tc->id;
	}

	fprintf(stderr, "Unknown test case name \"%s\"\n", test_name);
	test_usage(1, app);

	return -1;
}

void
test_parse_arguments(const struct test_app *app, struct test_util_options *opts, int argc, char **argv)
{
	int c;

	memset(opts, 0, sizeof(*opts));
	opts->timeout = 5;
	opts->tests = ~0U;

	while ((c = getopt(argc, argv, "hdps:t:")) != EOF) {
		switch (c) {
		case 'd':
			test_tracing = true;
			break;

		case 'p':
			test_progress = true;
			break;

		case 's':
			if (!parse_int_arg("seed -s", optarg, &opts->seed))
				exit(1);

			/* For the log file */
			printf("Initializing RNG with seed %d\n", opts->seed);
			srandom(opts->seed);
			break;

		case 't':
			if (!parse_int_arg("timeout -t", optarg, &opts->timeout))
				exit(1);
			break;

		case 'h':
			test_usage(0, app);
		default:
			test_usage(1, app);
		}
	}

	if (test_tracing && test_progress) {
		fprintf(stderr, "You can use only one of -d (debug) and -p (progress)\n");
		test_usage(1, app);
	}

	if (optind < argc) {
		opts->tests = 0;

		while (optind < argc) {
			int id;

			id = test_case_id(app, argv[optind++]);
			opts->tests |= (1 << id);
		}
	}
}

static void
alarm_handler(int dummy)
{
	done = true;
}

bool *
test_set_alarm(unsigned int nsecs)
{
	done = false;
	signal(SIGALRM, alarm_handler);
	alarm(nsecs);

	return &done;
}

unsigned int
test_random_size(unsigned int sz)
{
	unsigned int rsz;

	if (sz == 0)
		return sz;
	rsz = ((unsigned int) random()) % sz;
	if (rsz == 0)
		rsz = sz;
	return rsz;
}

/*
 * Pattern send and receive functions
 */
static int
pattern_offset(unsigned char cc)
{
	const char *s;

	s = strchr(test_pattern, cc);
	if (s == NULL)
		return -1;

	return s - test_pattern;
}

void
test_generate_pattern(unsigned long *pos, void *buffer, unsigned int count)
{
	unsigned int offset = *pos % test_pattern_len;
	unsigned int copied = 0;

	while (copied < count) {
		unsigned int copy = test_pattern_len - offset;
		unsigned int left = count - copied;

		if (copy > left)
			copy = left;
		memcpy(buffer + copied, test_pattern + offset, copy);

		if ((offset += copy) >= test_pattern_len)
			offset = 0;

		copied += copy;
	}

	if (count)
		assert(((unsigned char *) buffer)[0] == test_pattern[*pos % test_pattern_len]);

	*pos += copied;
}

bool
test_verify_pattern(unsigned long *pos, const unsigned char *buffer, unsigned int count, unsigned long *fail_pos)
{
	unsigned int orig_pos = *pos;
	unsigned char *verify = alloca(count);

	test_generate_pattern(pos, verify, count);

	if (memcmp(buffer, verify, count) != 0) {
		unsigned int i;

		for (i = 0; i < count; ++i) {
			if (buffer[i] != verify[i])
				break;
		}

		fflush(stdout);
		fprintf(stderr, "pattern verification error at %u (0x%x)\n", orig_pos + i, orig_pos + i);
		fprintf(stderr, "Expected 0x%02x %c (offset %d), got 0x%02x %c (offset %d)\n",
					verify[i], verify[i], pattern_offset(verify[i]),
					buffer[i], buffer[i], pattern_offset(buffer[i]));

		if (i < 16) {
			fprintf(stderr, "Expect: ... %-32.32s ...\n", verify);
			fprintf(stderr, "Got:    ... %-32.32s ...\n", buffer);
			fprintf(stderr, "            %*s^\n", i, "");
		} else {
			fprintf(stderr, "Expect: ... %-32.32s ...\n", verify + i - 16);
			fprintf(stderr, "Got:    ... %-32.32s ...\n", buffer + i - 16);
			fprintf(stderr, "            %*s^\n", 16, "");
		}

		*fail_pos = orig_pos + i;
		return false;
	}

	return true;
}

void
test_client_queue_pattern(struct queue *q, unsigned long *pos, unsigned int count)
{
	void *buf = alloca(count);

	test_trace("%s(pos %lu (offset %lu), count %u)\n", __func__, *pos, *pos % test_pattern_len, count);

	memset(buf, '^', count);
	test_generate_pattern(pos, buf, count);

	queue_append(q, buf, count);
}

static void
__show_corrupt_buffer(struct queue *q, unsigned int stream_pos, unsigned int i)
{
	struct buf *bp;
	unsigned int k = 0;

	for (bp = q->head; bp; bp = bp->next, ++k) {
		unsigned int avail = buf_available(bp);
		const unsigned char *data;
		unsigned int offset;

		if (avail <= i) {
			stream_pos += avail;
			i -= avail;
			continue;
		}

		fprintf(stderr, "Buffer %u at %p, len %u, pos %u-%u\n", k, bp, avail, stream_pos, stream_pos + avail);
		data = bp->data + bp->head;
		for (offset = 0; offset < avail; offset += test_pattern_len) {
			unsigned int left = avail - offset;

			if (left > test_pattern_len)
				left = test_pattern_len;
			fprintf(stderr, "%*.*s\n", left, left, data + offset);
			offset += left;
		}

		break;
	}
}

void
test_client_recv_pattern(struct queue *q, unsigned long *pos, unsigned int count)
{
	unsigned long orig_pos = *pos;
	unsigned char *buf = alloca(count);
	const unsigned char *p;
	unsigned long fail_pos;

	test_trace("%s(pos %lu (offset %lu), count %u)\n", __func__, *pos, *pos % test_pattern_len, count);

	p = queue_peek(q, buf, count);
	if (!test_verify_pattern(pos, p, count, &fail_pos)) {
		__show_corrupt_buffer(q, orig_pos, fail_pos - orig_pos);

		fflush(stderr);
		assert(0);
	}
	queue_advance_head(q, count);
}

const char *
print_byte_count(unsigned long count)
{
	static struct scaling {
		unsigned long	factor;
		const char *	scale;
	} scales[] = {
		{	1024 * 1024 * 1024,	"G"	},
		{	1024 * 1024,		"M"	},
		{	1024,			"k"	},
		{	1,			""	},
	};

	static char buffer[4][32];
	static unsigned int bnum = 0;
	struct scaling *s;
	char *buf;

	buf = buffer[bnum];

	for (s = scales; ; ++s) {
		if (count >= s->factor) {
			snprintf(buf, sizeof(buffer[0]), "%.2f %sbytes",
					count * 1.0 / s->factor,
					s->scale);
			break;
		}
	}

	bnum = (bnum + 1) % 4;
	return buf;
}
