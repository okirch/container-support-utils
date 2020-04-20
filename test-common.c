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

const char	test_pattern[] = 
	"0123456789abcdefghijklmnopqrstuvwxyz"
	"=()[]{}/_-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	",;.:<|>#*~!$%&?"
	;
const unsigned int test_pattern_len = sizeof(test_pattern) - 1;

static bool		done = false;

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
