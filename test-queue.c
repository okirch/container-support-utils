
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include "buffer.h"
#include "testing.h"

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

static void
do_queue_pattern(struct queue *q, unsigned long *pos, unsigned int count)
{
	void *buf = alloca(count);

	test_trace("%s(pos %lu (offset %lu), count %u)\n", __func__, *pos, *pos % test_pattern_len, count);

	memset(buf, '^', count);
	test_generate_pattern(pos, buf, count);

	queue_append(q, buf, count);
}

static void
do_recv_pattern(struct queue *q, unsigned long *pos, unsigned int count)
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

void
do_test(unsigned int time, bool random_send, bool random_recv)
{
	struct queue __queue, *q = &__queue;
	unsigned int send_sz, recv_sz;
	unsigned long send_pos = 0, recv_pos = 0;
	unsigned int nsends = 0, nrecvs = 0;
	bool *done;

	printf("queue test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);
	queue_init(q);

	done = test_set_alarm(time);
	while (!*done) {
		send_sz = queue_tailroom(q);
		if (random_send)
			send_sz = test_random_size(send_sz);

		if (send_sz) {
			do_queue_pattern(q, &send_pos, send_sz);
			nsends++;
		}

		recv_sz = queue_available(q);
		if (random_recv)
			recv_sz = test_random_size(recv_sz);

		do_recv_pattern(q, &recv_pos, recv_sz);
		nrecvs++;
	}

	/* If we do random-recv, there will be data left in the queue.
	 * Drain it. */
	if (q->size) {
		do_recv_pattern(q, &recv_pos, q->size);
		nrecvs++;
	}

	assert(send_pos == recv_pos);

	printf("OK: sent %s bytes in %u chunks; received %s bytes in %u chunks\n",
			print_byte_count(send_pos), nsends,
			print_byte_count(recv_pos), nrecvs);
}

int
main(int argc, char **argv)
{
	struct test_app appinfo = {
		.name = "test-shell",
		.test_cases = {
			{ NULL }
		},
	};
	struct test_util_options opt;

	test_parse_arguments(&appinfo, &opt, argc, argv);

	do_test(opt.timeout, true, false);
	do_test(opt.timeout, true, true);
	do_test(opt.timeout, false, true);
	printf("All is well.\n");

	return 0;
}
