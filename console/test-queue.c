/*
 * testing buffer and queue functionality
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

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <getopt.h>
#include "buffer.h"
#include "testing.h"

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
			test_client_queue_pattern(q, &send_pos, send_sz);
			nsends++;
		}

		recv_sz = queue_available(q);
		if (random_recv)
			recv_sz = test_random_size(recv_sz);

		test_client_recv_pattern(q, &recv_pos, recv_sz);
		nrecvs++;
	}

	/* If we do random-recv, there will be data left in the queue.
	 * Drain it. */
	if (q->size) {
		test_client_recv_pattern(q, &recv_pos, q->size);
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
