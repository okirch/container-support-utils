/*
 * Test socket code
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
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>

#include "endpoint.h"
#include "testing.h"


struct endpoint *
create_echo_service(int fd)
{
	struct endpoint *ep;

	ep = endpoint_new_socket(fd);
	ep->recvq = &ep->sendq;
	if (test_tracing)
		endpoint_set_debug(ep, "echo-svc", -1);

	io_register_endpoint(ep);
	return ep;
}

void
do_pipe_test(unsigned int time, bool random_send, bool random_recv)
{
	struct test_client_appdata appdata;
	struct endpoint *ep;
	int pair[2];
	
	printf("pipe test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	test_client_appdata_init(&appdata, random_send, random_recv);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		log_error("socketpair: %m");
		exit(66);
	}

	/* The first of the two sockets is the sender */
	ep = test_client_create(pair[0], "sender", &appdata);
	ep->receiver = NULL;

	/* The second socket is the receiver. */
	ep = test_client_create(pair[1], "receiver", &appdata);
	ep->sender = NULL;

	io_mainloop(time * 1000);

	assert(appdata.recv_pos <= appdata.send_pos);
	/* assert(appdata.send_pos - appdata.recv_pos <= QUEUE_SZ); */

	test_client_print_stats(&appdata);

	io_close_all();
}

void
do_echo_test(unsigned int time, bool random_send, bool random_recv)
{
	struct test_client_appdata appdata;
	int pair[2];
	
	printf("echo test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	test_client_appdata_init(&appdata, random_send, random_recv);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		log_error("socketpair: %m");
		exit(66);
	}

	/* The first of the two sockets is the echo socket.
	 * Its recvq is also its sendq. */
	create_echo_service(pair[0]);

	/* The second socket is the client socket. */
	test_client_create(pair[1], "echo-client", &appdata);

	io_mainloop(time * 1000);

	assert(appdata.recv_pos <= appdata.send_pos);
	/* assert(appdata.send_pos - appdata.recv_pos <= QUEUE_SZ); */

	test_client_print_stats(&appdata);

	io_close_all();
}

void
do_hangup_test(unsigned int time, bool random_send, bool random_recv)
{
	struct test_client_appdata appdata;
	struct endpoint *ep;
	int pair[2];
	
	printf("hangup test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	test_client_appdata_init(&appdata, random_send, random_recv);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		log_error("socketpair: %m");
		exit(66);
	}

	/* The first of the two sockets is the echo socket.
	 * Its recvq is also its sendq. */
	create_echo_service(pair[0]);

	/* The second socket is the client socket. */
	ep = test_client_create(pair[1], "echo-client", &appdata);

	if (io_mainloop((time - 1) * 1000) < 0) {
		fprintf(stderr, "io_mainloop returns error\n");
		exit(99);
	}

	fprintf(stderr, "=== shutting down client socket\n");
	endpoint_shutdown_write(ep);

	if (io_mainloop(1000) < 0) {
		fprintf(stderr, "io_mainloop #2 returns error\n");
		exit(99);
	}

	assert(appdata.recv_pos <= appdata.send_pos);
	/* assert(appdata.send_pos - appdata.recv_pos <= QUEUE_SZ); */

	if (!appdata.closed) {
		fprintf(stderr, "Client socket did not receive EOF from server\n");
		exit(99);
	}
	printf("Client socket received EOF from server\n");

	test_client_print_stats(&appdata);

	io_close_all();
}

enum {
	TEST_PIPE,
	TEST_ECHO,
	TEST_HANGUP,
};

int
main(int argc, char **argv)
{
	struct test_app appinfo = {
		.name = "test-shell",
		.test_cases = {
			{ "pipe",	TEST_PIPE	},
			{ "echo",	TEST_ECHO	},
			{ "hangup",	TEST_HANGUP	},
			{ NULL }
		},
	};
	struct test_util_options opt;

	test_parse_arguments(&appinfo, &opt, argc, argv);

	io_mainloop_detect_stalls();

	if (opt.tests & (1 << TEST_PIPE))
		do_pipe_test(opt.timeout, true, false);
	if (opt.tests & (1 << TEST_ECHO))
		do_echo_test(opt.timeout, true, false);
	if (opt.tests & (1 << TEST_HANGUP))
		do_hangup_test(2, true, false);
	printf("All is well.\n");
	return 0;
}

