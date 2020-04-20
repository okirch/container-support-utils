/*
 * Test shell/session code
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>
#include "shell.h"
#include "endpoint.h"
#include "testing.h"

struct endpoint *
create_console_service(int fd, struct console_slave *console)
{
	struct endpoint *sep, *pep;

	sep = endpoint_new_socket(fd);
	sep->debug_name = "shell-service";

	pep = endpoint_new_pty(console->master_fd);
	pep->debug_name = "cat";

	/* Incoming data from the socket goes to the pty master.
	 * Incoming data from the shell session goes to the socket. */
	sep->recvq = &pep->sendq;
	pep->recvq = &sep->sendq;

	sep->debug = test_tracing;
	pep->debug = test_tracing;

	io_register_endpoint(pep);
	io_register_endpoint(sep);
	return sep;
}

void
do_cat_test(unsigned int time, bool random_send, bool random_recv)
{
	char *argv[] = {
		"cat",
		NULL
	};
	struct console_slave *console;
	struct test_client_appdata appdata;
	int pair[2], status;

	printf("echo test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	test_client_appdata_init(&appdata, random_send, random_recv);

	console = start_shell("/usr/bin/cat", argv, -1);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		perror("socketpair");
		exit(66);
	}

	/* The first of the two sockets is the echo socket.
	 * Its recvq is also its sendq. */
	create_console_service(pair[0], console);

	/* The second socket is the client socket. */
	test_client_create(pair[1], "echo-client", &appdata);

	io_mainloop(time * 1000);

	assert(appdata.recv_pos <= appdata.send_pos);
	/* assert(appdata.send_pos - appdata.recv_pos <= QUEUE_SZ); */

	process_kill(console);
	if (process_wait(console) < 0) {
		fprintf(stderr, "failed to wait for child process\n");
		exit(99);
	}

	status = process_killsignal(console);
	if (status == 9) {
		/* We killed it */
	} else 
	if (status > 0) {
		fprintf(stderr, "cat command was killed by signal %d\n", status);
		exit(99);
	} else {
		status = process_exitstatus(console);
		if (status < 0) {
			fprintf(stderr, "process_exitstatus() returns %d\n", status);
			exit(99);
		}
		if (status != 0) {
			fprintf(stderr, "cat exited with status %d\n", status);
			exit(99);
		}
	}

	test_client_print_stats(&appdata);

	io_close_all();
}

enum {
	TEST_CAT,
};

int
main(int argc, char **argv)
{
	struct test_app appinfo = {
		.name = "test-shell",
		.test_cases = {
			{ "cat",	TEST_CAT	},
			{ NULL }
		},
	};
	struct test_util_options opt;

	test_parse_arguments(&appinfo, &opt, argc, argv);

	if (opt.tests & (1 << TEST_CAT))
		do_cat_test(opt.timeout, true, false);
	printf("All is well.\n");
	return 0;
}

