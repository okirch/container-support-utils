/*
 * Test shell/session code
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <netinet/in.h>
#include "shell.h"
#include "endpoint.h"
#include "testing.h"


struct endpoint *
create_console_service(int fd, struct console_slave *console)
{
	struct endpoint *socket;
	struct io_forwarder *fwd;

	socket = endpoint_new_socket(fd);
	socket->debug_name = "shell-service";
	socket->debug = test_tracing;

	fwd = io_shell_service_create(socket, console);
	fwd->pty->debug_name = "cat";
	fwd->pty->debug = test_tracing;

	return socket;
}

static struct console_slave *
create_cat_service(int sockfd)
{
	char *argv[] = {
		"cat",
		NULL
	};
	struct console_slave *console;

	/* The true argument changes the slave tty to raw mode.
	 * In particular, this will turn echoing off, which would
	 * otherwise confuse our testing. */
	console = start_shell("/usr/bin/cat", argv, -1, true);

	/* The first of the two sockets is the echo socket.
	 * Its recvq is also its sendq. */
	create_console_service(sockfd, console);

	return console;

}

static struct endpoint *
create_shell_client(int fd, struct test_client_appdata *appdata)
{
	struct endpoint *ep;

	ep = test_client_create(fd, "echo-client", appdata);

	/* Install the shell protocol layer */
	io_shell_service_install(ep);

	return ep;
}

static void
shell_terminate_and_exit(struct console_slave *console)
{
	int status;

	process_kill(console);
	if (process_wait(console) < 0) {
		fprintf(stderr, "failed to wait for child process\n");
		exit(99);
	}

	status = process_killsignal(console);
	if (status == 9 || status == 1) {
		printf("Child process was killed by signal %d\n", status);
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
		printf("Child process exited with status %d\n", status);
	}

}

static void
do_common_test_setup(struct test_client_appdata *appdata, struct console_slave **consolep, struct endpoint **clientp)
{
	struct console_slave *console;
	struct endpoint *client;
	int pair[2];

	test_client_appdata_init(appdata, false, false);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		perror("socketpair");
		exit(66);
	}

	/* The first of the two sockets is the server endpoint.
	 * It sends all incoming data to the shell/subcommand, and
	 * forwards all shell output to the client. */
	console = create_cat_service(pair[0]);

	/* The second socket is the client socket. */
	client = create_shell_client(pair[1], appdata);

	if (consolep)
		*consolep = console;

	if (clientp)
		*clientp = client;
}

static void
do_common_test_teardown(struct test_client_appdata *appdata, struct console_slave *console)
{
	assert(appdata->recv_pos <= appdata->send_pos);
	/* assert(appdata->send_pos - appdata->recv_pos <= QUEUE_SZ); */

	shell_terminate_and_exit(console);
	test_client_print_stats(appdata);

	io_close_all();
}

void
do_cat_test(unsigned int time)
{
	struct console_slave *console;
	struct test_client_appdata appdata;

	printf("echo test, duration %u\n", time);

	do_common_test_setup(&appdata, &console, NULL);

	io_mainloop(time * 1000);

	do_common_test_teardown(&appdata, console);
}

void
do_hangup_test(unsigned int time)
{
	struct console_slave *console;
	struct test_client_appdata appdata;
	struct endpoint *ep;

	printf("hangup test, duration %u\n", time);

	do_common_test_setup(&appdata, &console, &ep);

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

	if (!appdata.closed) {
		fprintf(stderr, "Client socket did not receive EOF from server\n");
		exit(99);
	}
	printf("Client socket received EOF from server\n");

	do_common_test_teardown(&appdata, console);
}

void
do_die_test(unsigned int time)
{
	struct console_slave *console;
	struct test_client_appdata appdata;
	struct endpoint *ep;

	printf("shell-hangup test, duration %u\n", time);

	do_common_test_setup(&appdata, &console, &ep);

	if (io_mainloop((time - 1) * 1000) < 0) {
		fprintf(stderr, "io_mainloop returns error\n");
		exit(99);
	}

	fprintf(stderr, "=== killing the shell process ===\n");
	process_kill(console);

	if (io_mainloop(1000) < 0) {
		fprintf(stderr, "io_mainloop #2 returns error\n");
		exit(99);
	}

	if (!appdata.closed) {
		fprintf(stderr, "Client socket did not receive EOF from server\n");
		exit(99);
	}
	printf("Client socket received EOF from server\n");

	do_common_test_teardown(&appdata, console);
}

enum {
	TEST_CAT,
	TEST_HANGUP,
	TEST_DIE,
};

int
main(int argc, char **argv)
{
	struct test_app appinfo = {
		.name = "test-shell",
		.test_cases = {
			{ "cat",	TEST_CAT	},
			{ "hangup",	TEST_HANGUP	},
			{ "die",	TEST_DIE	},
			{ NULL }
		},
	};
	struct test_util_options opt;

	test_parse_arguments(&appinfo, &opt, argc, argv);

	if (opt.tests & (1 << TEST_CAT))
		do_cat_test(opt.timeout);
	if (opt.tests & (1 << TEST_HANGUP))
		do_hangup_test(2);
	if (opt.tests & (1 << TEST_DIE))
		do_die_test(2);
	printf("All is well.\n");
	return 0;
}

