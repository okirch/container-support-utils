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

#include <fcntl.h>

struct io_forwarder {
	struct endpoint *	socket;
	struct endpoint *	pty;

	struct console_slave *	process;
};

static void
io_shell_service_recv_callback(struct queue *q, void *handle)
{
	struct io_forwarder *fwd = handle;

	if (q != NULL) {
		/* Nothing for us to do. Data has already been queued
		 * up for the pty master, and the mainloop socket takes
		 * care of writing that out.
		 */
		return;
	}

	/* We received an EOF from the client.
	 * We should now switch the pty master socket to sending a
	 * continuous stream of ctrl-ds... if we had termios enabled,
	 * which we don't, for now.
	 * Instead, just kill the child process.
	 */
	test_trace("=== Killing shell command\n");
	/* process_kill(fwd->process); */

	queue_destroy(&fwd->pty->sendq);
	process_hangup(fwd->process);

	/* Write out any data we have queued, then close the socket's
	 * sending half. */
	if (fwd->socket)
		endpoint_shutdown_write(fwd->socket);
}

static void
io_shell_service_push_data(struct queue *q, struct receiver *r)
{
	io_shell_service_recv_callback(q, r->handle);
}

static void
io_shell_service_close_callback(struct endpoint *ep, struct receiver *r)
{
	struct io_forwarder *fwd = r->handle;

	if (fwd->socket == ep)
		fwd->socket = NULL;
	else if (fwd->pty == ep)
		fwd->pty = NULL;

	if (fwd->pty)
		fwd->pty->recvq = NULL;
	if (fwd->socket)
		fwd->socket->recvq = NULL;

	if (fwd->pty == NULL && fwd->socket == NULL)
		free(fwd);
}

static struct receiver *
shell_service_receiver(struct io_forwarder *fwd)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->handle = fwd;
	r->push_data = io_shell_service_push_data;
	r->close_callback = io_shell_service_close_callback;

	return r;
}

static struct receiver *
shell_pty_receiver(struct io_forwarder *fwd)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->handle = fwd;
	r->close_callback = io_shell_service_close_callback;

	return r;
}

struct io_forwarder *
io_shell_service_create(struct endpoint *socket, struct console_slave *process)
{
	struct io_forwarder *fwd;
	struct endpoint *pty;

	fwd = calloc(1, sizeof(*fwd));
	fwd->socket = socket;
	fwd->process = process;

	socket->receiver = shell_service_receiver(fwd);

	pty = endpoint_new_pty(process->master_fd);
	pty->receiver = shell_pty_receiver(fwd);

	fwd->pty = pty;

	/* Incoming data from the socket goes to the pty master.
	 * Incoming data from the shell session goes to the socket. */
	socket->recvq = &pty->sendq;
	pty->recvq = &socket->sendq;

	io_register_endpoint(socket);
	io_register_endpoint(pty);

	return fwd;
}

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

	console = start_shell("/usr/bin/cat", argv, -1);

	/* The first of the two sockets is the echo socket.
	 * Its recvq is also its sendq. */
	create_console_service(sockfd, console);

	return console;

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

void
do_cat_test(unsigned int time, bool random_send, bool random_recv)
{
	struct console_slave *console;
	struct test_client_appdata appdata;
	int pair[2];

	printf("echo test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	test_client_appdata_init(&appdata, random_send, random_recv);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		perror("socketpair");
		exit(66);
	}

	/* The first of the two sockets is the server endpoint.
	 * It sends all incoming data to the shell/subcommand, and
	 * forwards all shell output to the client. */
	console = create_cat_service(pair[0]);

	/* The second socket is the client socket. */
	test_client_create(pair[1], "echo-client", &appdata);

	io_mainloop(time * 1000);

	assert(appdata.recv_pos <= appdata.send_pos);
	/* assert(appdata.send_pos - appdata.recv_pos <= QUEUE_SZ); */

	shell_terminate_and_exit(console);
	test_client_print_stats(&appdata);

	io_close_all();
}

void
do_hangup_test(unsigned int time, bool random_send, bool random_recv)
{
	struct console_slave *console;
	struct test_client_appdata appdata;
	struct endpoint *ep;
	int pair[2];

	printf("hangup test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	test_client_appdata_init(&appdata, random_send, random_recv);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		perror("socketpair");
		exit(66);
	}

	/* The first of the two sockets is the server endpoint.
	 * It sends all incoming data to the shell/subcommand, and
	 * forwards all shell output to the client. */
	console = create_cat_service(pair[0]);

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

	shell_terminate_and_exit(console);
	test_client_print_stats(&appdata);

	io_close_all();
}

enum {
	TEST_CAT,
	TEST_HANGUP,
};

int
main(int argc, char **argv)
{
	struct test_app appinfo = {
		.name = "test-shell",
		.test_cases = {
			{ "cat",	TEST_CAT	},
			{ "hangup",	TEST_HANGUP	},
			{ NULL }
		},
	};
	struct test_util_options opt;

	test_parse_arguments(&appinfo, &opt, argc, argv);

	if (opt.tests & (1 << TEST_CAT))
		do_cat_test(opt.timeout, true, false);
	if (opt.tests & (1 << TEST_HANGUP))
		do_hangup_test(2, true, false);
	printf("All is well.\n");
	return 0;
}

