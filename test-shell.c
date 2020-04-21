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

#include <errno.h>
#include <fcntl.h>


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

/*
 * Echo client.
 * This client will send a command to the remote shell service,
 * and check for a specific pattern in the output.
 */
struct echo_client_appdata {
	bool		sent;
	bool		yesman;
	bool		socket_closed;

	unsigned int *	pending_count;
};

static void
echo_client_get_data(struct queue *q, struct sender *s)
{
	static char command[] = {
		"V=Yes; echo \"$V$V$V\"; exit 0;\n"
	};
	struct echo_client_appdata *appdata = s->handle;

	if (appdata->sent)
		return;

	queue_append(q, command, strlen(command));
	appdata->sent = true;
}

struct sender *
echo_client_sender(void *handle)
{
	struct sender *s;

	s = calloc(1, sizeof(*s));
	s->handle = handle;
	s->get_data = echo_client_get_data;

	return s;
}

static bool
echo_client_push_data(struct queue *q, struct receiver *r)
{
	struct echo_client_appdata *appdata = r->handle;
	unsigned int bytes;
	void *buffer;
	const void *p;

	assert(q);
	assert(q == r->recvq);

	bytes = queue_available(q);
	buffer = alloca(bytes);
	p = queue_peek(q, buffer, bytes);

	test_trace("received \"%.*s\"\n", bytes, (const char *) p);
	if (memmem(p, bytes, "YesYesYes", 9) != NULL)
		appdata->yesman = true;

	return false;
}

struct receiver *
echo_client_receiver(void *handle)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->handle = handle;
	r->push_data = echo_client_push_data;
	r->recvq = &r->__queue;

	return r;
}

static void
echo_client_close_callback(struct endpoint *ep, void *handle)
{
	struct echo_client_appdata *appdata = handle;

	appdata->socket_closed = true;
	*(appdata->pending_count) -= 1;

	if (*(appdata->pending_count) == 0)
		io_mainloop_exit();
}

static struct endpoint *
create_echo_client(struct echo_client_appdata *appdata, const char *name, const struct sockaddr_in *svc_addr)
{
	struct endpoint *ep;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, 0);

	fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR);

	if (connect(fd, (struct sockaddr *) svc_addr, sizeof(*svc_addr)) < 0 && errno != EINPROGRESS) {
		perror("connect");
		return NULL;
	}

	ep = endpoint_new_socket(fd);
	ep->debug_name = strdup(name);
	ep->debug = test_tracing;

	memset(appdata, 0, sizeof(*appdata));
	endpoint_set_upper_layer(ep, echo_client_sender(appdata), echo_client_receiver(appdata));

	/* Install the shell protocol layer */
	io_shell_service_install(ep);

	endpoint_register_close_callback(ep, echo_client_close_callback, appdata);

	return ep;
}

static struct endpoint *
do_listener_test_setup(struct sockaddr_in *listen_addr)
{
	struct endpoint *ep;

	ep = io_shell_service_create_listener(listen_addr);
	ep->debug = test_tracing;
	io_register_endpoint(ep);

	return ep;
}

void
do_listen_test(unsigned int time)
{
	static const unsigned int NCLIENTS = 32;
	struct echo_client_appdata appdata[NCLIENTS];
	struct sockaddr_in svc_addr;
	unsigned int i, pending_count = 0;
	bool failed = false;

	printf("listener test\n");

	do_listener_test_setup(&svc_addr);

	for (i = 0; i < NCLIENTS; ++i) {
		char namebuf[64];
		struct endpoint *ep;

		pending_count += 1;

		snprintf(namebuf, sizeof(namebuf), "echo-client%d", i);
		ep = create_echo_client(&appdata[i], namebuf, &svc_addr);
		appdata[i].pending_count = &pending_count;

		io_register_endpoint(ep);
	}

	if (io_mainloop(time * 1000) < 0) {
		fprintf(stderr, "io_mainloop returns error\n");
		exit(99);
	}

	for (i = 0; i < NCLIENTS; ++i) {
		struct echo_client_appdata *app = &appdata[i];

		if (!app->sent || !app->yesman || !app->socket_closed) {
			fprintf(stderr, "Client %u sent=%s received=%s closed=%s\n", i,
					app->sent? "okay" : "NO",
					app->yesman? "okay" : "NO",
					app->socket_closed? "okay" : "NO");
			failed = true;
		}
	}

	if (failed) {
		fprintf(stderr, "FAILED\n");
		exit(99);
	}

	printf("echo client test succeeded\n");

	io_close_all();
}


enum {
	TEST_CAT,
	TEST_HANGUP,
	TEST_DIE,
	TEST_LISTEN,
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
			{ "listen",	TEST_LISTEN	},
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
	if (opt.tests & (1 << TEST_LISTEN))
		do_listen_test(opt.timeout);
	printf("All is well.\n");
	return 0;
}
