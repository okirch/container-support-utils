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
#include <signal.h>
#include <netinet/in.h>

#include "shell.h"
#include "forwarder.h"
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

	fwd = io_shell_service_create(socket, console, NULL);

	if (test_tracing) {
		endpoint_set_debug(socket, "shell-service", -1);
		endpoint_set_debug(fwd->pty, "cat", -1);
	}

	return socket;
}

static struct console_slave *
create_cat_service(int sockfd)
{
	struct shell_settings shell_settings = {
		.command	= "/usr/bin/cat",
		.argv		= { "cat", NULL },
		.container	= NULL,
	};
	struct console_slave *console;

	/* The true argument changes the slave tty to raw mode.
	 * In particular, this will turn echoing off, which would
	 * otherwise confuse our testing. */
	console = start_shell(&shell_settings, true);

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
	io_shell_service_install(ep, NULL);

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

	switch (status) {
	case SIGHUP:
	case SIGTERM:
	case SIGKILL:
		printf("Child process was killed by signal %d\n", status);
		return;

	default:
		if (status > 0) {
			fprintf(stderr, "cat command was killed by signal %d\n", status);
			exit(99);
		}
	}

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

static void
do_common_test_setup(struct test_client_appdata *appdata, struct console_slave **consolep, struct endpoint **clientp)
{
	struct console_slave *console;
	struct endpoint *client;
	int pair[2];

	test_client_appdata_init(appdata, false, false);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		log_error("socketpair: %m");
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

	const char *	command;
	const char *	expected;

	bool		shutdown_write;
	struct endpoint *hack_endpoint;

	unsigned int *	pending_count;
};

#define ECHO_CLIENT_COMMAND	"V=Yes; echo \"$V$V$V\"; exit 0;\n"
#define ECHO_CLIENT_EXPECT	"YesYesYes"
#define ECHO_CLIENT_COMMAND2	"V=Yes; echo \"$V$V$V\"\n"

static void
echo_client_get_data(struct endpoint *ep, struct queue *q, struct sender *s)
{
	struct echo_client_appdata *appdata = s->handle;

	if (appdata->sent)
		return;

	queue_append(q, appdata->command, strlen(appdata->command));

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
echo_client_push_data(struct endpoint *ep, struct queue *q, struct receiver *r)
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
	if (memmem(p, bytes, appdata->expected, strlen(appdata->expected)) != NULL) {
		appdata->yesman = true;

		if (appdata->shutdown_write && appdata->hack_endpoint) {
			endpoint_shutdown_write(appdata->hack_endpoint);
			appdata->hack_endpoint = NULL;
		}
	}

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
		log_error("connect: %m");
		return NULL;
	}

	ep = endpoint_new_socket(fd);
	if (test_tracing)
		endpoint_set_debug(ep, name, -1);

	memset(appdata, 0, sizeof(*appdata));
	endpoint_set_upper_layer(ep, echo_client_sender(appdata), echo_client_receiver(appdata));

	/* Install the shell protocol layer */
	io_shell_service_install(ep, NULL);

	endpoint_register_close_callback(ep, echo_client_close_callback, appdata);

	return ep;
}

static bool
echo_client_check_result(int client_id, const struct echo_client_appdata *appdata)
{
	if (!appdata->sent || !appdata->yesman || !appdata->socket_closed) {
		if (client_id >= 0)
			fprintf(stderr, "Client %u", client_id);
		else
			fprintf(stderr, "Client");
		fprintf(stderr, " sent=%s received=%s closed=%s\n",
				appdata->sent? "okay" : "NO",
				appdata->yesman? "okay" : "NO",
				appdata->socket_closed? "okay" : "NO");
		return false;
	}

	return true;
}

static struct endpoint *
do_listener_test_setup(struct sockaddr_in *listen_addr)
{
	struct endpoint *ep;

	memset(listen_addr, 0, sizeof(*listen_addr));

	ep = io_shell_service_create_listener(NULL, listen_addr);

	if (test_tracing)
		endpoint_set_debug(ep, "shell-svc-listener", -1);

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

		appdata[i].command = ECHO_CLIENT_COMMAND;
		appdata[i].expected = ECHO_CLIENT_EXPECT;
		appdata[i].pending_count = &pending_count;

		io_register_endpoint(ep);
	}

	if (io_mainloop(time * 1000) < 0) {
		fprintf(stderr, "io_mainloop returns error\n");
		exit(99);
	}

	for (i = 0; i < NCLIENTS; ++i) {
		if (!echo_client_check_result(i, &appdata[i]))
			failed = true;
	}

	if (failed) {
		fprintf(stderr, "FAILED\n");
		exit(99);
	}

	printf("echo client test succeeded\n");

	io_close_all();
}

void
do_ctrl_d_test(unsigned int time)
{
	struct echo_client_appdata appdata;
	struct sockaddr_in svc_addr;
	struct endpoint *ep;
	unsigned int pending_count = 0;

	printf("ctrl-d test\n");

	do_listener_test_setup(&svc_addr);

	ep = create_echo_client(&appdata, "echo-client", &svc_addr);

	appdata.command = ECHO_CLIENT_COMMAND2;
	appdata.expected = ECHO_CLIENT_EXPECT;
	appdata.shutdown_write = true;
	appdata.hack_endpoint = ep;
	appdata.pending_count = &pending_count;
	pending_count += 1;

	io_register_endpoint(ep);

	if (io_mainloop(time * 1000) < 0) {
		fprintf(stderr, "io_mainloop returns error\n");
		exit(99);
	}

	if (!echo_client_check_result(-1, &appdata)) {
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
	TEST_CTRLD,
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
			{ "ctrld",	TEST_CTRLD	},
			{ NULL }
		},
	};
	struct test_util_options opt;

	io_mainloop_detect_stalls();

	test_parse_arguments(&appinfo, &opt, argc, argv);

	if (opt.tests & (1 << TEST_CAT))
		do_cat_test(opt.timeout);
	if (opt.tests & (1 << TEST_HANGUP))
		do_hangup_test(2);
	if (opt.tests & (1 << TEST_DIE))
		do_die_test(2);
	if (opt.tests & (1 << TEST_LISTEN))
		do_listen_test(opt.timeout);
	if (opt.tests & (1 << TEST_CTRLD))
		do_ctrl_d_test(opt.timeout);
	printf("All is well.\n");
	return 0;
}
