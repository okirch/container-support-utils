/*
 * Test socket code
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>
#include "endpoint.h"
#include "testing.h"

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
	unsigned char *buf = alloca(count);
	const unsigned char *p;
	unsigned long fail_pos;

	test_trace("%s(pos %lu (offset %lu), count %u)\n", __func__, *pos, *pos % test_pattern_len, count);

	p = queue_peek(q, buf, count);
	if (!test_verify_pattern(pos, p, count, &fail_pos)) {
		/* __show_corrupt_buffer(q, orig_pos, fail_pos - orig_pos); */

		fflush(stderr);
		assert(0);
	}
	queue_advance_head(q, count);
}

struct client_appdata {
	bool		random_send;
	bool		random_recv;
	unsigned long	send_pos;
	unsigned long	recv_pos;

	unsigned int	nsends;
	unsigned int	nrecvs;

	bool		closed;

	struct queue	recvq;
};

static void
client_send_callback(struct queue *q, void *handle)
{
	struct client_appdata *appdata = handle;
	size_t send_sz;

	send_sz = queue_tailroom(q);
	if (appdata->random_send)
		send_sz = test_random_size(send_sz);

	if (send_sz) {
		do_queue_pattern(q, &appdata->send_pos, send_sz);
		appdata->nsends++;

		if (test_progress)
			write(1, ".", 1);
	}
}

static void
client_recv_callback(struct queue *q, void *handle)
{
	struct client_appdata *appdata = handle;
	size_t recv_sz;

	if (q == NULL) {
		/* EOF from client */
		return;
	}

	recv_sz = queue_available(q);

	test_trace("%s: %lu bytes of data available\n", __func__, recv_sz);
	if (appdata->random_recv)
		recv_sz = test_random_size(recv_sz);

	do_recv_pattern(q, &appdata->recv_pos, recv_sz);
	appdata->nrecvs++;

	if (test_progress)
		write(1, "+", 1);
}

static void
client_close_callback(struct endpoint *ep, void *handle)
{
	struct client_appdata *appdata = handle;

	test_trace("%s: socket about to be destroyed\n", __func__);
	appdata->closed = true;
}

void
client_print_stats(const struct client_appdata *appdata)
{
	printf("OK: sent %s bytes in %u chunks; received %s bytes in %u chunks. %lu bytes still in flight.\n",
			print_byte_count(appdata->send_pos), appdata->nsends,
			print_byte_count(appdata->recv_pos), appdata->nrecvs,
			appdata->send_pos - appdata->recv_pos);
}

struct endpoint *
create_echo_service(int fd)
{
	struct endpoint *ep;

	ep = endpoint_new_socket(fd);
	ep->debug_name = "echo-service";
	ep->recvq = &ep->sendq;

	ep->debug = test_tracing;

	io_register_endpoint(ep);
	return ep;
}

struct endpoint *
create_client(int fd, const char *name, struct client_appdata *appdata)
{
	struct endpoint *ep;

	ep = endpoint_new_socket(fd);
	ep->debug_name = name;
	ep->recvq = &appdata->recvq;

	ep->data_source_callback = client_send_callback;
	ep->data_sink_callback = client_recv_callback;
	ep->close_callback = client_close_callback;
	ep->app_handle = appdata;

	ep->debug = test_tracing;

	io_register_endpoint(ep);
	return ep;
}

static void
appdata_init(struct client_appdata *appdata, bool random_send, bool random_recv)
{
	memset(appdata, 0, sizeof(*appdata));
	appdata->random_send = random_send;
	appdata->random_recv = random_recv;
	queue_init(&appdata->recvq);
}

void
do_pipe_test(unsigned int time, bool random_send, bool random_recv)
{
	struct client_appdata appdata;
	struct endpoint *ep;
	int pair[2];
	
	printf("pipe test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	appdata_init(&appdata, random_send, random_recv);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		perror("socketpair");
		exit(66);
	}

	/* The first of the two sockets is the sender */
	ep = create_client(pair[0], "sender", &appdata);
	ep->data_sink_callback = NULL;

	/* The second socket is the receiver. */
	ep = create_client(pair[1], "receiver", &appdata);
	ep->data_source_callback = NULL;

	io_mainloop(time * 1000);

	assert(appdata.recv_pos <= appdata.send_pos);
	/* assert(appdata.send_pos - appdata.recv_pos <= QUEUE_SZ); */

	client_print_stats(&appdata);

	io_close_all();
}

void
do_echo_test(unsigned int time, bool random_send, bool random_recv)
{
	struct client_appdata appdata;
	int pair[2];
	
	printf("echo test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	appdata_init(&appdata, random_send, random_recv);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		perror("socketpair");
		exit(66);
	}

	/* The first of the two sockets is the echo socket.
	 * Its recvq is also its sendq. */
	create_echo_service(pair[0]);

	/* The second socket is the client socket. */
	create_client(pair[1], "echo-client", &appdata);

	io_mainloop(time * 1000);

	assert(appdata.recv_pos <= appdata.send_pos);
	/* assert(appdata.send_pos - appdata.recv_pos <= QUEUE_SZ); */

	client_print_stats(&appdata);

	io_close_all();
}

void
do_hangup_test(unsigned int time, bool random_send, bool random_recv)
{
	struct client_appdata appdata;
	struct endpoint *ep;
	int pair[2];
	
	printf("hangup test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	appdata_init(&appdata, random_send, random_recv);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		perror("socketpair");
		exit(66);
	}

	/* The first of the two sockets is the echo socket.
	 * Its recvq is also its sendq. */
	create_echo_service(pair[0]);

	/* The second socket is the client socket. */
	ep = create_client(pair[1], "echo-client", &appdata);

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

	client_print_stats(&appdata);

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

	if (opt.tests & (1 << TEST_PIPE))
		do_pipe_test(opt.timeout, true, false);
	if (opt.tests & (1 << TEST_ECHO))
		do_echo_test(opt.timeout, true, false);
	if (opt.tests & (1 << TEST_HANGUP))
		do_hangup_test(2, true, false);
	printf("All is well.\n");
	return 0;
}

