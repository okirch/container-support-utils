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

#include <fcntl.h>

struct io_forwarder {
	struct endpoint *	socket;
	struct endpoint *	pty;

	struct console_slave *	process;
};

struct shell_receiver {
	struct receiver		base;
	struct receiver *	next;
};

struct shell_sender {
	struct sender		base;
	struct queue		queue;
	struct sender *		next;
};

struct packet_header {
	uint32_t		magic;
	uint16_t		type;
	uint16_t		len;
};
#define PACKET_HEADER_MAGIC	0x50feeb1e
#define PACKET_MAX_DATA		1024

enum {
	PKT_TYPE_DATA,
	PKT_TYPE_WINDOW,
	PKT_TYPE_SIGNAL,

	__PKT_TYPE_MAX
};

/*
 * Passthru senders and receivers
 */
static struct receiver *
passthru_receiver(struct queue *q)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->recvq = q;
	return r;
}

static struct sender *
passthru_sender(struct queue **qp)
{
	struct sender *s;

	s = calloc(1, sizeof(*s));
	s->sendqp = qp;
	return s;
}

/*
 * Process one or more incoming packets
 */
static void
__io_shell_process_packet(const struct packet_header *hdr, struct queue *q, struct receiver *next)
{
	void *buffer;
	const void *p;

	buffer = alloca(hdr->len);
	p = queue_peek(q, buffer, hdr->len);

	if (hdr->type != PKT_TYPE_DATA) {
		fprintf(stderr, "Ignoring type %d packet\n", hdr->type);
		queue_advance_head(q, hdr->len);
		return;
	}

	queue_append(next->recvq, p, hdr->len);
	queue_advance_head(q, hdr->len);

	if (next->push_data)
		next->push_data(next->recvq, next);
}

/*
 * Process packets that sit in our queue.
 * Returns true IFF there are remaining packets that we could not
 * process (eg because the next receiver's queue was already full).
 */
static bool
io_shell_process_packets(struct queue *q, struct receiver *next)
{
	static unsigned int HDRLEN = sizeof(struct packet_header);
	struct packet_header hdrbuf;
	const struct packet_header *p;

	while (queue_available(q) >= HDRLEN) {
		p = queue_peek(q, &hdrbuf, HDRLEN);
		if (p != &hdrbuf)
			memcpy(&hdrbuf, p, HDRLEN);

		hdrbuf.magic = ntohl(hdrbuf.magic);
		hdrbuf.type = ntohs(hdrbuf.type);
		hdrbuf.len = ntohs(hdrbuf.len);

		//test_trace("packet 0x%x type %d len %d\n", hdrbuf.magic, hdrbuf.type, hdrbuf.len);
		if (hdrbuf.magic != PACKET_HEADER_MAGIC
		 || hdrbuf.type >= __PKT_TYPE_MAX) {
			fprintf(stderr, "Bad packet header\n");
			test_trace("packet magic 0x%x type %d len %d\n", hdrbuf.magic, hdrbuf.type, hdrbuf.len);
			exit(1);
			return false; /* error */
		}

		if (queue_available(q) < HDRLEN + hdrbuf.len)
			return false;

		if (queue_tailroom(next->recvq) < hdrbuf.len) {
			test_trace("not enough room in next layer, cannot queue incoming data packet\n");
			if (test_progress)
				write(2, "!", 1);
			return true;
		}

		/* Skip past header */
		queue_advance_head(q, HDRLEN);

		__io_shell_process_packet(&hdrbuf, q, next);
	}

	return false;
}

static bool
io_shell_build_data_packet(struct queue *q, struct queue *dataq, struct sender *next)
{
	static unsigned int HDRLEN = sizeof(struct packet_header);
	struct packet_header hdrbuf;
	unsigned int bytes, room;

	if (next && next->get_data)
		next->get_data(dataq, next);

	bytes = queue_available(dataq);
	if (bytes == 0)
		return false;

	room = queue_tailroom(q);
	if (room < HDRLEN + 1)
		return false;

	if (bytes > PACKET_MAX_DATA)
		bytes = PACKET_MAX_DATA;
	if (room < HDRLEN + bytes)
		bytes = room - HDRLEN;

	hdrbuf.magic = htonl(PACKET_HEADER_MAGIC);
	hdrbuf.type = PKT_TYPE_DATA;
	hdrbuf.len = htons(bytes);

	queue_append(q, &hdrbuf, HDRLEN);

	/* Transfer bytes from raw dataq to shell layer packet queue */
	queue_transfer(q, dataq, bytes);

	return true;
}

/*
 * We received data from the network.
 * See if we have one or more full packets, and process them.
 */
static bool
io_shell_service_push_data(struct queue *q, struct receiver *r)
{
	assert(q);

	assert(q == r->recvq);

	if (test_progress)
		write(2, "r", 1);
	return io_shell_process_packets(q, ((struct shell_receiver *) r)->next);
}

static struct receiver *
shell_service_receiver(struct receiver *next)
{
	struct shell_receiver *r;

	r = calloc(1, sizeof(*r));
	r->base.push_data = io_shell_service_push_data;
	r->base.recvq = &r->base.__queue;

	r->next = next;

	return &r->base;
}

static void
io_shell_service_get_data(struct queue *q, struct sender *base_sender)
{
	struct shell_sender *s = (struct shell_sender *) base_sender;
	struct queue *dataq = &s->queue;

	/* Build data packets while there's data - and room in the
	 * send queue */
	while (io_shell_build_data_packet(q, dataq, s->next)) {
		if (test_progress)
			write(2, "s", 1);
	}
}

static struct sender *
shell_service_sender(struct sender *next)
{
	struct shell_sender *s;

	s = calloc(1, sizeof(*s));
	s->base.get_data = io_shell_service_get_data;

	s->next = next;
	if (next && next->sendqp)
		*(next->sendqp) = &s->queue;

	return &s->base;
}

static void
io_forwarder_eof_callback(struct endpoint *ep, void *handle)
{
	struct io_forwarder *fwd = handle;

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
io_forwarder_close_callback(struct endpoint *ep, void *handle)
{
	struct io_forwarder *fwd = handle;

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

static struct io_forwarder *
io_forwarder_setup(struct endpoint *socket, struct console_slave *process)
{
	struct io_forwarder *fwd;

	fwd = calloc(1, sizeof(*fwd));
	fwd->socket = socket;
	fwd->process = process;

	fwd->pty = endpoint_new_pty(process->master_fd);

	endpoint_set_upper_layer(socket,
			passthru_sender(&fwd->pty->recvq),
			passthru_receiver(&fwd->pty->sendq));

	endpoint_register_eof_callback(socket, io_forwarder_eof_callback, fwd);
	endpoint_register_close_callback(socket, io_forwarder_close_callback, fwd);

	io_register_endpoint(socket);
	io_register_endpoint(fwd->pty);

	return fwd;
}

#if 0
static struct receiver *
shell_pty_receiver(struct io_forwarder *fwd)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->handle = fwd;
	r->close_callback = io_forwarder_close_callback;
	r->recvq = &fwd->socket->sendq;

	return r;
}

static struct sender *
shell_pty_sender(struct io_forwarder *fwd)
{
	struct sender *s;

	s = calloc(1, sizeof(*s));
	s->handle = fwd;

	return s;
}
#endif

struct io_forwarder *
io_shell_service_create(struct endpoint *socket, struct console_slave *process)
{
	struct io_forwarder *fwd;
	/* struct endpoint *pty; */

	fwd = io_forwarder_setup(socket, process);

	/* Install the shell protocol layer */
	endpoint_set_upper_layer(socket, 
		shell_service_sender(socket->sender),
		shell_service_receiver(socket->receiver));

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

static struct endpoint *
create_shell_client(int fd, struct test_client_appdata *appdata)
{
	struct endpoint *ep;

	ep = test_client_create(fd, "echo-client", appdata);

	/* Install the shell protocol layer */
	endpoint_set_upper_layer(ep, 
		shell_service_sender(ep->sender),
		shell_service_receiver(ep->receiver));

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
		do_cat_test(opt.timeout);
	if (opt.tests & (1 << TEST_HANGUP))
		do_hangup_test(2);
	printf("All is well.\n");
	return 0;
}

