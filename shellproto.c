/*
 * shellproto.c
 *
 * On the wire protocol for shell sessions
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include "shell.h"
#include "endpoint.h"
#include "tracing.h"


struct packet_header {
	uint32_t		magic;
	uint16_t		type;
	uint16_t		len;
};

struct packet_window_size {
	struct packet_header	hdr;
	uint32_t		rows;
	uint32_t		cols;
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
 * Process one or more incoming packets
 */
static void
__io_shell_process_packet(const struct packet_header *hdr, struct queue *q, struct receiver *next)
{
	void *buffer;
	const void *p;

	buffer = alloca(hdr->len);
	p = queue_peek(q, buffer, hdr->len);

	if (hdr->type == PKT_TYPE_WINDOW
	 && hdr->len == sizeof(struct packet_window_size) - sizeof(struct packet_header)) {
		struct window {
			uint32_t		rows;
			uint32_t		cols;
		} window;

		memcpy(&window, p, hdr->len);
		window.rows = ntohl(window.rows);
		window.cols = ntohl(window.cols);
		printf("window update <%u, %u>\n", window.rows, window.cols);
		queue_advance_head(q, hdr->len);
		return;
	}

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
			trace("packet magic 0x%x type %d len %d\n", hdrbuf.magic, hdrbuf.type, hdrbuf.len);
			exit(1);
			return false; /* error */
		}

		if (queue_available(q) < HDRLEN + hdrbuf.len)
			return false;

		if (queue_tailroom(next->recvq) < hdrbuf.len) {
			trace("not enough room in next layer, leave incoming packet in packet queue\n");
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

static bool
io_shell_build_window_packet(struct queue *q, const struct io_window *win)
{
	struct packet_window_size pkt;
	unsigned int room;

	/* printf("%s(<%u, %u>)\n", __func__, win->rows, win->cols); */
	room = queue_tailroom(q);
	if (room < sizeof(pkt))
		return false;

	pkt.hdr.magic = htonl(PACKET_HEADER_MAGIC);
	pkt.hdr.type = htons(PKT_TYPE_WINDOW);
	pkt.hdr.len = htons(sizeof(pkt) - sizeof(struct packet_header));
	pkt.rows = htonl(win->rows);
	pkt.cols = htonl(win->cols);

	queue_append(q, &pkt, sizeof(pkt));

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

	return io_shell_process_packets(q, r->next);
}

static struct receiver *
shell_service_receiver(struct receiver *next)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->push_data = io_shell_service_push_data;
	r->recvq = &r->__queue;
	r->next = next;

	return r;
}

static void
io_shell_service_get_data(struct queue *q, struct sender *s)
{
	struct queue *dataq = &s->__queue;

	/* FIXME: we may have tried to send a window update but failed
	 * because the sendq was full. We need to detect this case
	 * here and handle it.
	 */

	/* Build data packets while there's data - and room in the
	 * send queue */
	while (io_shell_build_data_packet(q, dataq, s->next))
		;
}

static struct sender *
shell_service_sender(struct sender *next)
{
	struct sender *s;

	s = calloc(1, sizeof(*s));
	s->get_data = io_shell_service_get_data;

	s->next = next;
	if (next && next->sendqp)
		*(next->sendqp) = &s->__queue;

	return s;
}

void
io_shell_service_install(struct endpoint *ep)
{
	endpoint_set_upper_layer(ep, 
		shell_service_sender(ep->sender),
		shell_service_receiver(ep->receiver));
}

struct io_forwarder *
io_shell_service_create(struct endpoint *socket, struct console_slave *process)
{
	struct io_forwarder *fwd;
	/* struct endpoint *pty; */

	fwd = io_forwarder_setup(socket, process->master_fd, process);
	fwd->pty->debug_name = "pty";
	fwd->pty->debug = socket->debug;

	/* Install the shell protocol layer */
	io_shell_service_install(socket);

	return fwd;
}

static void
__io_shell_service_accept(struct endpoint *new_socket, void *handle)
{
	static struct io_shell_session_settings default_shell_settings = {
		.command	= "/bin/bash",
		.argv		= { "-sh", NULL },
		.procfd		= -1,
	};
	const struct io_shell_session_settings *settings = handle;
	struct console_slave *shell;

	if (settings == NULL)
		settings = &default_shell_settings;

	shell = start_shell(settings->command, settings->argv, settings->procfd, false);

	io_shell_service_create(new_socket, shell);
	new_socket->debug_name = "shell-service";
}

struct endpoint *
io_shell_service_create_listener(const struct io_shell_session_settings *settings, struct sockaddr_in *listen_addr)
{
	struct endpoint *ep;
	struct sockaddr_in sin;
	socklen_t alen;
	int listen_fd;

	listen_fd = socket(PF_INET, SOCK_STREAM, 0);

	if (listen_addr && listen_addr->sin_family == AF_INET) {
		int one = 1;

		sin = *listen_addr;

		if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)))
			perror("setsockopt(SO_REUSEADDR)");
	} else {
		memset(&sin, 0, sizeof(sin));
	}

	if (bind(listen_fd, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		perror("bind");
		return NULL;
	}

	alen = sizeof(sin);
	if (getsockname(listen_fd, (struct sockaddr *) &sin, &alen) < 0) {
		perror("bind");
		return NULL;
	}

	if (listen(listen_fd, 128) < 0) {
		perror("listen");
		return NULL;
	}

	trace("=== Listen socket bound to port %d ===\n", ntohs(sin.sin_port));
	if (listen_addr)
		*listen_addr = sin;

	ep = endpoint_new_listener(listen_fd);
	endpoint_register_accept_callback(ep, __io_shell_service_accept, (void *) settings);
	ep->debug_name = "shell-listener";

	return ep;
}

static void
__io_shell_client_sigwinch_callback(struct endpoint *tty, void *handle)
{
	struct io_forwarder *fwd = handle;
	unsigned int rows, cols;

	if (tty_get_window_size(tty->fd, &rows, &cols) < 0)
		return;

	if (fwd->window.rows != rows
	 || fwd->window.cols != cols) {
		fwd->window.rows = rows;
		fwd->window.cols = cols;

		if (!io_shell_build_window_packet(&fwd->socket->sendq, &fwd->window)) {
			fprintf(stderr, "Could not push IO window update\n");
			/* FIXME - see comment in io_shell_service_get_data() */
		}
	}
}

struct endpoint *
io_shell_client_create(const struct sockaddr_in *svc_addr, int tty_fd)
{
	struct endpoint *sock;
	struct io_forwarder *fwd;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, 0);

	fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR);

	if (connect(fd, (struct sockaddr *) svc_addr, sizeof(*svc_addr)) < 0 && errno != EINPROGRESS) {
		perror("connect");
		return NULL;
	}

	sock = endpoint_new_socket(fd);
	sock->debug_name = "shell-client";

	/* Setup a forwarder between the tty and the socket we just
         * created. */
        fwd = io_forwarder_setup(sock, tty_fd, NULL);

	/* Install the shell protocol layer */
	io_shell_service_install(sock);

	endpoint_register_config_change_callback(fwd->pty, __io_shell_client_sigwinch_callback, fwd);

	/* Send the initial window size update */
	__io_shell_client_sigwinch_callback(fwd->pty, fwd);

	/* endpoint_register_close_callback(sock, echo_client_close_callback, appdata); */

	return sock;
}
