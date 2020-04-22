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

struct payload_window_size {
	uint32_t		rows;
	uint32_t		cols;
};

struct packet_window_size {
	struct packet_header	hdr;
	struct payload_window_size payload;
};

static unsigned int HDRLEN = sizeof(struct packet_header);

#define PACKET_HEADER_MAGIC	0x50feeb1e
#define PACKET_MAX_DATA		1024

enum {
	PKT_TYPE_AUTH,
	PKT_TYPE_DATA,
	PKT_TYPE_WINDOW,
	PKT_TYPE_SIGNAL,

	__PKT_TYPE_MAX
};

/*
 * Process one or more incoming packets
 */
static void
__io_shell_process_data_packet(const struct packet_header *hdr, struct queue *q, struct receiver *next)
{
	/* Skip past header */
	queue_advance_head(q, HDRLEN);

	/* Transfer data to upper layer queue and push it */
	queue_transfer(next->recvq, q, hdr->len);
	if (next->push_data)
		next->push_data(next->recvq, next);
}

static void
__io_shell_process_window_packet(const struct packet_header *hdr, struct queue *q, struct receiver *next)
{
	struct payload_window_size window;

	/* Skip past header */
	queue_advance_head(q, HDRLEN);

	if (hdr->len != sizeof(struct payload_window_size)) {
		fprintf(stderr, "Bad packet size %u in window packet\n", hdr->len);
		queue_advance_head(q, hdr->len);
		return;
	}

	queue_get(q, &window, hdr->len);

	window.rows = ntohl(window.rows);
	window.cols = ntohl(window.cols);

	printf("window update <%u, %u>\n", window.rows, window.cols);
	if (next->push_event)
		next->push_event(io_forwarder_window_event(window.rows, window.cols), next);
}

/*
 * Process packets that sit in our queue.
 * Returns true IFF there are remaining packets that we could not
 * process (eg because the next receiver's queue was already full).
 */
static bool
io_shell_process_packets(struct queue *q, struct receiver *next)
{
	struct packet_header hdrbuf, *hdr;
	const struct packet_header *p;

	while (queue_available(q) >= HDRLEN) {
		p = queue_peek(q, &hdrbuf, HDRLEN);
		if (p != &hdrbuf)
			memcpy(&hdrbuf, p, HDRLEN);

		hdrbuf.magic = ntohl(hdrbuf.magic);
		hdrbuf.type = ntohs(hdrbuf.type);
		hdrbuf.len = ntohs(hdrbuf.len);
		hdr = &hdrbuf;

		//test_trace("packet 0x%x type %d len %d\n", hdrbuf.magic, hdrbuf.type, hdrbuf.len);
		if (hdr->magic != PACKET_HEADER_MAGIC
		 || hdr->type >= __PKT_TYPE_MAX) {
			log_error("bad packet header\n");
			log_error("packet magic 0x%x type %d len %d\n", hdr->magic, hdr->type, hdr->len);
			log_fatal("aborting.\n");
			return false; /* error */
		}

		if (queue_available(q) < HDRLEN + hdr->len)
			return false;

		switch (hdr->type) {
		case PKT_TYPE_WINDOW:
			__io_shell_process_window_packet(hdr, q, next);
			break;

		case PKT_TYPE_DATA:
			if (queue_tailroom(next->recvq) < hdr->len) {
				trace("not enough room in next layer, leave incoming packet in packet queue\n");
				return true;
			}
			__io_shell_process_data_packet(hdr, q, next);
			break;

		default:
			fprintf(stderr, "Ignoring type %d packet\n", hdr->type);
			queue_advance_head(q, HDRLEN + hdr->len);
			break;
		}
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
	hdrbuf.type = htons(PKT_TYPE_DATA);
	hdrbuf.len = htons(bytes);

	queue_append(q, &hdrbuf, HDRLEN);

	/* Transfer bytes from raw dataq to shell layer packet queue */
	queue_transfer(q, dataq, bytes);

	return true;
}

static bool
io_shell_build_auth_packet(struct queue *q, const char *secret)
{
	struct packet_header hdr;
	unsigned int room, secret_len;

	if (secret == NULL)
		return true;

	secret_len = strlen(secret);

	room = queue_tailroom(q);
	if (room < sizeof(hdr) + secret_len)
		return false;

	hdr.magic = htonl(PACKET_HEADER_MAGIC);
	hdr.type = htons(PKT_TYPE_AUTH);
	hdr.len = htons(secret_len);

	queue_append(q, &hdr, sizeof(hdr));
	queue_append(q, secret, secret_len);

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
	pkt.payload.rows = htonl(win->rows);
	pkt.payload.cols = htonl(win->cols);

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
	struct io_forwarder *fwd;
	struct console_slave *shell;

	if (settings == NULL)
		settings = &default_shell_settings;

	shell = start_shell(settings->command, settings->argv, settings->procfd, false);

	fwd = io_shell_service_create(new_socket, shell);

	if (new_socket->debug) {
		static unsigned int num_shell_sockets = 0;

		endpoint_set_debug(new_socket, "shell-sock", num_shell_sockets);
		endpoint_set_debug(fwd->pty, "shell-pty", num_shell_sockets);
		num_shell_sockets += 1;
	}
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
			log_error("setsockopt(SO_REUSEADDR): %m");
	} else {
		memset(&sin, 0, sizeof(sin));
	}

	if (bind(listen_fd, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		log_error("bind: %m");
		return NULL;
	}

	alen = sizeof(sin);
	if (getsockname(listen_fd, (struct sockaddr *) &sin, &alen) < 0) {
		log_error("bind: %m");
		return NULL;
	}

	if (listen(listen_fd, 128) < 0) {
		log_error("listen: %m");
		return NULL;
	}

	trace("=== Listen socket bound to port %d ===\n", ntohs(sin.sin_port));
	if (listen_addr)
		*listen_addr = sin;

	ep = endpoint_new_listener(listen_fd);
	endpoint_register_accept_callback(ep, __io_shell_service_accept, (void *) settings);

	return ep;
}

static void
__io_shell_client_send_auth_secret(struct endpoint *socket, const char *secret)
{
	if (!io_shell_build_auth_packet(&socket->sendq, secret)) {
		endpoint_error(socket, "could not push auth packet\n");
		log_fatal("Authentication failed\n");
	}
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
			endpoint_error(fwd->socket, "could not push IO window update\n");
			/* FIXME - see comment in io_shell_service_get_data() */
		}
	}
}

struct endpoint *
io_shell_client_create(const struct sockaddr_in *svc_addr, int tty_fd, const char *secret, bool debug)
{
	struct endpoint *sock;
	struct io_forwarder *fwd;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, 0);

	fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR);

	if (connect(fd, (struct sockaddr *) svc_addr, sizeof(*svc_addr)) < 0 && errno != EINPROGRESS) {
		log_error("connect: %m");
		return NULL;
	}

	sock = endpoint_new_socket(fd);

	/* Setup a forwarder between the tty and the socket we just
         * created. */
        fwd = io_forwarder_setup(sock, tty_fd, NULL);

	if (debug) {
		static unsigned int num_client_sockets = 0;

		endpoint_set_debug(sock, "shellclnt-sock", num_client_sockets);
		endpoint_set_debug(fwd->pty, "shellclnt-tty", num_client_sockets);
		num_client_sockets += 1;
	}

	/* Install the shell protocol layer */
	io_shell_service_install(sock);

	/* If we've been given an auth secret, send it as first packet */
	__io_shell_client_send_auth_secret(fwd->socket, secret);

	endpoint_register_config_change_callback(fwd->pty, __io_shell_client_sigwinch_callback, fwd);

	/* Send the initial window size update */
	__io_shell_client_sigwinch_callback(fwd->pty, fwd);

	/* endpoint_register_close_callback(sock, echo_client_close_callback, appdata); */

	return sock;
}
