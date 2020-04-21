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
#include <netinet/in.h>
#include "shell.h"
#include "endpoint.h"


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
			/* test_trace("packet magic 0x%x type %d len %d\n", hdrbuf.magic, hdrbuf.type, hdrbuf.len); */
			exit(1);
			return false; /* error */
		}

		if (queue_available(q) < HDRLEN + hdrbuf.len)
			return false;

		if (queue_tailroom(next->recvq) < hdrbuf.len) {
			/* test_trace("not enough room in next layer, leave incoming packet in packet queue\n"); */
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

	fwd = io_forwarder_setup(socket, process);

	/* Install the shell protocol layer */
	io_shell_service_install(socket);

	return fwd;
}
