/*
 * forwarder.c
 *
 * Copy data between pty and socket, with an intermediate layer
 * possibly taking care of packetization, signal delivery etc.
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
#include "tracing.h"

#include <fcntl.h>

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

static void
io_forwarder_eof_callback(struct endpoint *ep, void *handle)
{
	struct io_forwarder *fwd = handle;

	trace("%s(%s)\n", __func__, endpoint_debug_name(ep));
	if (ep == fwd->socket) {
		/* We received an EOF from the client.
		 * We should now switch the pty master socket to sending a
		 * continuous stream of ctrl-ds... if we had termios enabled,
		 * which we don't, for now.
		 * Instead, just kill the child process.
		 */
		trace("=== Hanging up PTY master ===\n");
		if (fwd->pty)
			queue_destroy(&fwd->pty->sendq);
		if (fwd->process)
			process_hangup(fwd->process);
	} else
	if (ep == fwd->pty) {
		/* We received a hangup from the pty slave.
		 */
		trace("=== Hanging up PTY master ===\n");
		if (fwd->pty) {
			queue_destroy(&fwd->pty->sendq);
			endpoint_shutdown_write(fwd->pty);
		}
		if (fwd->process)
			process_hangup(fwd->process);

		/* Pretend that the socket has received an
		 * EOF from the peer. This is to make sure
		 * we no longer queue any data to the pty
		 * (which may soon cease to exist). */
		if (fwd->socket)
			endpoint_eof_from_peer(fwd->socket);
	}

	/* We should now write out any pending data to the socket, then
	 * close the socket's sending half */
	if (fwd->socket)
		endpoint_shutdown_write(fwd->socket);
}

static void
io_forwarder_close_callback(struct endpoint *ep, void *handle)
{
	struct io_forwarder *fwd = handle;

	trace("%s(%s)\n", __func__, endpoint_debug_name(ep));
	if (fwd->socket == ep) {
		trace("=== Hangup from client ===\n");
		fwd->socket = NULL;
	} else if (fwd->pty == ep) {
		trace("=== Hangup on PTY ===\n");
		fwd->pty = NULL;
	}

	if (fwd->pty)
		fwd->pty->recvq = NULL;
	if (fwd->socket)
		fwd->socket->recvq = NULL;

	if (fwd->pty == NULL && fwd->socket == NULL)
		free(fwd);
}

struct io_forwarder *
io_forwarder_setup(struct endpoint *socket, struct console_slave *process)
{
	struct io_forwarder *fwd;

	fwd = calloc(1, sizeof(*fwd));
	fwd->socket = socket;
	fwd->process = process;

	fwd->pty = endpoint_new_pty(process->master_fd);
	endpoint_register_eof_callback(fwd->pty, io_forwarder_eof_callback, fwd);
	endpoint_register_close_callback(fwd->pty, io_forwarder_close_callback, fwd);

	endpoint_set_upper_layer(socket,
			passthru_sender(&fwd->pty->recvq),
			passthru_receiver(&fwd->pty->sendq));

	endpoint_register_eof_callback(socket, io_forwarder_eof_callback, fwd);
	endpoint_register_close_callback(socket, io_forwarder_close_callback, fwd);

	io_register_endpoint(socket);
	io_register_endpoint(fwd->pty);

	return fwd;
}

