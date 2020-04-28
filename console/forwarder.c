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
#include "forwarder.h"
#include "endpoint.h"
#include "tracing.h"

#include <fcntl.h>

static int		window_change_event_id = -1;

struct pty_window_event {
	struct event		base;
	unsigned int		rows;
	unsigned int		cols;
};

/*
 * Passthru senders and receivers
 */
static void
pty_push_event(struct event *ev, struct receiver *r)
{
	struct endpoint *pty = r->handle;

	if (ev->type == window_change_event_id) {
		struct pty_window_event *wev = (struct pty_window_event *) ev;

		trace("%s set window size %ux%u\n",
				endpoint_debug_name(pty), wev->rows, wev->cols);
		tty_set_window_size(pty->fd, wev->rows, wev->cols);
	} else {
		trace("%s unknown event %d\n", endpoint_debug_name(pty), ev->type);
	}
}

static struct receiver *
pty_receiver(struct endpoint *pty)
{
	struct receiver *r;

	r = calloc(1, sizeof(*r));
	r->handle = pty;
	r->recvq = &pty->sendq;
	r->push_event = pty_push_event;
	return r;
}

static struct sender *
pty_sender(struct endpoint *pty)
{
	struct sender *s;

	s = calloc(1, sizeof(*s));
	s->sendqp = &pty->recvq;
	return s;
}

static void
io_forwarder_eof_callback(struct endpoint *ep, void *handle)
{
	struct io_forwarder *fwd = handle;

	endpoint_debug(ep, "%s()", __func__);

	if (ep == fwd->socket) {
		/* We received an EOF from the client.
		 * We should now switch the pty master socket to sending a
		 * continuous stream of ctrl-ds... if we had termios enabled,
		 * which we don't, for now.
		 * Instead, just kill the child process.
		 */
		if (fwd->process) {
			trace("=== Hanging up PTY master ===\n");
			process_hangup(fwd->process);
		} else {
			trace("=== Hanging up TTY ===\n");
			tty_redirect_null(fwd->pty->fd);
		}

		if (fwd->pty)
			queue_destroy(&fwd->pty->sendq);
	} else
	if (ep == fwd->pty) {
		/* We received a hangup from the pty slave.
		 */
		if (fwd->process) {
			trace("=== Hanging up PTY master ===\n");
			process_hangup(fwd->process);
		}

		if (fwd->pty) {
			queue_destroy(&fwd->pty->sendq);
			endpoint_shutdown_write(fwd->pty);
		}

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
		trace("=== Hangup on tty ===\n");
		fwd->pty = NULL;
	}

	if (fwd->pty)
		fwd->pty->recvq = NULL;
	if (fwd->socket)
		fwd->socket->recvq = NULL;

	if (fwd->pty == NULL && fwd->socket == NULL) {
		if (fwd->process) {
			if (fwd->process->child_pid) {
				trace("%s: killing child process %d\n", endpoint_debug_name(ep), fwd->process->child_pid);
				process_kill(fwd->process);
				process_wait(fwd->process);
			}
			process_free(fwd->process);
		}
		free(fwd);
	}
}

/*
 * Window size events
 */
struct event *
io_forwarder_window_event(unsigned int rows, unsigned int cols)
{
	static struct pty_window_event event;

	if (window_change_event_id < 0)
		window_change_event_id = io_register_event_type("pty-window-change");

	event.base.type = window_change_event_id;
	event.rows = rows;
	event.cols = cols;

	return (struct event *) &event;
}

struct io_forwarder *
io_forwarder_setup(struct endpoint *socket, int tty_fd, struct console_slave *process)
{
	struct io_forwarder *fwd;

	fwd = calloc(1, sizeof(*fwd));
	fwd->socket = socket;
	fwd->process = process;

	fwd->pty = endpoint_new_pty(tty_fd);
	endpoint_register_eof_callback(fwd->pty, io_forwarder_eof_callback, fwd);
	endpoint_register_close_callback(fwd->pty, io_forwarder_close_callback, fwd);

	endpoint_set_upper_layer(socket,
			pty_sender(fwd->pty),
			pty_receiver(fwd->pty));

	endpoint_register_eof_callback(socket, io_forwarder_eof_callback, fwd);
	endpoint_register_close_callback(socket, io_forwarder_close_callback, fwd);

	io_register_endpoint(socket);
	io_register_endpoint(fwd->pty);

	return fwd;
}

