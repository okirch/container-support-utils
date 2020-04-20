/*
 * endpoint.c
 *
 * Wrapper class for sockets, ttys etc
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <assert.h>
#include <endpoint.h>


struct endpoint *
endpoint_new(int fd, const struct endpoint_ops *ops)
{
	struct endpoint *ep;

	ep = calloc(1, sizeof(*ep));
	ep->fd = fd;
	ep->ops = ops;

	return ep;
}

const char *
endpoint_debug_name(const struct endpoint *ep)
{
	static char namebuf[64];

	if (ep->debug_name)
		return ep->debug_name;

	snprintf(namebuf, sizeof(namebuf), "fd%d", ep->fd);
	return namebuf;
}

void
endpoint_error(const struct endpoint *ep, const char *fmt, ...)
{
	if (ep->debug) {
		va_list ap;
		int n;

		va_start(ap, fmt);
		fprintf(stderr, "ERROR on socket %s: ", endpoint_debug_name(ep));
		fprintf(stderr, fmt, ap);
		va_end(ap);

		n = strlen(fmt);
		if (n && fmt[n-1] != '\n')
			fputs("\n", stderr);
	}
}

void
endpoint_debug(const struct endpoint *ep, const char *fmt, ...)
{
	if (ep->debug) {
		va_list ap;
		int n;

		va_start(ap, fmt);
		fprintf(stderr, "%-20s ", endpoint_debug_name(ep));
		vfprintf(stderr, fmt, ap);
		va_end(ap);

		n = strlen(fmt);
		if (n && fmt[n-1] != '\n')
			fputs("\n", stderr);
	}
}

void
endpoint_free(struct endpoint *ep)
{
	if (ep->fd >= 0)
		close(ep->fd);

	queue_destroy(&ep->sendq);
	free(ep);
}

void
endpoint_shutdown_write(struct endpoint *ep)
{
	if (!ep->write_shutdown_requested)
		endpoint_debug(ep, "write-shutdown requested");

	ep->write_shutdown_requested = 1;

	if (queue_available(&ep->sendq) == 0) {
		ep->ops->shutdown_write(ep);
		ep->write_shutdown_sent = 1;
	}
}

/*
 * Common ops functions
 */
static int
__endpoint_poll_generic(const struct endpoint *ep, struct pollfd *pfd, unsigned int poll_mask)
{
	poll_mask &= ep->poll_mask;

	/* If we have nothing queued up for sending, we shouldn't wait for POLLOUT */
	if (queue_available(&ep->sendq) == 0)
		poll_mask &= ~POLLOUT;

	/* If the receive queue has been changed to NULL, this means we have nothing
	 * to write to anymore (and we need to discard all incoming data). In order
	 * not to miss the client closing the connection, we DO assert POLLIN in this
	 * situation.
	 *
	 * If recvq is non-NULL, but we have no room to queue more incoming data,
	 * we shouldn't wait for POLLIN */
	if (ep->recvq == NULL) {
		/* NOP */
	} else
	if (queue_tailroom(ep->recvq) == 0)
		poll_mask &= ~POLLIN;

	if (poll_mask == 0)
		return 0;

	pfd->fd = ep->fd;
	pfd->events = poll_mask;
	return 1;
}

/*
 * Socket code
 */
static size_t
__endpoint_socket_send_size_hint(const struct endpoint *ep)
{
	unsigned int size_hint = 0;

	if (ep->send_size_hint) {
		int bytes;

		if (ioctl(ep->fd, SIOCOUTQ, &bytes) >= 0
		 && (unsigned int) bytes <= ep->send_size_hint) {
			size_hint = ep->send_size_hint - bytes;
		}

	}

	if (size_hint == 0)
		size_hint = 1400; /* arbitrary */

	return size_hint;
}

static int
__endpoint_socket_send(struct endpoint *ep, const void *p, size_t len)
{
	int n;

	n = send(ep->fd, p, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0) {
		if (errno != EPIPE)
			perror("socket send");
	}

	return n;
}

static int
__endpoint_socket_recv(struct endpoint *ep, void *p, size_t len)
{
	int n;

	n = recv(ep->fd, p, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0)
		perror("socket recv");

	return n;
}

static int
__endpoint_socket_shutdown_write(struct endpoint *ep)
{
	if (shutdown(ep->fd, SHUT_WR) < 0) {
		perror("shutdown");
		return -1;
	}

	return 0;
}

static struct endpoint_ops __endpoint_socket_ops = {
	.poll		= __endpoint_poll_generic,
	.send_size_hint	= __endpoint_socket_send_size_hint,
	.send		= __endpoint_socket_send,
	.recv		= __endpoint_socket_recv,
	.shutdown_write	= __endpoint_socket_shutdown_write,
};

struct endpoint *
endpoint_new_socket(int fd)
{
	struct endpoint *ep;
	socklen_t optlen;
	int size;

	ep = endpoint_new(fd, &__endpoint_socket_ops);

	optlen = sizeof(size);
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, &optlen) < 0) {
		perror("getsockopt(SO_SNDBUF)");
	} else {
		assert(optlen == sizeof(size));
		ep->send_size_hint = size;
	}

	ep->poll_mask = POLLIN | POLLOUT;
	return ep;
}

/*
 * PTY endpoint
 */
static size_t
__endpoint_pty_send_size_hint(const struct endpoint *ep)
{
	unsigned int size_hint = 0;

	if (ep->send_size_hint) {
		int bytes;

		if (ioctl(ep->fd, TIOCOUTQ, &bytes) >= 0
		 && (unsigned int) bytes <= ep->send_size_hint) {
			size_hint = ep->send_size_hint - bytes;
		}

	}

	if (size_hint == 0)
		size_hint = 128; /* arbitrary */

	return size_hint;
}

static int
__endpoint_pty_send(struct endpoint *ep, const void *p, size_t len)
{
	int n;

	n = write(ep->fd, p, len);
	if (n < 0)
		perror("pty send");

	endpoint_debug(ep, "pty_send(%u bytes) = %d", len, n);
	return n;
}

static int
__endpoint_pty_recv(struct endpoint *ep, void *p, size_t len)
{
	int n;

	n = read(ep->fd, p, len);
	if (n < 0)
		perror("pty recv");

	endpoint_debug(ep, "pty_recv(%u bytes) = %d", len, n);
	return n;
}

static int
__endpoint_pty_shutdown_write(struct endpoint *ep)
{
	/* Not implemented yet */
	return 0;
}

static struct endpoint_ops __endpoint_pty_ops = {
	.poll		= __endpoint_poll_generic,
	.send_size_hint	= __endpoint_pty_send_size_hint,
	.send		= __endpoint_pty_send,
	.recv		= __endpoint_pty_recv,
	.shutdown_write	= __endpoint_pty_shutdown_write,
};

struct endpoint *
endpoint_new_pty(int fd)
{
	struct endpoint *ep;
	int flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
		fprintf(stderr, "fcntl(pty, F_GETFL): %m\n");
		return NULL;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		fprintf(stderr, "fcntl(pty, F_SETFL, O_NONBLOCK): %m\n");
		return NULL;
	}

	ep = endpoint_new(fd, &__endpoint_pty_ops);

	/* There's an ioctl for inquiring the buffer size */
	ep->send_size_hint = 4096;

	ep->poll_mask = POLLIN | POLLOUT;
	return ep;
}

int
endpoint_transmit(struct endpoint *ep)
{
	size_t send_sz, size_hint;
	void *buf;
	const void *p;
	int sent;

	send_sz = queue_available(&ep->sendq);
	if (send_sz == 0)
		return 0;

	size_hint = endpoint_send_size_hint(ep);
	if (size_hint && size_hint < send_sz)
		send_sz = size_hint;

	assert(send_sz <= QUEUE_SZ);

	buf = alloca(send_sz);

	/* Get a pointer to send_sz bytes from the send queue.
	 * If needed, this will linearize data from the send q
	 * and store it in buf. Otherwise, it may return a pointer
	 * to an internal buffer that we can send from directly.
	 */
	p = queue_peek(&ep->sendq, buf, send_sz);

	sent = endpoint_send(ep, p, send_sz);
	if (sent >= 0)
		queue_advance_head(&ep->sendq, sent);

	return sent;
}

unsigned int
endpoint_tailroom(const struct endpoint *ep)
{
	if (ep->write_shutdown_requested)
		return 0;

	return queue_tailroom(&ep->sendq);
}

int
endpoint_enqueue(struct endpoint *ep, const void *buffer, size_t count)
{
	unsigned int tailroom = endpoint_tailroom(ep);

	if (tailroom < count) {
		fprintf(stderr, "%s: not enough room in send buffer\n", __func__);
		return -1;
	}

	queue_append(&ep->sendq, buffer, count);
	return count;
}

int
endpoint_receive(struct endpoint *ep)
{
	size_t recv_sz;
	void *buf;
	int n;

	if (ep->recvq == NULL) {
		/* Discard incoming data */
		buf = alloca(4096);
		return endpoint_recv(ep, buf, 4096);
	}

	recv_sz = queue_tailroom(ep->recvq);
	if (recv_sz == 0) {
		/* XXX complain */
		fprintf(stderr, "bug: %s called without space in recvq\n", __func__);
		return 0;
	}

	buf = alloca(recv_sz);

	n = endpoint_recv(ep, buf, recv_sz);
	if (n >= 0)
		queue_append(ep->recvq, buf, n);

	return n;
}

void
endpoint_eof_from_peer(struct endpoint *ep)
{
	ep->read_shutdown_received = 1;
	ep->poll_mask &= ~POLLIN;

	if (ep->data_sink_callback) {
		ep->data_sink_callback(NULL, ep->app_handle);
	} else {
		endpoint_shutdown_write(ep);
	}

	ep->recvq = NULL;
}
