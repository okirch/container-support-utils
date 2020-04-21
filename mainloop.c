/*
 * forwarder.c
 *
 * Forward data between pty/socket
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/poll.h>
#include <sys/time.h>
#include "endpoint.h"

#define ENDPOINT_MAX	1024

static struct endpoint *io_endpoints[ENDPOINT_MAX];
static unsigned int	io_endpoint_count;

static struct io_callback *io_callbacks;

void
io_register_endpoint(struct endpoint *ep)
{
	assert(io_endpoint_count < ENDPOINT_MAX);
	io_endpoints[io_endpoint_count++] = ep;
}

static inline void
io_callback_insert(struct io_callback **pos, struct io_callback *cb)
{
	struct io_callback *next = *pos;

	cb->prev = pos;
	cb->next = next;
	if (next)
		next->prev = &cb->next;
	*pos = cb;
}

static inline void
io_callback_remove(struct io_callback *cb)
{
	struct io_callback **pos = cb->prev;
	struct io_callback *next = cb->next;

	*pos = next;
	if (next)
		next->prev = pos;

	cb->prev = NULL;
	cb->next = NULL;
}

void
io_register_callback(struct io_callback *cb)
{
	assert(cb->prev == NULL);
	io_callback_insert(&io_callbacks, cb);
}

void
io_unregister_callback(struct io_callback *cb)
{
	if (cb->prev == NULL)
		return;

	io_callback_remove(cb);
}

void
io_close_all(void)
{
	while (io_endpoint_count) {
		struct endpoint *ep = io_endpoints[--io_endpoint_count];

		endpoint_free(ep);
	}
}

void
io_close_dead(void)
{
	struct endpoint *dead[ENDPOINT_MAX];
	unsigned int i, j, ndead = 0;

	for (i = j = 0; i < io_endpoint_count; ++i) {
		struct endpoint *ep = io_endpoints[i];

		if (ep->write_shutdown_sent && ep->read_shutdown_received) {
			endpoint_debug(ep, "socket is a zombie");
			dead[ndead++] = ep;

			endpoint_close_callback(ep);
		} else {
			io_endpoints[j++] = ep;
		}
	}
	io_endpoint_count = j;

	for (i = 0; i < ndead; ++i) {
		struct endpoint *zombie = dead[i];

		for (j = 0; j < io_endpoint_count; ++j) {
			struct endpoint *ep = io_endpoints[j];

			if (zombie->recvq == &ep->sendq) {
				endpoint_debug(ep, "socket peer is a zombie");
				endpoint_shutdown_write(ep);
			}
			if (ep->recvq == &zombie->sendq) {
				/* XXX warn? */
				ep->recvq = NULL;
			}
		}

		endpoint_debug(zombie, "DESTROYED");
		endpoint_free(zombie);
	}
}

unsigned long
io_timestamp_ms(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) < 0) {
		perror("gettimeofday");
		exit(66);
	}
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int
io_mainloop(long timeout)
{
	unsigned long until = 0;

	if (timeout >= 0)
		until = io_timestamp_ms() + timeout;

	while (io_endpoint_count) {
		struct pollfd pfd[ENDPOINT_MAX];
		struct endpoint *watching[ENDPOINT_MAX];
		int nfds = 0, i, count;
		unsigned long now, wait_ms;

		for (i = 0; i < io_endpoint_count; ++i) {
			struct endpoint *ep = io_endpoints[i];

			if (!ep->write_shutdown_requested)
				endpoint_data_source_callback(ep);

			if (endpoint_poll(ep, &pfd[nfds], ~0) > 0) {
				if (ep->debug) {
					int events = pfd[nfds].events;
					endpoint_debug(ep, "poll %s%s",
							(events & POLLIN)? " POLLIN" : "",
							(events & POLLOUT)? " POLLOUT" : "");
				}
				watching[nfds++] = ep;
			}
		}

		if (nfds == 0) {
			fprintf(stderr, "%s: %u sockets but they're all shy\n", __func__, io_endpoint_count);
			break;
		}

		if (until == 0) {
			wait_ms = 1000;
		} else {
			now = io_timestamp_ms();
			if (now >= until)
				return 0;
			wait_ms = until - now;
		}

		if (poll(pfd, nfds, wait_ms) < 0) {
			perror("poll");
			return -1;
		}

		for (i = 0; i < nfds; ++i) {
			struct endpoint *ep = watching[i];

			if (pfd[i].revents & POLLOUT) {
				endpoint_debug(ep, "socket can send");
				count = endpoint_transmit(ep);
				if (count < 0) {
					endpoint_error(ep, "socket transmit error");
					return -1;
				}

				endpoint_debug(ep, "socket transmitted %d bytes", count);
				if (ep->write_shutdown_requested && !ep->write_shutdown_sent)
					endpoint_shutdown_write(ep);
			}
		}

		now = io_timestamp_ms();
		for (i = 0; i < nfds; ++i) {
			struct endpoint *ep = watching[i];

			if (pfd[i].revents & POLLHUP) {
				endpoint_debug(ep, "hangup from client");
				endpoint_eof_from_peer(ep);
			}

			if (pfd[i].revents & POLLIN) {
				endpoint_debug(ep, "socket has data");
				count = endpoint_receive(ep);
				if (count < 0) {
					endpoint_error(ep, "socket receive error");
					return -1;
				}
				if (count == 0) {
					endpoint_debug(ep, "socket received end of file from peer");
					endpoint_eof_from_peer(ep);
					continue;
				}

				endpoint_debug(ep, "socket received %d bytes", count);
				endpoint_data_sink_callback(ep);
			}
		}

		io_close_dead();
	}

	return 0;
}
