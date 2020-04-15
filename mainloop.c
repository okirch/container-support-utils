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

void
io_register_endpoint(struct endpoint *ep)
{
	assert(io_endpoint_count < ENDPOINT_MAX);
	io_endpoints[io_endpoint_count++] = ep;
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
			if (ep->debug)
				fprintf(stderr, "%-10s socket is a zombie\n", endpoint_debug_name(ep));
			dead[ndead++] = ep;
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
				if (ep->debug)
					fprintf(stderr, "%-10s socket peer is a zombie\n", endpoint_debug_name(ep));
				endpoint_shutdown_write(ep);
			}
			if (ep->recvq == &zombie->sendq) {
				/* XXX warn? */
				ep->recvq = NULL;
			}
		}

		if (zombie->debug)
			fprintf(stderr, "%-10s DESTROYED\n", endpoint_debug_name(zombie));
		endpoint_free(zombie);
	}
}

static unsigned long
ms_now(void)
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
		until = ms_now() + timeout;

	while (io_endpoint_count) {
		struct pollfd pfd[ENDPOINT_MAX];
		struct endpoint *watching[ENDPOINT_MAX];
		int nfds = 0, i, count;
		unsigned long now, wait_ms;

		for (i = 0; i < io_endpoint_count; ++i) {
			struct endpoint *ep = io_endpoints[i];

			if (ep->data_source_callback && !ep->write_shutdown_requested)
				ep->data_source_callback(&ep->sendq, ep->app_handle);

			if (endpoint_poll(ep, &pfd[nfds], ~0) > 0) {
				if (ep->debug) {
					int events = pfd[nfds].events;
					printf("%-10s poll %s%s\n",
							endpoint_debug_name(ep),
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
			now = ms_now();
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
				if (ep->debug)
					printf("%-10s socket can send\n", endpoint_debug_name(ep));
				count = endpoint_transmit(ep);
				if (count < 0) {
					fprintf(stderr, "%-10s socket transmit error\n", endpoint_debug_name(ep));
					return -1;
				}

				if (ep->write_shutdown_requested && !ep->write_shutdown_sent)
					endpoint_shutdown_write(ep);
			}
		}

		for (i = 0; i < nfds; ++i) {
			struct endpoint *ep = watching[i];

			if (pfd[i].revents & POLLHUP) {
				if (ep->debug)
					printf("%-10s hangup from client\n", endpoint_debug_name(ep));
			}

			if (pfd[i].revents & POLLIN) {
				if (ep->debug)
					printf("%-10s socket has data\n", endpoint_debug_name(ep));
				count = endpoint_receive(ep);
				if (count < 0) {
					fprintf(stderr, "%-10s socket receive error\n", endpoint_debug_name(ep));
					return -1;
				}
				if (count == 0) {
					if (ep->debug)
						printf("%-10s socket received end of file from client\n", endpoint_debug_name(ep));

					ep->read_shutdown_received = 1;
					if (ep->data_sink_callback) {
						ep->data_sink_callback(NULL, ep->app_handle);
					} else {
						endpoint_shutdown_write(ep);
					}
						
					continue;
				}

				if (ep->debug)
					printf("%-10s socket received %d bytes\n", endpoint_debug_name(ep), count);
				if (ep->data_sink_callback)
					ep->data_sink_callback(ep->recvq, ep->app_handle);

			}
		}

		io_close_dead();
	}

	return 0;
}
