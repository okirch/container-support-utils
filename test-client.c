/*
 * Test client that sends a test pattern and verifies what comes back from
 * the service.
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>
#include "shell.h"
#include "endpoint.h"
#include "testing.h"

static void
test_client_send_callback(struct queue *q, void *handle)
{
	struct test_client_appdata *appdata = handle;
	size_t send_sz;

	send_sz = queue_tailroom(q);
	if (appdata->random_send)
		send_sz = test_random_size(send_sz);

	if (send_sz) {
		test_client_queue_pattern(q, &appdata->send_pos, send_sz);
		appdata->nsends++;

		if (test_progress)
			write(1, ".", 1);
	}
}

static void
test_client_recv_callback(struct queue *q, void *handle)
{
	struct test_client_appdata *appdata = handle;
	size_t recv_sz;

	if (q == NULL) {
		/* EOF from client */
		return;
	}

	recv_sz = queue_available(q);
	test_trace("%s: %lu bytes of data available\n", __func__, recv_sz);

	if (appdata->random_recv)
		recv_sz = test_random_size(recv_sz);
	test_client_recv_pattern(q, &appdata->recv_pos, recv_sz);
	appdata->nrecvs++;

	if (test_progress)
		write(1, "+", 1);
}

static void
test_client_close_callback(struct endpoint *ep, void *handle)
{
	struct test_client_appdata *appdata = handle;

	if (test_progress)
		write(1, "\n", 1);

	test_trace("%s: socket about to be destroyed\n", __func__);
	appdata->closed = true;
}

void
test_client_print_stats(const struct test_client_appdata *appdata)
{
	printf("OK: sent %s bytes in %u chunks; received %s bytes in %u chunks. %lu bytes still in flight.\n",
			print_byte_count(appdata->send_pos), appdata->nsends,
			print_byte_count(appdata->recv_pos), appdata->nrecvs,
			appdata->send_pos - appdata->recv_pos);
}

void
test_client_appdata_init(struct test_client_appdata *appdata, bool random_send, bool random_recv)
{
	memset(appdata, 0, sizeof(*appdata));
	appdata->random_send = random_send;
	appdata->random_recv = random_recv;
	queue_init(&appdata->recvq);
}

struct endpoint *
test_client_create(int fd, const char *name, struct test_client_appdata *appdata)
{
	struct endpoint *ep;

	ep = endpoint_new_socket(fd);
	ep->debug_name = name;
	ep->recvq = &appdata->recvq;

	ep->data_source_callback = test_client_send_callback;
	ep->data_sink_callback = test_client_recv_callback;
	ep->close_callback = test_client_close_callback;
	ep->app_handle = appdata;

	ep->debug = test_tracing;

	io_register_endpoint(ep);
	return ep;
}
