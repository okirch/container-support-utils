/*
 * Test socket code
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

#undef TRACE
#undef PROGRESS

static void
do_queue_pattern(struct queue *q, unsigned long *pos, unsigned int count)
{
	void *buf = alloca(count);

#ifdef TRACE
	printf("%s(pos %lu (offset %lu), count %u)\n", __func__, *pos, *pos % test_pattern_len, count);
#endif

	memset(buf, '^', count);
	test_generate_pattern(pos, buf, count);

	queue_append(q, buf, count);
}

static void
do_recv_pattern(struct queue *q, unsigned long *pos, unsigned int count)
{
	unsigned char *buf = alloca(count);
	const unsigned char *p;
	unsigned long fail_pos;

#ifdef TRACE
	printf("%s(pos %lu (offset %lu), count %u)\n", __func__, *pos, *pos % test_pattern_len, count);
#endif

	p = queue_peek(q, buf, count);
	if (!test_verify_pattern(pos, p, count, &fail_pos)) {
		/* __show_corrupt_buffer(q, orig_pos, fail_pos - orig_pos); */

		fflush(stderr);
		assert(0);
	}
	queue_advance_head(q, count);
}

struct client_appdata {
	bool		random_send;
	bool		random_recv;
	unsigned long	send_pos;
	unsigned long	recv_pos;

	unsigned int	nsends;
	unsigned int	nrecvs;

	bool		closed;

	struct queue	recvq;
};

static void
client_send_callback(struct queue *q, void *handle)
{
	struct client_appdata *appdata = handle;
	size_t send_sz;

	send_sz = queue_tailroom(q);
	if (appdata->random_send)
		send_sz = test_random_size(send_sz);

	if (send_sz) {
		do_queue_pattern(q, &appdata->send_pos, send_sz);
		appdata->nsends++;
#if !defined(TRACE) && defined(PROGRESS)
		write(1, ".", 1);
#endif
	}
}

static void
client_recv_callback(struct queue *q, void *handle)
{
	struct client_appdata *appdata = handle;
	size_t recv_sz;

	if (q == NULL) {
		/* EOF from client */
		return;
	}

	recv_sz = queue_available(q);
#ifdef TRACE
	printf("%s: %lu bytes of data available\n", __func__, recv_sz);
#endif
	if (appdata->random_recv)
		recv_sz = test_random_size(recv_sz);

	do_recv_pattern(q, &appdata->recv_pos, recv_sz);
	appdata->nrecvs++;

#if !defined(TRACE) && defined(PROGRESS)
	write(1, "+", 1);
#endif
}

static void
client_close_callback(struct endpoint *ep, void *handle)
{
	struct client_appdata *appdata = handle;

#ifdef TRACE
	printf("%s: socket about to be destroyed\n", __func__);
#endif
	appdata->closed = true;
}

void
client_print_stats(const struct client_appdata *appdata)
{
	printf("OK: sent %s bytes in %u chunks; received %s bytes in %u chunks. %lu bytes still in flight.\n",
			print_byte_count(appdata->send_pos), appdata->nsends,
			print_byte_count(appdata->recv_pos), appdata->nrecvs,
			appdata->send_pos - appdata->recv_pos);
}

struct endpoint *
create_console_service(int fd, struct console_slave *console)
{
	struct endpoint *sep, *pep;

	sep = endpoint_new_socket(fd);
	sep->debug_name = "shell-service";

	pep = endpoint_new_pty(console->master_fd);
	pep->debug_name = "cat";

	/* Incoming data from the socket goes to the pty master.
	 * Incoming data from the shell session goes to the socket. */
	sep->recvq = &pep->sendq;
	pep->recvq = &sep->sendq;

#ifdef TRACE
	sep->debug = true;
	pep->debug = true;
#endif

	io_register_endpoint(pep);
	io_register_endpoint(sep);
	return sep;
}

struct endpoint *
create_client(int fd, const char *name, struct client_appdata *appdata)
{
	struct endpoint *ep;

	ep = endpoint_new_socket(fd);
	ep->debug_name = name;
	ep->recvq = &appdata->recvq;

	ep->data_source_callback = client_send_callback;
	ep->data_sink_callback = client_recv_callback;
	ep->close_callback = client_close_callback;
	ep->app_handle = appdata;

#ifdef TRACE
	ep->debug = true;
#endif

	io_register_endpoint(ep);
	return ep;
}

static void
appdata_init(struct client_appdata *appdata, bool random_send, bool random_recv)
{
	memset(appdata, 0, sizeof(*appdata));
	appdata->random_send = random_send;
	appdata->random_recv = random_recv;
	queue_init(&appdata->recvq);
}

void
do_cat_test(unsigned int time, bool random_send, bool random_recv)
{
	char *argv[] = {
		"cat",
		NULL
	};
	struct console_slave *console;
	struct client_appdata appdata;
	int pair[2], status;

	printf("echo test%s%s, duration %u\n",
			random_send? " random-sends" : "",
			random_recv? " random-recvs" : "",
			time);

	appdata_init(&appdata, random_send, random_recv);

	console = start_shell("/usr/bin/cat", argv, -1);

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, pair) < 0) {
		perror("socketpair");
		exit(66);
	}

	/* The first of the two sockets is the echo socket.
	 * Its recvq is also its sendq. */
	create_console_service(pair[0], console);

	/* The second socket is the client socket. */
	create_client(pair[1], "echo-client", &appdata);

	io_mainloop(time * 1000);

	assert(appdata.recv_pos <= appdata.send_pos);
	/* assert(appdata.send_pos - appdata.recv_pos <= QUEUE_SZ); */

	process_kill(console);
	if (process_wait(console) < 0) {
		fprintf(stderr, "failed to wait for child process\n");
		exit(99);
	}

	status = process_killsignal(console);
	if (status == 9) {
		/* We killed it */
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
	}

	client_print_stats(&appdata);

	io_close_all();
}

static void
usage(int exitval)
{
	fprintf(stderr, "test-shell [-h] [-t timeout] [-s seed] [test-name ...]\n");
	fprintf(stderr,
		"-h        show this message\n"
		"-t timeout\n"
		"          Test case duration in seconds\n"
		"-s seed\n"
		"          Initialize random number generator with seed\n");
	fprintf(stderr,
		"\n"
		"Valid test names:\n"
		"  cat\n"
	       );
	exit(exitval);
}

enum {
	TEST_CAT,
};

int
main(int argc, char **argv)
{
	int opt_timeout = 5, opt_seed;
	bool opt_seed_set = false;
	unsigned int opt_tests = ~0U;
	int c;

	while ((c = getopt(argc, argv, "hs:t:")) != EOF) {
		switch (c) {
		case 's':
			if (!parse_int_arg("seed -s", optarg, &opt_seed))
				return 1;
			opt_seed_set = true;
			break;

		case 't':
			if (!parse_int_arg("timeout -t", optarg, &opt_timeout))
				return 1;
			break;

		case 'h':
			usage(0);
		default:
			usage(1);
		}
	}

	if (optind < argc) {
		opt_tests = 0;

		while (optind < argc) {
			const char *test_name= argv[optind++];

			if (!strcmp(test_name, "cat")) {
				opt_tests |= (1 << TEST_CAT);
			} else {
				fprintf(stderr, "Unknown test case name \"%s\"\n", test_name);
				usage(1);
			}
		}
	}

	if (opt_seed_set) {
		/* For the log file */
		printf("Initializing RNG with seed %d\n", opt_seed);
		srandom(opt_seed);
	}

	if (opt_tests & (1 << TEST_CAT))
		do_cat_test(opt_timeout, true, false);
	printf("All is well.\n");
	return 0;
}

