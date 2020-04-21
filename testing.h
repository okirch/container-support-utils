#ifndef _TESTING_H
#define _TESTING_H

struct test_case_info {
	const char *	name;
	unsigned int	id;
};

#define TEST_CASE_MAX	16

struct test_app {
	const char *	name;

	struct test_case_info test_cases[TEST_CASE_MAX];
};

struct test_util_options {
	int		timeout;
	int		seed;

	unsigned int	tests;
};

extern bool		test_tracing;
extern bool		test_progress;

extern const char	test_pattern[];
extern const unsigned int test_pattern_len;

extern void		test_parse_arguments(const struct test_app *, struct test_util_options *, int argc, char **argv);
extern bool		parse_int_arg(const char *name, const char *arg, int *opt_valp);
extern const char *	print_byte_count(unsigned long);

extern bool *		test_set_alarm(unsigned int nsecs);
extern unsigned int	test_random_size(unsigned int sz);
extern void		test_generate_pattern(unsigned long *pos, void *buffer, unsigned int count);
extern bool		test_verify_pattern(unsigned long *pos, const unsigned char *buffer, unsigned int count,
				unsigned long *fail_pos);

struct test_client_appdata {
	bool		random_send;
	bool		random_recv;
	unsigned long	send_pos;
	unsigned long	recv_pos;

	unsigned int	nsends;
	unsigned int	nrecvs;

	bool		closed;

	struct queue	recvq;
};

extern struct application_ops  test_client_application_ops;

extern void		test_client_appdata_init(struct test_client_appdata *appdata, bool random_send, bool random_recv);
extern struct endpoint *test_client_create(int fd, const char *name, struct test_client_appdata *appdata);
extern void		test_client_queue_pattern(struct queue *q, unsigned long *pos, unsigned int count);
extern void		test_client_recv_pattern(struct queue *q, unsigned long *pos, unsigned int count);
extern void		test_client_print_stats(const struct test_client_appdata *appdata);


#define test_trace(...) \
	if (test_tracing) do { \
		fflush(stdout); \
		fprintf(stderr, __VA_ARGS__); \
	} while (0)

#endif /* _TESTING_H */
