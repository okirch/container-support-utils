#ifndef _TESTING_H
#define _TESTING_H

extern const char	test_pattern[];
extern const unsigned int test_pattern_len;

extern bool		parse_int_arg(const char *name, const char *arg, int *opt_valp);
extern const char *	print_byte_count(unsigned long);

extern bool *		test_set_alarm(unsigned int nsecs);
extern unsigned int	test_random_size(unsigned int sz);
extern void		test_generate_pattern(unsigned long *pos, void *buffer, unsigned int count);
extern bool		test_verify_pattern(unsigned long *pos, const unsigned char *buffer, unsigned int count,
				unsigned long *fail_pos);

#endif /* _TESTING_H */
