#ifndef _TRACING_H
#define _TRACING_H

extern void		(*__tracing_hook)(const char *fmt, ...);

#define trace(...) do { \
		if (__tracing_hook) \
			__tracing_hook(__VA_ARGS__); \
	} while (0)

#endif /* _TRACING_H */
