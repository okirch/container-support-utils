#ifndef _TRACING_H
#define _TRACING_H

#include <stdbool.h>

extern void		(*__tracing_hook)(const char *fmt, ...);

#define trace(...) do { \
		if (__tracing_hook) \
			__tracing_hook(__VA_ARGS__); \
	} while (0)

extern bool		set_logfile(const char *filename);
extern void		tracing_enable(void);

extern void		log_warning(const char *fmt, ...);
extern void		log_error(const char *fmt, ...);
extern void		log_fatal(const char *fmt, ...);
extern void		logging_notify_raw_tty(bool);

#endif /* _TRACING_H */
