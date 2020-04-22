/*
 * tracing.c
 *
 * Simple tracing and logging facilities
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "tracing.h"

void		(*__tracing_hook)(const char *fmt, ...);

static FILE *	logfile = NULL;

static void
__trace_logfile(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(logfile?: stderr, fmt, ap);
	va_end(ap);
}

/*
 * Print a prefix to a log message. We squirrel away errno in case
 * the message format contains %m.
 */
static void
__log_prefix(const char *pfx)
{
	int saved_errno = errno;

	fprintf(logfile?: stderr, "%s: ", pfx);
	errno = saved_errno;
}

void
log_warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_prefix("Warning");
	vfprintf(logfile?: stderr, fmt, ap);
	va_end(ap);
}

void
log_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_prefix("Error");
	vfprintf(logfile?: stderr, fmt, ap);
	va_end(ap);
}

void
log_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_prefix("Fatal error");
	vfprintf(logfile?: stderr, fmt, ap);
	va_end(ap);

	exit(1);
}

bool
set_logfile(const char *filename)
{
	if (logfile && logfile != stderr)
		fclose(logfile);
	logfile = NULL;

	if (filename && strcmp(filename, "-")) {
		logfile = fopen(filename, "w");
		if (logfile == NULL) {
			fprintf(stderr, "Unable to open logfile \"%s\": %m\n", filename);
			return false;
		}
	} else {
		logfile = stderr;
	}

	return true;
}

void
tracing_enable(void)
{
	__tracing_hook = __trace_logfile;
}
