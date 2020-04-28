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

/* For __get_logf() */
#include <unistd.h>
#include <fcntl.h>

#include "endpoint.h"
#include "tracing.h"

void		(*__tracing_hook)(const char *fmt, ...);

static FILE *	logfile = NULL;
static bool	logging_to_tty = false;
static bool	logging_raw_tty = false;

static FILE *
__get_logf(void)
{
	if (logfile == NULL) {
		int fd = dup(2);

		fcntl(fd, F_SETFD, FD_CLOEXEC);
		logfile = fdopen(fd, "w");

		logging_to_tty = isatty(fd);
	}
	return logfile;
}

static void
__trace_logfile(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(__get_logf(), fmt, ap);
	va_end(ap);
}

/*
 * Print a prefix to a log message. We squirrel away errno in case
 * the message format contains %m.
 */
static void
__log_prefix(const char *fmt, ...)
{
	int saved_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vfprintf(__get_logf(), fmt, ap);
	va_end(ap);

	errno = saved_errno;
}

static void
__log_format(const char *fmt, va_list ap)
{
	FILE *f = __get_logf();

	if (fmt == NULL)
		return;

	vfprintf(f, fmt, ap);

	/* When logging to a tty in raw mode, there is no automatic CRLF
	 * translation. fudge it. */
	if (logging_to_tty && logging_raw_tty) {
		int n = strlen(fmt);
		if (n && fmt[n-1] == '\n')
			fputc('\r', f);
	}
	if (logging_to_tty)
		fflush(f);
}

void
log_warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_prefix("Warning: ");
	__log_format(fmt, ap);
	va_end(ap);
}

void
log_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_prefix("Error: ");
	__log_format(fmt, ap);
	va_end(ap);
}

void
log_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__log_prefix("Fatal error: ");
	__log_format(fmt, ap);
	va_end(ap);

	exit(1);
}

bool
set_logfile(const char *filename)
{
	if (logfile && logfile != stderr)
		fclose(logfile);
	logfile = NULL;

	printf("Setting logfile to %s\n", filename);
	if (filename && strcmp(filename, "-")) {
		logfile = fopen(filename, "w");
		if (logfile == NULL) {
			fprintf(stderr, "Unable to open logfile \"%s\": %m\n", filename);
			return false;
		}
		setlinebuf(logfile);
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

void
logging_notify_raw_tty(bool on)
{
	trace("%s(%d)\n", __func__, on);
	logging_raw_tty = on;
}

/*
 * Endpoint error and tracing hooks
 */
void
endpoint_error(const struct endpoint *ep, const char *fmt, ...)
{
	if (ep->debug) {
		FILE *fp = __get_logf();
		va_list ap;
		int n;

		va_start(ap, fmt);
		__log_prefix("Error on socket %s: ", endpoint_debug_name(ep));
		vfprintf(fp, fmt, ap);
		va_end(ap);

		n = strlen(fmt);
		if (n && fmt[n-1] != '\n')
			fputs("\n", fp);
	}
}

void
endpoint_debug(const struct endpoint *ep, const char *fmt, ...)
{
	if (ep->debug) {
		FILE *fp = __get_logf();
		va_list ap;
		int n;

		va_start(ap, fmt);
		__log_prefix("%-20s ", endpoint_debug_name(ep));
		vfprintf(fp, fmt, ap);
		va_end(ap);

		n = strlen(fmt);
		if (n && fmt[n-1] != '\n')
			trace("\n");
	}
}

