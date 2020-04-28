/*
 * container.h
 *
 * Detect and access containers.
 */

#ifndef _CONTAINER_H
#define _CONTAINER_H

#include <stdbool.h>

struct container {
	pid_t			pid;
	int			procfd;
};

extern struct container *	container_open(pid_t pid);
extern void			container_close(struct container *);
extern bool			container_has_command(const struct container *, const char *command);
extern int			container_attach(const struct container *);

#endif /* _CONTAINER_H */
