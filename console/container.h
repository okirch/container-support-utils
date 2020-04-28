/*
 * container.h
 *
 * Detect and access containers.
 */

#ifndef _CONTAINER_H
#define _CONTAINER_H

#include <stdbool.h>

struct container_info {
	pid_t			pid;
	char *			hostname;

	struct {
		unsigned int	dev, ino;
	} __private;
};

struct container {
	pid_t			pid;
	int			procfd;
};

extern int			container_list(struct container_info *result, unsigned int max);
extern void			container_info_destroy(struct container_info *list, unsigned int count);
extern struct container *	container_open(const char *id);
extern void			container_close(struct container *);
extern bool			container_has_command(const struct container *, const char *command);
extern int			container_attach(const struct container *);

#endif /* _CONTAINER_H */
