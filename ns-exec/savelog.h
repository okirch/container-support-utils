/*
 * savelog.h
 *
 * Client side of the savelog facility.
 */

#ifndef SAVELOG_H
#define SAVELOG_H

/* Server side init */
extern int		savelog_init(const char *destination);

/* Client side */
struct savelog {
	int		fd;
	int		(*send)(struct savelog *, const char *pathname);
};

extern struct savelog *	savelog_connect(void);

static inline int
savelog_send_file(struct savelog *savelog, const char *pathname)
{
	return savelog->send(savelog, pathname);
}

#endif /* SAVELOG_H */
