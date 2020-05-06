/*
 * savelog.h
 *
 * Client side of the savelog facility.
 *
 *   Copyright (C) 2020 Olaf Kirch <okir@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef SAVELOG_H
#define SAVELOG_H

#include <stdbool.h>

/* Server side init */
extern int		savelog_init(const char *destination);

/* Client side */
struct savelog {
	int		fd;

	bool		overwrite;

	int		(*send)(struct savelog *, const char *pathname);
};

extern struct savelog *	savelog_connect(void);

static inline int
savelog_send_file(struct savelog *savelog, const char *pathname)
{
	return savelog->send(savelog, pathname);
}

#endif /* SAVELOG_H */
