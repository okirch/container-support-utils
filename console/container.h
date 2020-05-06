/*
 * container.h
 *
 * Detect and access containers.
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

struct export_state;
struct export_dir_array;

extern int			export_dir_prepare(const struct export_dir_array *ap, struct export_state **retp);
extern void			export_state_destroy(struct export_state *state_list);
extern int			export_state_apply(struct export_state *state_list);

#endif /* _CONTAINER_H */
