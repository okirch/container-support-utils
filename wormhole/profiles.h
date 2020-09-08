/*
 * profiles.h
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

#ifndef _WORMHOLE_PROFILES_H
#define _WORMHOLE_PROFILES_H

struct path_info {
	char *			path;
	char *			replace;
};

#define PATH_INFO_HIDE(n)	{ .path = n, .replace = NULL }
#define PATH_INFO_REPLACE(n)	{ .path = n, .replace = "$ROOT" n }
#define PATH_INFO_REPLACE_CHILDREN(n)	{ .path = n, .replace = "$ROOT" n "/*" }
#define PATH_INFO_WORMHOLE(n)	{ .path = n, .replace = "/usr/bin/wormhole" }

struct wormhole_environment {
	struct wormhole_environment *next;

	char *			name;
	int			nsfd;
	bool			failed;

	/* While setup is in process */
	struct {
		pid_t		child_pid;
		unsigned int	sock_id;
	} setup_ctx;
};

typedef struct wormhole_profile wormhole_profile_t;
struct wormhole_profile {
	char *			name;
	char *			command;
	char *			container_image;
	char *			mount_point;
	struct path_info	path_info[128];
};

extern wormhole_profile_t *		wormhole_profile_find(const char *argv0);
extern int				wormhole_profile_setup(wormhole_profile_t *);

extern struct wormhole_environment *	wormhole_environment_find(const char *name);
extern struct wormhole_socket *		wormhole_environment_async_setup(struct wormhole_environment *, wormhole_profile_t *);
extern bool				wormhole_environment_async_complete(pid_t pid, int status);

#endif // _WORMHOLE_PROFILES_H
