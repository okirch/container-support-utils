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

#include "environment.h"

/* fwd decl */
struct wormhole_config;

enum {
	WORMHOLE_PATH_TYPE_HIDE,
	WORMHOLE_PATH_TYPE_BIND,
	WORMHOLE_PATH_TYPE_BIND_CHILDREN,
	WORMHOLE_PATH_TYPE_OVERLAY,
	WORMHOLE_PATH_TYPE_OVERLAY_CHILDREN,
	WORMHOLE_PATH_TYPE_WORMHOLE,
};

struct path_info {
	int			type;
	char *			path;
	char *			replace;
};

#define PATH_INFO_HIDE(n)	{ .path = n, .replace = NULL }
#define PATH_INFO_REPLACE(n)	{ .path = n, .replace = "$ROOT" n }
#define PATH_INFO_REPLACE_CHILDREN(n)	{ .path = n, .replace = "$ROOT" n "/*" }
#define PATH_INFO_WORMHOLE(n)	{ .path = n, .replace = "/usr/bin/wormhole" }

typedef struct wormhole_profile wormhole_profile_t;
struct wormhole_profile {
	wormhole_profile_t *	next;
	char *			name;

	wormhole_environment_t *environment;

	struct wormhole_profile_config *config;
};

extern bool			wormhole_profiles_configure(struct wormhole_config *);
extern wormhole_profile_t *	wormhole_profile_find(const char *argv0);
extern int			wormhole_profile_setup(wormhole_profile_t *);

extern const char *		wormhole_profile_command(const wormhole_profile_t *);
extern wormhole_environment_t *	wormhole_profile_environment(wormhole_profile_t *);
extern int			wormhole_profile_namespace_fd(const wormhole_profile_t *);
/* Will go away again */
extern const char *		wormhole_profile_container_image_name(const wormhole_profile_t *);

#endif // _WORMHOLE_PROFILES_H
