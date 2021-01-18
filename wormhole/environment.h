/*
 * environment.h
 *
 *   Copyright (C) 2020, 2021 Olaf Kirch <okir@suse.de>
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

#ifndef _WORMHOLE_ENVIRONMENT_H
#define _WORMHOLE_ENVIRONMENT_H

/* fwd decl */
struct wormhole_profile;

typedef struct wormhole_environment wormhole_environment_t;
struct wormhole_environment {
	wormhole_environment_t *next;
	char *			name;

	struct wormhole_environment_config *config;

	int			nsfd;
	bool			failed;

	/* While setup is in process */
	struct {
		pid_t		child_pid;
		unsigned int	sock_id;
	} setup_ctx;

	/* Information on the sub-daemon for this context. */
	struct {
		char *		socket_name;
		pid_t		pid;
	} sub_daemon;
};

extern wormhole_environment_t *	wormhole_environment_find(const char *name);
extern struct wormhole_socket *	wormhole_environment_async_setup(wormhole_environment_t *, struct wormhole_profile *);
extern bool			wormhole_environment_async_complete(pid_t pid, int status);

#endif // _WORMHOLE_ENVIRONMENT_H
