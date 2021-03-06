/*
 * util.h
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

#ifndef _WORMHOLE_UTIL_H
#define _WORMHOLE_UTIL_H

#include <sys/types.h>

struct fsutil_tempdir {
	char *		path;
	bool		mounted;
};


extern const char *		wormhole_const_basename(const char *path);
extern const char *		wormhole_concat_argv(int argc, char **argv);
extern pid_t			wormhole_fork_with_socket(int *fdp);
extern void			wormhole_install_sigchild_handler(void);
extern pid_t			wormhole_get_exited_child(int *status);
extern bool			wormhole_child_status_okay(int status);
extern const char *		wormhole_child_status_describe(int status);

extern void			fsutil_tempdir_init(struct fsutil_tempdir *td);
extern char *			fsutil_tempdir_path(struct fsutil_tempdir *td);
extern int			fsutil_tempdir_cleanup(struct fsutil_tempdir *td);

extern int			fsutil_makedirs(const char *path, int mode);
extern int			fsutil_create_empty(const char *path);
extern bool			fsutil_check_path_prefix(const char *path, const char *potential_prefix);

extern bool			fsutil_mount_overlay(const char *lowerdir,
					const char *upperdir,
					const char *workdir,
					const char *target);

enum {
	FSUTIL_MISMATCH_TYPE = -2,
	FSUTIL_MISMATCH_MISSING = -1,
	FSUTIL_FILE_IDENTICAL = 0,

	/* The rest are bits that can be tested for */
	FSUTIL_FILE_SMALLER	= 0x001,
	FSUTIL_FILE_BIGGER	= 0x002,
	FSUTIL_FILE_YOUNGER	= 0x004,
	FSUTIL_FILE_OLDER	= 0x008,
};

extern int			fsutil_inode_compare(const char *path1, const char *path2);

#endif // _WORMHOLE_UTIL_H
