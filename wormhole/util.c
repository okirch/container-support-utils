/*
 * utility functions for wormhole
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

#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>

#include "tracing.h"
#include "util.h"


const char *
wormhole_concat_argv(int argc, char **argv)
{
	static char buffer[8192];
	unsigned int pos, n;
	int i;

	if (argc < 0) {
		for (argc = 0; argv[argc]; ++argc)
			;
	}

	pos = 0;
	for (i = 0; i < argc; ++i) {
		const char *s = argv[i];

		n = strlen(s);

		/* We need to be able to include 3 additional chars (space, and 2x") plus
		 * the ellipsis string " ..."
		 */
		if (pos + n >= sizeof(buffer) - 20) {
			strcpy(buffer + pos, " ...");
			break;
		}

		if (i)
			buffer[pos++] = ' ';
		if (strchr(s, ' ') == NULL) {
			strcpy(buffer + pos, s);
			pos += n;
		} else {
			buffer[pos++] = '"';
			strcpy(buffer + pos, s);
			pos += n;
			buffer[pos++] = '"';
		}
	}

	return buffer;
}

const char *
wormhole_const_basename(const char *path)
{
	const char *s;

	if (path == NULL)
		return NULL;

	s = strrchr(path, '/');
	if (s == NULL)
		return path;

	/* Path ends with a slash */
	if (s[1] == '\0')
		return NULL;

	return &s[1];
}

pid_t
wormhole_fork_with_socket(int *fdp)
{
	int fdpair[2];
	pid_t pid;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fdpair) < 0) {
		log_error("%s: socketpair failed: %m", __func__);
		return -1;
	}

	if ((pid = fork()) < 0) {
		log_error("%s: fork failed: %m", __func__);
		close(fdpair[0]);
		close(fdpair[1]);
		return -1;
	}

	if (pid > 0) {
		*fdp = fdpair[0];
		close(fdpair[1]);
	} else {
		close(fdpair[0]);
		*fdp = fdpair[1];
	}

	return pid;
}

/*
 * Reap exited children
 */
static bool	have_waiting_children = false;

static void
reaper(int sig)
{
	have_waiting_children = true;
}

void
wormhole_install_sigchild_handler(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = reaper;
	sigaction(SIGCHLD, &act, NULL);
}

pid_t
wormhole_get_exited_child(int *status)
{
	pid_t pid;

	if (!have_waiting_children)
		return -1;

	have_waiting_children = false;
	pid = waitpid(-1, status, WNOHANG);

	if (pid < 0 && errno != ECHILD)
		return pid;

	have_waiting_children = true;
	return pid;
}

bool
wormhole_child_status_okay(int status)
{
	if (WIFSIGNALED(status))
		return false;

	if (!WIFEXITED(status))
		return false;

	return WEXITSTATUS(status) == 0;
}

const char *
wormhole_child_status_describe(int status)
{
	static char msgbuf[128];

	if (WIFSIGNALED(status)) {
		snprintf(msgbuf, sizeof(msgbuf), "crashed with signal %d", WTERMSIG(status));
	} else if (WIFEXITED(status)) {
		snprintf(msgbuf, sizeof(msgbuf), "exited with status %d", WEXITSTATUS(status));
	} else {
		snprintf(msgbuf, sizeof(msgbuf), "weird status word 0x%x", status);
	}
	return msgbuf;
}

void
fsutil_tempdir_init(struct fsutil_tempdir *td)
{
	memset(td, 0, sizeof(*td));
}

char *
fsutil_tempdir_path(struct fsutil_tempdir *td)
{
	if (td->path == NULL) {
		char dirtemplate[] = "/tmp/mounts.XXXXXX";
		char *tempdir;

		tempdir = mkdtemp(dirtemplate);
		if (tempdir == NULL)
			log_fatal("Unable to create tempdir: %m\n");

		td->path = strdup(tempdir);

		trace("Mounting tmpfs on %s\n", tempdir);
		if (mount("tmpfs", tempdir, "tmpfs", 0, NULL) < 0)
			log_fatal("Unable to mount tmpfs in container: %m\n");

		td->mounted = true;
	}

	return td->path;
}

int
fsutil_tempdir_cleanup(struct fsutil_tempdir *td)
{
	if (td->path == NULL)
		return 0;

	if (td->mounted && umount(td->path) < 0) {
                log_error("Unable to unmount %s: %m", td->path);
		return -1;
        }

        if (rmdir(td->path) < 0) {
                log_error("Unable to remove temporary mountpoint %s: %m", td->path);
		return -1;
        }

	free(td->path);
	memset(td, 0, sizeof(*td));
	return 0;
}

static int
__fsutil_makedirs(char *path, int mode)
{
	char *slash;
	int ret;

	/* trace("%s(%s)", __func__, path); */
	if (mkdir(path, mode) == 0)
		return 0;

	slash = strrchr(path, '/');
	while (slash > path && slash[-1] == '/')
		--slash;
	slash[0] = '\0';

	ret = __fsutil_makedirs(path, mode);

	slash[0] = '/';
	if (ret >= 0)
		ret = mkdir(path, mode);

	return ret;
}

int
fsutil_makedirs(const char *path, int mode)
{
	char path_copy[PATH_MAX];

	if (mkdir(path, mode) == 0 || errno == EEXIST)
		return 0;

	if (errno != ENOENT)
		return -1;

	if (strlen(path) + 1 > sizeof(path_copy)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	strcpy(path_copy, path);
	return __fsutil_makedirs(path_copy, mode);
}

int
fsutil_create_empty(const char *path)
{
	int fd;

	if ((fd = open(path, O_WRONLY|O_CREAT, 0644)) < 0)
		return -1;
	close(fd);
	return 0;
}

bool
fsutil_check_path_prefix(const char *path, const char *potential_prefix)
{
	unsigned int len;

	if (potential_prefix == NULL || path == NULL)
		return false;

	len = strlen(potential_prefix);
	if (strncmp(path, potential_prefix, len) != 0)
		return false;

	return path[len] == 0 || path[len] == '/';
}

/*
 * Rather special kind of file comparison
 */
int
fsutil_inode_compare(const char *path1, const char *path2)
{
	struct stat stb1, stb2;
	int verdict = FSUTIL_FILE_IDENTICAL;

	if (lstat(path1, &stb1) < 0)
		return FSUTIL_MISMATCH_MISSING;
	if (lstat(path2, &stb2) < 0)
		return FSUTIL_MISMATCH_MISSING;


	if ((stb1.st_mode & S_IFMT) != (stb2.st_mode & S_IFMT))
		return FSUTIL_MISMATCH_TYPE;

	if (S_ISREG(stb1.st_mode)) {
		if (stb1.st_size < stb2.st_size)
			verdict |= FSUTIL_FILE_SMALLER;
		else if (stb1.st_size > stb2.st_size)
			verdict |= FSUTIL_FILE_BIGGER;
	}

	if (stb1.st_mtime < stb2.st_mtime)
		verdict |= FSUTIL_FILE_YOUNGER;
	else if (stb1.st_mtime > stb2.st_mtime)
		verdict |= FSUTIL_FILE_OLDER;

	return verdict;
}

bool
fsutil_mount_overlay(const char *lowerdir, const char *upperdir, const char *workdir, const char *target)
{
	char options[3 * PATH_MAX];

	snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s",
			lowerdir, upperdir, workdir);

	if (mount("wormhole", target, "overlay", 0, options) < 0) {
		log_error("Cannot mount overlayfs at %s: %m", target);
		return false;
	}

	trace2("mounted overlay of %s and %s to %s", lowerdir, upperdir, target);
	return true;
}

