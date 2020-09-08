/*
 * profile handling for wormhole
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

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "tracing.h"
#include "profiles.h"
#include "runtime.h"
#include "socket.h"
#include "util.h"

static struct wormhole_environment *	wormhole_environments;

static struct profile		dummy_profiles[] = {
	{
		.name =			"ps",
		.command =		"/usr/bin/ps",
	},
	{
		.name =			"yast2",
		.command =		"/sbin/yast2",
		.container_image =	"okir/yast-testing",

		.path_info = {
			PATH_INFO_REPLACE("/usr/lib/perl5"),
			PATH_INFO_REPLACE("/usr/lib/YaST2"),
			PATH_INFO_REPLACE_CHILDREN("/usr/lib64"),
			// PATH_INFO_REPLACE("/usr/lib64/ruby"),
			PATH_INFO_REPLACE("/usr/share/YaST2"),
			PATH_INFO_REPLACE("/var/log/YaST2"),

			/* mount the wormhole client binary on /usr/bin/zypper so that
			 * zypper runs in the host context. */
			PATH_INFO_WORMHOLE("/usr/bin/zypper"),
			/* Same for rpm */
			PATH_INFO_WORMHOLE("/usr/bin/rpm"),
		},
	},
	{
		.name =			"zypper",
		.command =		"/usr/bin/zypper",
		/* No container, not path info - execute this in the root context */
	},
	{
		.name =			"rpm",
		.command =		"/usr/bin/rpm",
		/* No container, not path info - execute this in the root context */
	},
	{ NULL }
};

struct profile *
profile_find(const char *argv0)
{
	struct profile *profile;
	const char *name;

	name = const_basename(argv0);
	if (name == NULL || *name == '\0') {
		log_error("Cannot detect basename of executable");
		return NULL;
	}

	for (profile = dummy_profiles; profile->name; ++profile) {
		if (!strcmp(name, profile->name))
			return profile;
	}

	return NULL;
}

/*
 * Start a container for this image, and mount its file system.
 */
static const char *
profile_make_local_name(struct profile *profile)
{
	static char local_buf[128];
	char *s;

	if (!profile->container_image) {
		log_error("Profile \"%s\" does not have a container image defined", profile->name);
		return NULL;
	}
	if (strlen(profile->container_image) >= sizeof(local_buf)) {
		log_error("Profile \"%s\": image name \"%s\" is too long", profile->name, profile->container_image);
		return NULL;
	}

	strcpy(local_buf, profile->container_image);

	if ((s = strchr(local_buf, ':')) != NULL)
		*s = '\0';

	while ((s = strchr(local_buf, '/')) != NULL)
		*s = '_';

	return local_buf;
}

bool
profile_mount(struct profile *profile)
{
	const char *local_name;
	const char *mount_point;

	if (profile->mount_point)
		return true;

	if (!(local_name = profile_make_local_name(profile)))
		return false;

	if (!wormhole_container_exists(local_name)) {
		if (!wormhole_container_start(profile->container_image, local_name))
			return false;
	}

	mount_point = wormhole_container_mount(local_name);
	if (!mount_point)
		return false;

	profile->mount_point = strdup(mount_point);

	return true;
}

void
dump_mtab(const char *msg)
{
	FILE *fp;
	char line[256];

	printf("== mtab %s ==", msg);
	fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		log_error("Unable to open /proc/mounts: %m");
		exit(7);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		printf("%s\n", line);
	}
	fclose(fp);
}


static char *
pathinfo_expand(const struct profile *profile, const char *path)
{
	static char expanded[PATH_MAX];

	if (!strncmp(path, "$ROOT/", 6)) {
		snprintf(expanded, sizeof(expanded), "%s/%s", profile->mount_point, path + 6);
	} else {
		strncpy(expanded, path, sizeof(expanded));
	}
	expanded[sizeof(expanded) - 1] = '\0';
	return expanded;
}

struct fsutil_tempdir {
	char *		path;
	bool		mounted;
};

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
_pathinfo_bind_one(struct profile *profile, const char *source, const char *target)
{
	if (mount(source, target, NULL, MS_BIND, NULL) < 0) {
		log_error("%s: unable to bind mount %s to %s: %m", profile->name, source, target);
		return -1;
	}

	trace("%s: bind mounted %s to %s", profile->name, source, target);
	return 0;
}

static int
pathinfo_bind_directory(struct profile *profile, struct path_info *pi, const char *source)
{
	return _pathinfo_bind_one(profile, source, pi->path);
}

static int
pathinfo_create_overlay(const char *tempdir, const char *where)
{
	char upper[PATH_MAX], lower[PATH_MAX], work[PATH_MAX];
	char options[3 * PATH_MAX];

	snprintf(lower, sizeof(lower), "%s/lower", tempdir);
	snprintf(upper, sizeof(upper), "%s/upper", tempdir);
	snprintf(work, sizeof(work), "%s/work", tempdir);

	if (symlink(where, lower) < 0) {
		log_error("symlink(%s, %s): %m", where, lower);
		return -1;
	}
	if (mkdir(upper, 0755) < 0) {
		log_error("mkdir(%s): %m", upper);
		return -1;
	}
	if (mkdir(work, 0755) < 0) {
		log_error("mkdir(%s): %m", work);
		return -1;
	}

	snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s",
			lower, upper, work);

	if (mount("foo", where, "overlay", 0, options) < 0) {
		log_error("Cannot mount overlayfs at %s: %m", where);
		return -1;
	}

	return 0;
}

static int
pathinfo_bind_children(struct profile *profile, struct path_info *pi, const char *source)
{
	struct fsutil_tempdir td;
	const char *tempdir;
	struct dirent *d;
	DIR *dirfd;
	int rv = -1;

	dirfd = opendir(source);
	if (dirfd == NULL) {
		log_error("%s: unable to open dir %s: %m", profile->name, source);
		return -1;
	}

	fsutil_tempdir_init(&td);

	tempdir = fsutil_tempdir_path(&td);
	if (pathinfo_create_overlay(tempdir, pi->path) < 0) {
		log_error("unable to create overlay at \"%s\"", pi->path);
		goto out;
	}

	while ((d = readdir(dirfd)) != NULL) {
		char source_entry[PATH_MAX], target_entry[PATH_MAX];

		if (d->d_type != DT_DIR && d->d_type != DT_REG)
			continue;
		if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || d->d_name[1] == '.'))
			continue;

		/* printf("Trying to mount %s from %s to %s\n", d->d_name, source, pi->path); */
		snprintf(source_entry, sizeof(source_entry), "%s/%s", source, d->d_name);
		snprintf(target_entry, sizeof(target_entry), "%s/%s", pi->path, d->d_name);

		/* FIXME: avoid mounting if source and target are exactly the same file;
		 * this happens a lot when you mount a /lib directory. */

		if (access(target_entry, F_OK) < 0 && errno == ENOENT) {
			if (d->d_type == DT_DIR)
				(void) mkdir(target_entry, 0700);
			else {
				int fd;

				fd = open(target_entry, O_CREAT, 0600);
				if (fd >= 0)
					close(fd);
			}
		}

		if (_pathinfo_bind_one(profile, source_entry, target_entry) < 0)
			goto out;
	}

	rv = 0;

out:
	fsutil_tempdir_cleanup(&td);
	if (dirfd)
		closedir(dirfd);
	return rv;
}

static int
pathinfo_process(struct profile *profile, struct path_info *pi)
{
	int (*bind_fn)(struct profile *, struct path_info *, const char *) = pathinfo_bind_directory;
	char *source;
	int len;

	if (pi->replace == NULL) {
		/* hiding is not yet implemented */
		log_error("%s: do not know how to hide %s - no yet implemented", profile->name, pi->path);
		return -1;
	}

	source = pathinfo_expand(profile, pi->replace);
	if (source == NULL) {
		log_error("%s: unable to expand \"%s\"", profile->name, pi->path);
		return -1;
	}

	len = strlen(source);
	if (len >= 2 && !strcmp(source + len - 2, "/*")) {
		bind_fn = pathinfo_bind_children;
		source[len-2] = '\0';
	}

	if (!strcmp(source, pi->path)) {
		log_error("%s: refusing to bind mount %s to %s", profile->name,
				source, pi->path);
		return -1;
	}

	return bind_fn(profile, pi, source);
}

int
profile_setup(struct profile *profile)
{
	struct path_info *pi;
	struct stat stb1, stb2;

	/* No image means: execute command in the host context */
	if (!profile->container_image)
		return 0;

	if (!profile_mount(profile))
		return -1;

	if (profile->path_info[0].path == NULL)
		return 0;

	if (mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL) == -1) {
		log_error("cannot make / private: %m");
		return -1;
	}

	if (stat("/proc/self/ns/mnt", &stb1) < 0) {
		log_error("stat(\"/proc/self/ns/mnt\") failed: %m");
		return -1;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		log_error("unshare(CLONE_NEWNS) failed: %m");
		return -1;
	}

	if (stat("/proc/self/ns/mnt", &stb2) < 0) {
		log_error("stat(\"/proc/self/ns/mnt\") failed: %m");
		return -1;
	}
	if (stb1.st_dev == stb2.st_dev && stb1.st_ino == stb2.st_ino) {
		log_error("Something is not quite right");
		return -1;
	}
#if 0
	printf("namespace before 0x%lx/%ld -> 0x%lx/%ld\n",
			stb1.st_dev, stb1.st_ino,
			stb2.st_dev, stb2.st_ino);
#endif

	for (pi = profile->path_info; pi->path; ++pi) {
		if (pathinfo_process(profile, pi) < 0)
			return -1;
	}

	return 0;
}

static struct wormhole_environment *
wormhole_environment_new(const char *name)
{
	struct wormhole_environment *env;

	env = calloc(1, sizeof(*env));
	env->name = strdup(name);
	env->nsfd = -1;

	env->next = wormhole_environments;
	wormhole_environments = env;

	return env;
}

static void
wormhole_environment_set_fd(struct wormhole_environment *env, int fd)
{
	if (env->nsfd >= 0) {
		close(env->nsfd >= 0);
		env->nsfd = -1;
	}

	trace("Environment \"%s\": installing namespace fd %d", env->name, fd);
	env->nsfd = fd;
}

struct wormhole_environment *
wormhole_environment_find(const char *name)
{
	struct wormhole_environment *env;

	for (env = wormhole_environments; env; env = env->next) {
		if (!strcmp(env->name, name))
			return env;
	}

	return wormhole_environment_new(name);
}

struct wormhole_environment *
wormhole_environment_find_by_pid(pid_t pid)
{
	struct wormhole_environment *env;

	for (env = wormhole_environments; env; env = env->next) {
		if (env->setup_ctx.child_pid == pid)
			return env;
	}

	return NULL;
}

/*
 * Server side socket handler for receiving namespace fds passed back to us by
 * the async profile setup code.
 */
static bool
wormhole_environment_fd_received(struct wormhole_socket *s, struct buf *bp, int fd)
{
	struct wormhole_environment *env;

	trace("%s(sock_id=%d)", __func__, s->id);
	if (fd < 0) {
		log_error("%s: missing file descriptor from client", __func__);
		return false;
	}

	for (env = wormhole_environments; env; env = env->next) {
		if (env->setup_ctx.sock_id == s->id) {
			/* We need to dup the file descriptor, as our caller will close it */
			wormhole_environment_set_fd(env, dup(fd));
			buf_zap(bp);
			return true;
		}
	}

	return false;
}

static struct wormhole_socket *
wormhole_environment_create_fd_receiver(struct wormhole_environment *env, int fd)
{
	static struct wormhole_app_ops app_ops = {
		.received = wormhole_environment_fd_received,
		// .closed = wormhole_environment_fd_closed,
	};
	struct wormhole_socket *sock;

	sock = wormhole_connected_socket_new(fd, 0, 0);
	sock->app_ops = &app_ops;

	env->setup_ctx.sock_id = sock->id;
	return sock;
}

struct wormhole_socket *
wormhole_environment_async_setup(struct wormhole_environment *env, struct profile *profile)
{
	pid_t pid;
	int nsfd, sock_fd;

	pid = wormhole_fork_with_socket(&sock_fd);
	if (pid < 0)
		return NULL;

	if (pid > 0) {
		env->setup_ctx.child_pid = pid;

		return wormhole_environment_create_fd_receiver(env, sock_fd);
	}

	if (profile_setup(profile) < 0)
                log_fatal("Failed to set up environment for %s", profile->name);

        nsfd = open("/proc/self/ns/mnt", O_RDONLY);
        if (nsfd < 0)
                log_fatal("Cannot open /proc/self/ns/mnt: %m");

	if (wormhole_socket_sendmsg(sock_fd, "", 1, nsfd) < 0)
		log_fatal("unable to send namespace fd to parent: %m");

	trace("Successfully set up environment \"%s\"", env->name);
	exit(0);
}

bool
wormhole_environment_async_complete(pid_t pid, int status)
{
	struct wormhole_environment *env;

	if (!(env = wormhole_environment_find_by_pid(pid)))
		return false;

	env->setup_ctx.child_pid = 0;

	if (!wormhole_child_status_okay(status)) {
		log_error("Environment \"%s\": setup process failed (%s)", env->name,
				wormhole_child_status_describe(status));
		env->failed = true;
	} else {
		trace("Environment \"%s\": setup process complete", env->name);
		env->failed = false;
	}

	return true;
}
