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
#include <glob.h>

#include "wormhole.h"
#include "tracing.h"
#include "profiles.h"
#include "config.h"
#include "runtime.h"
#include "server.h"
#include "socket.h"
#include "util.h"

static wormhole_profile_t *	wormhole_profiles;
static wormhole_environment_t *	wormhole_environments;
static const char *		wormhole_client_path;

static bool			__wormhole_profiles_configure_environments(struct wormhole_environment_config *list);
static bool			__wormhole_profiles_configure_profiles(struct wormhole_profile_config *list);

static wormhole_environment_t *	wormhole_environment_new(const char *name);
static wormhole_profile_t *	wormhole_profile_new(const char *name);

/*
 * Initialize our internal data structures from config
 */
bool
wormhole_profiles_configure(struct wormhole_config *cfg)
{
	wormhole_client_path = cfg->client_path;
	if (wormhole_client_path == NULL)
		wormhole_client_path = WORMHOLE_CLIENT_PATH;

	__wormhole_profiles_configure_environments(cfg->environments);
	__wormhole_profiles_configure_profiles(cfg->profiles);
	return true;
}

wormhole_environment_t *
__wormhole_environment_from_config(struct wormhole_environment_config *cfg)
{
	wormhole_environment_t *env;

	env = wormhole_environment_new(cfg->name);
	env->config = cfg;

	return env;
}

bool
__wormhole_profiles_configure_environments(struct wormhole_environment_config *list)
{
	wormhole_environment_t **tail = &wormhole_environments;
	struct wormhole_environment_config *cfg;

	for (cfg = list; cfg; cfg = cfg->next) {
		wormhole_environment_t *env;

		if (!(env = __wormhole_environment_from_config(cfg)))
			return false;

		*tail = env;
		tail = &env->next;
	}

	return true;
}

static wormhole_profile_t *
__wormhole_profile_from_config(struct wormhole_profile_config *cfg)
{
	wormhole_environment_t *env = NULL;
	wormhole_profile_t *profile;

	if (cfg->environment) {
		if ((env = wormhole_environment_find(cfg->environment)) == NULL) {
			log_error("Profile %s references environment \"%s\", which does not exist",
					cfg->name, cfg->environment);
			return NULL;
		}
	}

	profile = wormhole_profile_new(cfg->name);
	profile->config = cfg;
	profile->environment = env;

	return profile;
}

bool
__wormhole_profiles_configure_profiles(struct wormhole_profile_config *list)
{
	wormhole_profile_t **tail = &wormhole_profiles;
	struct wormhole_profile_config *cfg;

	for (cfg = list; cfg; cfg = cfg->next) {
		wormhole_profile_t *profile;

		if (!(profile = __wormhole_profile_from_config(cfg)))
			return false;

		*tail = profile;
		tail = &profile->next;
	}

	return true;
}

wormhole_profile_t *
wormhole_profile_new(const char *name)
{
	wormhole_profile_t *profile;

	profile = calloc(1, sizeof(*profile));
	profile->name = strdup(name);

	return profile;
}

wormhole_profile_t *
wormhole_profile_find(const char *argv0)
{
	wormhole_profile_t *profile;
	const char *name;

	name = wormhole_const_basename(argv0);
	if (name == NULL || *name == '\0') {
		log_error("Cannot detect basename of executable");
		return NULL;
	}

	for (profile = wormhole_profiles; profile; profile = profile->next) {
		if (!strcmp(name, profile->name))
			return profile;
	}

	return NULL;
}

static wormhole_environment_t *
wormhole_environment_new(const char *name)
{
	wormhole_environment_t *env;

	env = calloc(1, sizeof(*env));
	env->name = strdup(name);
	env->nsfd = -1;

	return env;
}

static void
wormhole_environment_set_fd(wormhole_environment_t *env, int fd)
{
	if (env->nsfd >= 0) {
		close(env->nsfd >= 0);
		env->nsfd = -1;
	}

	trace("Environment \"%s\": installing namespace fd %d", env->name, fd);
	env->nsfd = fd;
}

wormhole_environment_t *
wormhole_environment_find(const char *name)
{
	wormhole_environment_t *env;

	for (env = wormhole_environments; env; env = env->next) {
		if (!strcmp(env->name, name))
			return env;
	}

	return NULL;
}

wormhole_environment_t *
wormhole_environment_find_by_pid(pid_t pid)
{
	wormhole_environment_t *env;

	for (env = wormhole_environments; env; env = env->next) {
		if (env->setup_ctx.child_pid == pid)
			return env;
	}

	return NULL;
}


/*
 * Start a container for this image, and mount its file system.
 */
/* The following should be part of the container runtime facade */
static const char *
container_make_local_name(const char *image_name)
{
	static char local_buf[256];
	char *s;

	if (snprintf(local_buf, sizeof(local_buf), "wormhole_%s", image_name) >= sizeof(local_buf)) {
		log_error("Container image name \"%s\" is too long", image_name);
		return NULL;
	}

	if ((s = strchr(local_buf, ':')) != NULL)
		*s = '\0';

	while ((s = strchr(local_buf, '/')) != NULL)
		*s = '_';

	return local_buf;
}

static const char *
overlay_container_mount(const wormhole_environment_t *env, const char *container_image)
{
	const char *local_name;

	if (container_image == NULL) {
		log_error("Environment \"%s\" does not have a container image defined", env->name);
		return NULL;
	}

	if (!(local_name = container_make_local_name(container_image)))
		return NULL;

	if (!wormhole_container_exists(local_name)) {
		if (!wormhole_container_start(container_image, local_name))
			return NULL;
	}

	return wormhole_container_mount(local_name);
}

static bool
overlay_container_unmount(const wormhole_environment_t *env, const char *container_image, const char *mount_point)
{
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

/*
 * pathinfo related functions
 */
static const char *
pathinfo_type_string(int type)
{
	switch (type) {
	case WORMHOLE_PATH_TYPE_HIDE:
		return "HIDE";
	case WORMHOLE_PATH_TYPE_BIND:
		return "BIND";
	case WORMHOLE_PATH_TYPE_BIND_CHILDREN:
		return "BIND_CHILDREN";
	case WORMHOLE_PATH_TYPE_OVERLAY:
		return "OVERLAY";
	case WORMHOLE_PATH_TYPE_OVERLAY_CHILDREN:
		return "OVERLAY_CHILDREN";
	case WORMHOLE_PATH_TYPE_WORMHOLE:
		return "WORMHOLE";
	}

	return "UNKNOWN";
}

static bool
_pathinfo_bind_one(wormhole_environment_t *environment, const char *source, const char *target)
{
	if (mount(source, target, NULL, MS_BIND, NULL) < 0) {
		log_error("%s: unable to bind mount %s to %s: %m", environment->name, source, target);
		return false;
	}

	trace2("%s: bind mounted %s to %s", environment->name, source, target);
	return true;
}

static bool
_pathinfo_overlay_one(wormhole_environment_t *environment,
		const char *source, const char *target,
		const char *workdir)
{
	/* Overlay "source" on top of "target" and mount at path "target" */
	return fsutil_mount_overlay(target, source, workdir, target);
}

static bool
pathinfo_bind_path(wormhole_environment_t *environment, const struct path_info *pi,
			const char *overlay_root,
			const char *dest, const char *source)
{
	trace2("%s(%s, %s)", __func__, dest, source);
	return _pathinfo_bind_one(environment, source, dest);
}

static bool
pathinfo_overlay_path(wormhole_environment_t *environment, const struct path_info *pi,
			const char *overlay_root,
			const char *dest, const char *source)
{
	char workdir[PATH_MAX];

	trace2("%s(%s, %s)", __func__, dest, source);

	snprintf(workdir, sizeof(workdir), "%s/work%s", overlay_root, dest);
	if (fsutil_makedirs(workdir, 0755) < 0) {
		log_error("Failed to create overlay workdir for %s at %s", dest, workdir);
		return false;
	}

	return _pathinfo_overlay_one(environment, source, dest, workdir);
}

static bool
pathinfo_create_overlay(const char *tempdir, const char *where)
{
	char upper[PATH_MAX], lower[PATH_MAX], work[PATH_MAX];

	snprintf(lower, sizeof(lower), "%s/lower", tempdir);
	snprintf(upper, sizeof(upper), "%s/upper", tempdir);
	snprintf(work, sizeof(work), "%s/work", tempdir);

	if (symlink(where, lower) < 0) {
		log_error("symlink(%s, %s): %m", where, lower);
		return false;
	}
	if (mkdir(upper, 0755) < 0) {
		log_error("mkdir(%s): %m", upper);
		return false;
	}
	if (mkdir(work, 0755) < 0) {
		log_error("mkdir(%s): %m", work);
		return false;
	}

	return fsutil_mount_overlay(lower, upper, work, where);
}

static bool
pathinfo_bind_children(wormhole_environment_t *environment, const struct path_info *pi,
		const char *overlay_root,
		const char *dest, const char *source)
{
	struct fsutil_tempdir td;
	const char *tempdir;
	struct dirent *d;
	DIR *dirfd;
	unsigned int num_mounted = 0;
	bool ok = false;

	trace2("%s(%s, %s)", __func__, dest, source);

	dirfd = opendir(source);
	if (dirfd == NULL) {
		log_error("%s: unable to open dir %s: %m", environment->name, source);
		return false;
	}

	fsutil_tempdir_init(&td);

	tempdir = fsutil_tempdir_path(&td);
	if (!pathinfo_create_overlay(tempdir, dest)) {
		log_error("unable to create overlay at \"%s\"", dest);
		goto out;
	}

	while ((d = readdir(dirfd)) != NULL) {
		char source_entry[PATH_MAX], target_entry[PATH_MAX];

		if (d->d_type != DT_DIR && d->d_type != DT_REG)
			continue;
		if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || d->d_name[1] == '.'))
			continue;

		/* printf("Trying to mount %s from %s to %s\n", d->d_name, source, dest); */
		snprintf(source_entry, sizeof(source_entry), "%s/%s", source, d->d_name);
		snprintf(target_entry, sizeof(target_entry), "%s/%s", dest, d->d_name);

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

		if (!_pathinfo_bind_one(environment, source_entry, target_entry))
			goto out;

		num_mounted ++;
	}

	trace("Mounted %u entries", num_mounted);
	ok = true;

out:
	fsutil_tempdir_cleanup(&td);
	if (dirfd)
		closedir(dirfd);
	return ok;
}

static bool
pathinfo_bind_wormhole(wormhole_environment_t *environment, const struct path_info *pi)
{
	trace2("%s(%s)", __func__, pi->path);
	return _pathinfo_bind_one(environment, wormhole_client_path, pi->path);
}

static bool
pathinfo_process_glob(wormhole_environment_t *env, const struct path_info *pi, const char *overlay_root,
			bool (*func)(wormhole_environment_t *env, const struct path_info *pi, const char *overlay_root, const char *dest, const char *source))
{
	bool retval = false;
	unsigned int overlay_path_len;
	char pattern[PATH_MAX];
	glob_t globbed;
	size_t n;
	int r;

	trace("pathinfo_process_glob(overlay_root=%s, path=%s)", overlay_root, pi->path);

	/* We check for this in the config file parsing code, so an assert is good enough here. */
	assert(pi->path[0] == '/');
	snprintf(pattern, sizeof(pattern), "%s%s", overlay_root, pi->path);

	r = glob(pattern, GLOB_NOSORT | GLOB_NOMAGIC | GLOB_TILDE, NULL, &globbed);
	if (r != 0) {
		/* I'm globsmacked. Why did it fail? */
		log_error("pathinfo expansion failed, glob(%s) returns %d", pattern, r);
		goto done;
	}

	overlay_path_len = strlen(overlay_root);

	for (n = 0; n < globbed.gl_pathc; ++n) {
		const char *source, *dest;

		source = globbed.gl_pathv[n];
		if (strncmp(source, overlay_root, overlay_path_len) != 0
		 || source[overlay_path_len] != '/') {
			log_error("%s: strange - glob expansion of %s returned path name %s", __func__,
					pattern, source);
			goto done;
		}
		dest = source + overlay_path_len;

		if (!func(env, pi, overlay_root, dest, source))
			goto done;
	}

	retval = true;

done:
	globfree(&globbed);
	return retval;
}

static bool
pathinfo_process(wormhole_environment_t *env, const struct path_info *pi, const char *overlay_root)
{
	if (pi->type == WORMHOLE_PATH_TYPE_HIDE) {
		/* hiding is not yet implemented */
		log_error("Environment %s: do not know how to hide %s - no yet implemented", env->name, pi->path);
		return false;
	}

	if (overlay_root == NULL) {
		log_error("Environment %s: requested overlay for \"%s\", but no image or directory given", env->name, pi->path);
		return false;
	}

	switch (pi->type) {
	case WORMHOLE_PATH_TYPE_BIND:
		return pathinfo_process_glob(env, pi, overlay_root, pathinfo_bind_path);

	case WORMHOLE_PATH_TYPE_BIND_CHILDREN:
		return pathinfo_process_glob(env, pi, overlay_root, pathinfo_bind_children);

	case WORMHOLE_PATH_TYPE_OVERLAY:
		return pathinfo_process_glob(env, pi, overlay_root, pathinfo_overlay_path);

#if 0
	case WORMHOLE_PATH_TYPE_OVERLAY_CHILDREN:
		return pathinfo_process_glob(env, pi, overlay_root, pathinfo_overlay_children);
#endif

	case WORMHOLE_PATH_TYPE_WORMHOLE:
		return pathinfo_bind_wormhole(env, pi);

	default:
		log_error("Environment %s: unsupported path_info type %d", env->name, pi->type);
		return false;
	}
}

/*
 * Some overlays contain shared libraries. Maintain a separate ld.so.cache inside the layer.
 */
static bool
wormhole_overlay_ldconfig(wormhole_environment_t *env, const struct wormhole_overlay_config *overlay, const char *overlay_root)
{
	char overlay_etc[PATH_MAX];
	int verdict;

	snprintf(overlay_etc, sizeof(overlay_etc), "%s/etc", overlay_root);
	if (fsutil_makedirs(overlay_etc, 0755) < 0) {
		log_error("Environment %s: unable to create /etc directory for ld.so.cache", env->name);
		return false;
	}

	snprintf(overlay_etc, sizeof(overlay_etc), "%s/etc/ld.so.cache", overlay_root);
	verdict = fsutil_inode_compare("/etc/ld.so.cache", overlay_etc);

	/* If the overlay has its own version of /etc/ld.so.cache that has a more recent time
	 * stamp than the "real" one, there's no need to regenerate.
	 */
	if (verdict < 0 || !(verdict & FSUTIL_FILE_YOUNGER)) {
		char command[PATH_MAX];

		trace2("Environment %s: updating ld.so.cache", env->name);

		/* We do not re-create links. The links inside the layer should be
		 * up-to-date (hopefully!); and touching links in layers below may
		 * fail. */
		snprintf(command, sizeof(command), "ldconfig -vX -C %s", overlay_etc);

		if (system(command) != 0)
			log_warning("Environment %s: ldconfig failed", env->name);
	} else {
		trace2("Environment %s: ld.so.cache exists and is recent - not updating it", env->name);
	}

	/* Now bind mount it */
	return _pathinfo_bind_one(env, overlay_etc, "/etc/ld.so.cache");
}

static bool
wormhole_overlay_setup(wormhole_environment_t *env, const struct wormhole_overlay_config *overlay)
{
	const char *overlay_root;
	const struct path_info *pi;
	bool mounted = false;
	bool ok = true;
	unsigned int i;

	if (overlay->npaths == 0)
		return true;

	if (overlay->image) {
		/* The overlay is provided via a container image. */
		overlay_root = overlay_container_mount(env, overlay->image);
		if (!overlay_root)
			log_error("Environment %s: unable to mount container \"%s\"", env->name, overlay->image);
		mounted = true;
	} else {
		assert(overlay->directory);
		overlay_root = overlay->directory;
	}

	for (i = 0, pi = overlay->path; ok && i < overlay->npaths; ++i, ++pi) {
		trace("Environment %s: pathinfo %s: %s", env->name,
				pathinfo_type_string(pi->type), pi->path);
		ok = pathinfo_process(env, pi, overlay_root);
		trace("  result: %sok", ok? "" : "not ");
	}

	if (ok && overlay->use_ldconfig)
		ok = wormhole_overlay_ldconfig(env, overlay, overlay_root);

	if (mounted && !overlay_container_unmount(env, overlay->image, overlay_root)) {
		log_error("Environment %s: unable to unmount \"%s\": %m", env->name, overlay_root);
		ok = false;
	}

	return ok;
}

static bool
wormhole_environment_setup(wormhole_environment_t *env)
{
	struct wormhole_overlay_config *overlay;

	if (env->failed)
		return false;

	for (overlay = env->config->overlays; overlay; overlay = overlay->next) {
		if (!wormhole_overlay_setup(env, overlay))
			return false;
	}

	return true;
}

int
wormhole_profile_setup(wormhole_profile_t *profile)
{
	struct stat stb1, stb2;

	/* No environment or no overlays - use the root context */
	if (profile->environment == NULL)
		return 0;

	assert(profile->environment->config);
	if (profile->environment->config->overlays == NULL)
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

	if (!wormhole_environment_setup(profile->environment))
		return -1;

	return 0;
}

const char *
wormhole_profile_command(const wormhole_profile_t *profile)
{
	return profile->config->command;
}

int
wormhole_profile_namespace_fd(const wormhole_profile_t *profile)
{
	wormhole_environment_t *env;
	int fd = -1;

	if ((env = profile->environment) == NULL) {
		trace("Profile %s: returning namespace fd for host namespace", profile->name);
		fd = open("/proc/self/ns/mnt", O_RDONLY);
		if (fd < 0)
			log_error("Unable to open /proc/self/ns/mnt: %m");
	} else
	if (!env->failed && env->nsfd >= 0) {
		trace("Profile %s: returning namespace fd for environment \"%s\"", profile->name, env->name);
		fd = dup(env->nsfd);
		if (fd < 0)
			log_error("Unable to dup() namespace fd: %m");
	}

	return fd;
}

/*
 * Server side socket handler for receiving namespace fds passed back to us by
 * the async profile setup code.
 */
static bool
wormhole_environment_fd_received(wormhole_socket_t *s, struct buf *bp, int fd)
{
	wormhole_environment_t *env;

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

static wormhole_socket_t *
wormhole_environment_create_fd_receiver(wormhole_environment_t *env, int fd)
{
	static struct wormhole_app_ops app_ops = {
		.received = wormhole_environment_fd_received,
		// .closed = wormhole_environment_fd_closed,
	};
	wormhole_socket_t *sock;

	sock = wormhole_connected_socket_new(fd, 0, 0);
	sock->app_ops = &app_ops;

	env->setup_ctx.sock_id = sock->id;
	return sock;
}

wormhole_socket_t *
wormhole_environment_async_setup(wormhole_environment_t *env, wormhole_profile_t *profile)
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

	if (wormhole_profile_setup(profile) < 0)
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
	wormhole_environment_t *env;

	if (!(env = wormhole_environment_find_by_pid(pid)))
		return false;

	env->setup_ctx.child_pid = 0;

	if (!wormhole_child_status_okay(status)) {
		log_error("Environment \"%s\": setup process failed (%s)", env->name,
				wormhole_child_status_describe(status));
		env->failed = true;
	} else if (!wormhole_start_sub_daemon(env)) {
		trace("Environment \"%s\": failed to start subspace daemon", env->name);
		env->failed = true;
	} else {
		trace("Environment \"%s\": setup process complete", env->name);
		env->failed = false;
	}

	return true;
}
