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

#include <sys/wait.h>
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
#include <libgen.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>

#include "tracing.h"
#include "profiles.h"
#include "util.h"

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
	char *fullname;
	char *name;

	fullname = strdup(argv0);

	name = basename(fullname);
	if (name == NULL || *name == '\0') {
		fprintf(stderr, "Cannot detect basename of executable\n");
		return NULL;
	}

	for (profile = dummy_profiles; profile->name; ++profile) {
		if (!strcmp(name, profile->name))
			return profile;
	}

	return NULL;
}

/*
 * Run a podman command and capture (a single line of) output
 */
#define PODMAN_MAX_ARGS	64

static char **
podman_build_cmd(const char *subcmd, va_list ap)
{
	static const char *argv[PODMAN_MAX_ARGS];
	char *s;
	int i = 0;

	argv[i++] = "podman";
	argv[i++] = subcmd;

	while ((s = va_arg(ap, char *)) != NULL) {
		if (i + 2 >= PODMAN_MAX_ARGS) {
			fprintf(stderr, "Too many arguments to podman\n");
			return NULL;
		}
		argv[i++] = s;
	}
	argv[i] = NULL;

	return (char **) argv;
}

static int
podman_exec(char **argv, int *fdp)
{
	int pfd[2];
	pid_t pid;

	if (true)
		log_debug("About to run: %s", concat_argv(-1, argv));

	if (fdp == NULL) {
		pid = fork();
		if (pid < 0) {
			perror("podman fork");
			return -1;
		}

		if (pid == 0) {
			execvp("podman", argv);
			perror("Cannot execute podman");
			exit(5);
		}
	} else {
		if (pipe(pfd) < 0) {
			perror("podman pipe");
			return -1;
		}

		pid = fork();
		if (pid < 0) {
			perror("podman fork");
			close(pfd[0]);
			close(pfd[1]);
			return -1;
		}

		if (pid == 0) {
			close(pfd[0]);
			dup2(pfd[1], 1);
			dup2(pfd[1], 2);
			execvp("podman", argv);
			perror("Cannot execute podman");
			exit(5);
		}

		close(pfd[1]);
		*fdp = pfd[0];
	}

	return pid;
}

static inline bool
chop(char *line)
{
	line[strcspn(line, "\n")] = '\0';
	return line[0] != '\0';
}

static char *
podman_read_response(int fd)
{
	static char buffer[1024];
	char more[1024], *resp;
	bool first = true;
	FILE *fp;

	fp = fdopen(fd, "r");

	resp = fgets(buffer, sizeof(buffer), fp);
	if (resp)
		chop(resp);

	while (fgets(more, sizeof(more), fp)) {
		if (chop(more)) {
			if (first) {
				fprintf(stderr, "Warning; additional output from podman:\n");
				first = false;
			}
			fprintf(stderr, "%s\n", more);
		}
	}

	fclose(fp);
	return resp;
}

static int
podman_wait(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) < 0) {
		perror("podman waitpid");
		if (errno == ECHILD)
			return -1;
	}

	if (WIFSIGNALED(status)) {
		fprintf(stderr, "podman command crashed with signal %d\n", WTERMSIG(status));
		return -1;
	}

	if (!WIFEXITED(status)) {
		fprintf(stderr, "something happened to podman command - status %d\n", status);
		return -1;
	}

	return WEXITSTATUS(status);
}

static char *
podman_run_and_capture(char *subcmd, ...)
{
	va_list ap;
	char **argv;
	char *response;
	int fd, exitcode;
	pid_t pid;

	va_start(ap, subcmd);
	argv = podman_build_cmd(subcmd, ap);
	va_end(ap);

	if (argv == NULL)
		return NULL;

	pid = podman_exec(argv, &fd);
	if (pid < 0)
		return NULL;

	response = podman_read_response(fd);

	exitcode = podman_wait(pid);

	if (exitcode < 0)
		return NULL;

	if (exitcode != 0) {
		fprintf(stderr, "podman %s exited with non-zero status %d\n", subcmd, exitcode);
		return NULL;
	}

	return response;
}

static bool
podman_run(char *subcmd, ...)
{
	va_list ap;
	char **argv;
	int exitcode;
	pid_t pid;

	va_start(ap, subcmd);
	argv = podman_build_cmd(subcmd, ap);
	va_end(ap);

	if (argv == NULL)
		return NULL;

	pid = podman_exec(argv, NULL);
	if (pid < 0)
		return NULL;

	exitcode = podman_wait(pid);
	if (exitcode < 0)
		return NULL;

	return exitcode == 0;
}

static bool
podman_container_exists(const char *name)
{
	return podman_run("container", "exists", name, NULL);
}

static bool
podman_start(const char *image_spec, const char *container_name)
{
	return podman_run("create", "--name", container_name, image_spec, NULL);
}

static const char *
podman_mount(const char *container_name)
{
	return podman_run_and_capture("mount", container_name, NULL);
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
		fprintf(stderr, "Profile \"%s\" does not have a container image defined\n", profile->name);
		return NULL;
	}
	if (strlen(profile->container_image) >= sizeof(local_buf)) {
		fprintf(stderr, "Profile \"%s\": image name \"%s\" is too long\n", profile->name, profile->container_image);
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

	if (!podman_container_exists(local_name)) {
		if (!podman_start(profile->container_image, local_name))
			return false;
	}

	mount_point = podman_mount(local_name);
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
		perror("/proc/mounts");
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
                log_error("Unable to unmount %s: %m\n", td->path);
		return -1;
        }

        if (rmdir(td->path) < 0) {
                log_error("Unable to remove temporary mountpoint %s: %m\n", td->path);
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
		fprintf(stderr, "%s: unable to bind mount %s to %s: %m\n", profile->name, source, target);
		return -1;
	}

	fprintf(stderr, "%s: bind mounted %s to %s\n", profile->name, source, target);
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
		log_error("symlink(%s, %s): %m\n", where, lower);
		return -1;
	}
	if (mkdir(upper, 0755) < 0) {
		log_error("mkdir(%s): %m\n", upper);
		return -1;
	}
	if (mkdir(work, 0755) < 0) {
		log_error("mkdir(%s): %m\n", work);
		return -1;
	}

	snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s",
			lower, upper, work);

	if (mount("foo", where, "overlay", 0, options) < 0) {
		log_error("Cannot mount overlayfs at %s: %m\n", where);
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
		log_error("%s: unable to open dir %s: %m\n", profile->name, source);
		return -1;
	}

	fsutil_tempdir_init(&td);

	tempdir = fsutil_tempdir_path(&td);
	if (pathinfo_create_overlay(tempdir, pi->path) < 0) {
		log_error("unable to create overlay at \"%s\"\n", pi->path);
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
		fprintf(stderr, "%s: do not know how to hide %s\n", profile->name, pi->path);
		return -1;
	}

	source = pathinfo_expand(profile, pi->replace);
	if (source == NULL) {
		fprintf(stderr, "%s: unable to expand \"%s\"\n", profile->name, pi->path);
		return -1;
	}

	len = strlen(source);
	if (len >= 2 && !strcmp(source + len - 2, "/*")) {
		bind_fn = pathinfo_bind_children;
		source[len-2] = '\0';
	}

	if (!strcmp(source, pi->path)) {
		fprintf(stderr, "%s: refusing to bind mount %s to %s\n", profile->name,
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
		perror("cannot make / private");
		return -1;
	}

	if (stat("/proc/self/ns/mnt", &stb1) < 0) {
		perror("stat(\"/proc/self/ns/mnt\")");
		return -1;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		perror("unshare(CLONE_NEWNS) failed");
		return -1;
	}

	if (stat("/proc/self/ns/mnt", &stb2) < 0) {
		perror("stat(\"/proc/self/ns/mnt\")");
		return -1;
	}
	if (stb1.st_dev == stb2.st_dev && stb1.st_ino == stb2.st_ino) {
		fprintf(stderr, "Something is not quite right\n");
		return -1;
	}
	printf("namespace before 0x%lx/%ld -> 0x%lx/%ld\n",
			stb1.st_dev, stb1.st_ino,
			stb2.st_dev, stb2.st_ino);

	/* exit(999); */

	for (pi = profile->path_info; pi->path; ++pi) {
		// dump_mtab("before mount");
		if (pathinfo_process(profile, pi) < 0)
			return -1;
		// dump_mtab("after mount");
		// return -1;
	}

	if (access("/usr/lib64/libQt5Core.so.5.9", F_OK) < 0)
		perror("/usr/lib64/libQt5Core.so.5.9");
	if (access("/usr/lib64/libsnapper.so.4", F_OK) < 0)
		perror("/usr/lib64/libsnapper.so.4");
	if (access("/usr/share/YaST2/clients/snapper.rb", F_OK) < 0)
		perror("/usr/share/YaST2/clients/snapper.rb");

	return 0;
}
