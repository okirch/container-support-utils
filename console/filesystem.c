/*
 * filesystem.c
 *
 * Messing around with mounts.
 *
 * I'm not sure whether this approach works by design or by accident.
 * At any rate, it's useful :-)
 *
 * The only drawback so far is that you cannot modify the host directory;
 * all changes are lost after you exit from the shell.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>

#include <setjmp.h>

#include "shell.h"
#include "container.h"
#include "tracing.h"

struct export_state {
	struct export_state *	next;
	const struct export_dir	*export;
	int			dir_fd;
};

/*
 * Handle arrays of export information
 */
void
export_dir_array_append(struct export_dir_array *ap, const char *host_dir, const char *container_dir)
{
	struct export_dir *ed;

	if (ap->count >= EXPORT_DIR_MAX)
		log_fatal("Too many exported directories for my little brain.\n");

	ed = &ap->dirs[ap->count++];
	ed->host_path = strdup(host_dir);
	ed->container_path = strdup(container_dir);
}

void
export_dir_array_destroy(struct export_dir_array *ap)
{
	struct export_dir *ed;
	unsigned int i;

	for (i = 0, ed = ap->dirs; i < ap->count; ++i, ++ap) {
		free(&ed->host_path);
		free(&ed->container_path);
	}
	memset(ap, 0, sizeof(*ap));
}

/*
 * Prepare for exporting. This is invoked prior to
 * attaching to the container's namespaces
 */
int
export_dir_prepare(const struct export_dir_array *ap, struct export_state **retp)
{
	const struct export_dir *ed;
	unsigned int i;

	*retp = NULL;


	for (i = 0, ed = ap->dirs; i < ap->count; ++i, ++ap) {
		struct export_state *st;
		int fd;

		if ((fd = open(ed->host_path, O_RDONLY|O_CLOEXEC)) < 0) {
			log_error("Unable to open \"%s\": %m\n", ed->host_path);
			continue;
		}

		st = calloc(1, sizeof(*st));
		st->export = ed;
		st->dir_fd = fd;

		*retp = st;
		retp = &st->next;
	}

	return 0;
}

/*
 * Destroy export state
 */
void
export_state_destroy(struct export_state *state_list)
{
	struct export_state *st;

	while ((st = state_list) != NULL) {
		state_list = st->next;
		if (st->dir_fd >= 0)
			close(st->dir_fd);
		free(st);
	}
}

/*
 * Apply all exports inside the container namespace
 */
int
export_state_apply(struct export_state *state_list)
{
	char dirtemplate[] = "/tmp/mounts.XXXXXX";
	struct export_state *st;
	unsigned int count = 0;
	char *tempdir;

	tempdir = mkdtemp(dirtemplate);
	if (tempdir == NULL)
		log_fatal("Unable to create tempdir in container: %m\n");

	trace("Mounting tmpfs on %s\n", tempdir);
	if (mount("tmpfs", tempdir, "tmpfs", 0, NULL) < 0)
		log_fatal("Unable to mount tmpfs in container: %m\n");

	for (st = state_list; st; st = st->next) {
		const struct export_dir *ed = st->export;
		char mount_dir[PATH_MAX], upper[PATH_MAX], lower[PATH_MAX], work[PATH_MAX], procdir[PATH_MAX];
		char options[3 * PATH_MAX];

		if (access(ed->container_path, X_OK) < 0) {
			log_error("cannot access \"%s\" in container: %m\n", ed->container_path);
			continue;
		}

		snprintf(mount_dir, sizeof(mount_dir), "%s/mnt%d", tempdir, count++);
		if (mkdir(mount_dir, 0755) < 0) {
			log_error("mkdir(%s): %m\n", mount_dir);
			continue;
		}

		snprintf(lower, sizeof(lower), "%s/lower", mount_dir);
		snprintf(upper, sizeof(upper), "%s/upper", mount_dir);
		snprintf(work, sizeof(work), "%s/work", mount_dir);

		snprintf(procdir, sizeof(procdir), "/proc/%d/fd/%d", getpid(), st->dir_fd);
		if (symlink(procdir, lower) < 0) {
			log_error("symlink(%s, %s): %m\n", procdir, lower);
			continue;
		}
		if (mkdir(upper, 0755) < 0) {
			log_error("mkdir(%s): %m\n", upper);
			continue;
		}
		if (mkdir(work, 0755) < 0) {
			log_error("mkdir(%s): %m\n", work);
			continue;
		}

		snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s",
				lower, upper, work);

		trace("Mounting %s on %s (via %s)\n", ed->host_path, ed->container_path, procdir);
		if (mount("foo", ed->container_path, "overlay", 0, options) < 0) {
			log_error("Cannot mount overlayfs at %s: %m\n", ed->container_path);
			continue;
		}
	}

	if (umount(tempdir) < 0) {
		log_error("Unable to unmount %s: %m\n", tempdir);
	} else
	if (rmdir(tempdir) < 0) {
		log_error("Unable to remove temporary mountpoint %s: %m\n", tempdir);
	}

	return 0;
}
