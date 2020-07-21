/*
 * wormhole
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
#include <sys/un.h>
#include <syslog.h>
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

#define WORMHOLE_SOCKET_PATH	"/var/run/wormhole.sock"

struct option wormhole_options[] = {
	{ "daemon",	no_argument,	NULL,	'D' },
	{ "foreground",	no_argument,	NULL,	'F' },
	{ "client",	no_argument,	NULL,	'C' },
	{ NULL }
};

static const char *		layer_path = "/var/lib/containers/storage/btrfs/subvolumes/9229975c0c692c97def1cd6fb095dcad584d6e9fa7a0a24cccde9fe2f5a3385f";

struct path_info {
	char *			path;
	char *			replace;
};

#define PATH_INFO_HIDE(n)	{ .path = n, .replace = NULL }
#define PATH_INFO_REPLACE(n)	{ .path = n, .replace = "$LAYER" n }
#define PATH_INFO_REPLACE_CHILDREN(n)	{ .path = n, .replace = "$LAYER" n "/*" }

struct profile {
	char *			name;
	char *			command;
	struct path_info	path_info[128];
};

static struct profile		dummy_ps_profile = {
	.name =			"ps",
	.command =		"/usr/bin/ps",
};
static struct profile		dummy_yast2_profile = {
	.name =			"yast2",
	.command =		"/sbin/yast2",

	.path_info = {
		PATH_INFO_REPLACE("/usr/lib/perl5"),
		PATH_INFO_REPLACE("/usr/lib/YaST2"),
		PATH_INFO_REPLACE_CHILDREN("/usr/lib64"),
		// PATH_INFO_REPLACE("/usr/lib64/ruby"),
		PATH_INFO_REPLACE("/usr/share/YaST2"),
		PATH_INFO_REPLACE("/var/log/YaST2"),
	},
};

static bool			opt_foreground = false;

static int			wormhole_default(int argc, char **argv);
static int			wormhole_client(int argc, char **argv);
static int			wormhole_daemon(int argc, char **argv);
static void			wormhole_process_connection(int fd);

static struct profile *		profile_find(const char *argv0);
static int			profile_setup(struct profile *);
static int			frob_arguments(int, char **, int);

int
main(int argc, char **argv)
{
	int (*fn)(int, char **) = wormhole_default;
	int c;

	while ((c = getopt_long(argc, argv, "", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'C':
			fn = wormhole_client;
			break;
		case 'D':
			fn = wormhole_daemon;
			break;
		case 'F':
			opt_foreground = true;
			break;

		default:
			fprintf(stderr, "Usage message goes here.\n");
			return 2;
		}
	}

	argc = frob_arguments(argc, argv, optind);
	return fn(argc, argv);
}

int
frob_arguments(int argc, char **argv, int optind)
{
	int i;

	if (optind == 1)
		return argc;

	for (i = 1; optind < argc; ++i, ++optind)
		argv[i] = argv[optind];
	return i;
}

int
wormhole_default(int argc, char **argv)
{
	struct profile *profile;

	if (argc == 0) {
		fprintf(stderr, "sneaky invocation detected. countermeasures initiated.\n");
		return 2;
	}

	profile = profile_find(argv[0]);
	if (profile == NULL) {
		fprintf(stderr, "no profile for %s.\n", argv[0]);
		return 2;
	}

	if (profile_setup(profile) < 0) {
		fprintf(stderr, "Failed to set up environment for %s\n", profile->name);
		return 2;
	}

	/* Drop uid/gid back to those of the calling user. */
	setgid(getgid());
	setuid(getuid());

	printf("I should now execute %s\n", profile->command);
	execv(profile->command, argv);

	fprintf(stderr, "Unable to execute %s: %m\n", profile->command);
	return 12;
}

static bool	opt_log_syslog = false;

void
wormhole_openlog(void)
{
	openlog("wormholed", 0, LOG_DAEMON);
	opt_log_syslog = true;
}

static void
__wormhole_do_log(int level, const char *fmt, va_list ap)
{
	if (opt_log_syslog) {
		vsyslog(level, fmt, ap);
	} else {
		FILE *fp;

		fp = (level <= LOG_WARNING)? stderr : stdout;
		vfprintf(fp, fmt, ap);
		fputs("\n", fp);
	}
}

static void
wormhole_daemon_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__wormhole_do_log(LOG_INFO, fmt, ap);
	va_end(ap);
}

static void
wormhole_daemon_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__wormhole_do_log(LOG_ERR, fmt, ap);
	va_end(ap);
}

static void
wormhole_daemon_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	__wormhole_do_log(LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

int
wormhole_daemon(int argc, char **argv)
{
	struct sockaddr_un sun;
	int fd;

	if (argc != 1) {
		fprintf(stderr, "bad additional arguments.\n");
		return 2;
	}

	if ((fd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return 1;
	}

	unlink(WORMHOLE_SOCKET_PATH);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, WORMHOLE_SOCKET_PATH);
	if (bind(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		perror("bind");
		return 1;
	}

	chmod(WORMHOLE_SOCKET_PATH, 0666);

	if (listen(fd, 10) < 0) {
		perror("listen");
		return 1;
	}

	if (!opt_foreground) {
		wormhole_openlog();
		if (daemon(false, false) < 0) {
			perror("listen");
			return 1;
		}
	}

	while (true) {
		pid_t pid;
		int cfd;

		cfd = accept(fd, NULL, NULL);
		if (cfd < 0) {
			wormhole_daemon_error("failed to accept incoming connection: %m");
			continue;
		}

		pid = fork();
		if (pid == 0) {
			wormhole_process_connection(cfd);
			exit(0);
		}

		if (pid < 0)
			wormhole_daemon_error("failed to fork child process: %m");
		close(cfd);
	}

	return 0;
}

void
wormhole_process_connection(int fd)
{
	struct profile *profile;
	char namebuf[1024];
	union {
		struct cmsghdr align;
		char buf[1024];
	} u;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	int n, nsfd;

	alarm(5);

	if ((n = recv(fd, namebuf, sizeof(namebuf) - 1, 0)) < 0)
		wormhole_daemon_fatal("recv: %m");
	namebuf[n] = '\0';

	profile = profile_find(namebuf);
	if (profile == NULL)
		wormhole_daemon_fatal("no profile for %s", namebuf);

	if (profile_setup(profile) < 0)
		wormhole_daemon_fatal("Failed to set up environment for %s", profile->name);

	nsfd = open("/proc/self/ns/mnt", O_RDONLY);
	if (nsfd < 0)
		wormhole_daemon_fatal("Cannot open /proc/self/ns/mnt: %m");

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = profile->command;
	iov.iov_len = strlen(profile->command);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

        msg.msg_control = u.buf;
        msg.msg_controllen = sizeof(u.buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &nsfd, sizeof(int));
	msg.msg_controllen = CMSG_SPACE(sizeof(int));

	if (sendmsg(fd, &msg, 0) < 0)
		wormhole_daemon_fatal("sendmsg: %m");

	wormhole_daemon_info("served request for a \"%s\" namespace", profile->name);
	return;
}

int
wormhole_client(int argc, char **argv)
{
	struct sockaddr_un sun;
	char pathbuf[PATH_MAX];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr align;
		char buf[1024];
	} u;
	int fd, nsfd = -1;

	if (argc == 0) {
		fprintf(stderr, "No argv[0]. How come?\n");
		return 2;
	}

	fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return 2;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, WORMHOLE_SOCKET_PATH);
	if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		perror("connect");
		return 1;
	}

	if (send(fd, argv[0], strlen(argv[0]), 0) < 0) {
		perror("send");
		return 1;
	}

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = pathbuf;
	iov.iov_len = sizeof(pathbuf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

        msg.msg_control = u.buf;
        msg.msg_controllen = sizeof(u.buf);

	if (recvmsg(fd, &msg, 0) < 0) {
		perror("recvmsg");
		return 1;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			memcpy(&nsfd, CMSG_DATA(cmsg), sizeof(int));
		}
	}

	if (nsfd < 0) {
		fprintf(stderr, "Server did not send us a namespace FD\n");
		return 2;
	}

	if (setns(nsfd, CLONE_NEWNS) < 0) {
		perror("setns");
		return 2;
	}

	/* Drop uid/gid back to those of the calling user. */
	setgid(getgid());
	setuid(getuid());

	printf("I should now execute %s\n", pathbuf);
	execv(pathbuf, argv);

	fprintf(stderr, "Unable to execute %s: %m\n", pathbuf);
	return 12;
}

struct profile *
profile_find(const char *argv0)
{
	char *fullname;
	char *name;

	fullname = strdup(argv0);

	name = basename(fullname);
	if (name == NULL || *name == '\0') {
		fprintf(stderr, "Cannot detect basename of executable\n");
		return NULL;
	}

	if (!strcmp(name, "ps"))
		return &dummy_ps_profile;
	if (!strcmp(name, "yast2"))
		return &dummy_yast2_profile;

	return NULL;
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
pathinfo_expand(const char *path)
{
	static char expanded[PATH_MAX];

	if (!strncmp(path, "$LAYER/", 7)) {
		snprintf(expanded, sizeof(expanded), "%s/%s", layer_path, path + 7);
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
		fprintf(stderr, "%s: unable to bind mount %s to %s\n", profile->name, source, target);
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

		printf("Trying to mount %s from %s to %s\n", d->d_name, source, pi->path);
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

	source = pathinfo_expand(pi->replace);
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
