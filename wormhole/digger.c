/*
 * wormhole digger
 *
 *   Copyright (C) 2020-2021 Olaf Kirch <okir@suse.de>
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

#include <sys/socket.h> /* only for send() call below - fix this */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>

#include "tracing.h"
#include "wormhole.h"
#include "protocol.h"
#include "socket.h"
#include "util.h"
#include "buffer.h"

struct option wormhole_options[] = {
	{ "debug",		no_argument,		NULL,	'd' },
	{ "base-environment",	required_argument,	NULL,	'B' },
	{ "overlay-root",	required_argument,	NULL,	'R' },
	{ NULL }
};

const char *		opt_base_environment = NULL;
const char *		opt_overlay_root = NULL;

static int		wormhole_digger(int argc, char **argv);

int
main(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv, "d", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			tracing_enable();
			break;

		case 'B':
			opt_base_environment = optarg;
			break;

		case 'R':
			opt_overlay_root = optarg;
			break;

		default:
			log_error("Usage message goes here.");
			return 2;
		}
	}

	return wormhole_digger(argc - optind, argv + optind);
}

struct overlay_mount_triple {
	struct overlay_mount_triple *next;

	const char *	dirname;
	char		tree_path[PATH_MAX];
	char		work_path[PATH_MAX];
};

static struct overlay_mount_triple *
prepare_overlay_mount_point(const char *overlay_root, const char *dirname)
{
	struct overlay_mount_triple *triple;

	triple = calloc(1, sizeof(*triple));
	triple->dirname = dirname;

	snprintf(triple->tree_path, sizeof(triple->tree_path), "%s/tree%s", overlay_root, dirname);
	snprintf(triple->work_path, sizeof(triple->work_path), "%s/work%s", overlay_root, dirname);

	if (fsutil_makedirs(triple->tree_path, 0755) < 0)
		log_fatal("Unable to create %s", triple->tree_path);
	if (fsutil_makedirs(triple->work_path, 0755) < 0)
		log_fatal("Unable to create %s", triple->work_path);

	return triple;
}

static bool
validate_overlay_mounts(const char *overlay_root, const char **dir_list)
{
	const char *dirname;

	if (overlay_root == NULL) {
		log_error("Please specify a root directory via --overlay-root");
		return false;
	}

	while ((dirname = *dir_list++) != NULL) {
		if (fsutil_check_path_prefix(overlay_root, dirname)) {
			log_error("Invalid overlay root %s resides below %s", overlay_root, dirname);
			return false;
		}
	}

	return true;
}

static struct overlay_mount_triple *
prepare_overlay_mounts(const char *overlay_root, const char **dir_list)
{
	struct overlay_mount_triple *list = NULL;
	struct overlay_mount_triple **tail = &list;
	const char *dirname;

	while ((dirname = *dir_list++) != NULL) {
		*tail = prepare_overlay_mount_point(overlay_root, dirname);
		tail = &(*tail)->next;
	}

	return list;
}

struct wormhole_digger_config {
	struct overlay_mount_triple *overlays;

	char **		argv;
};

static bool
wormhole_digger_setup_environment(struct wormhole_digger_config *cb)
{
	struct overlay_mount_triple *triple;
	const char *command;

	/* Unshare the namespace so that any nonsense that happens in the subprocess we spawns
	 * stays local to that execution context. */
	if (unshare(CLONE_NEWNS) < 0) {
		log_error("unshare: %m");
		return false;
	}

	for (triple = cb->overlays; triple; triple = triple->next) {
		const char *dirname = triple->dirname;

		if (!fsutil_mount_overlay(dirname, triple->tree_path, triple->work_path, dirname))
			log_fatal("Unable to create a transparent overlay at %s", dirname);
	}

	(void) chdir("/");

	setenv("PS1", "(wormhole) # ", 1);

	/* Caveat:
	 * There's a glitch in devpts that causes isatty() to fail inside the container,
	 * at least for pty slaves that were opened outside the environment.
	 *  readlink("/proc/self/fd/0", "/dev/pts/15", 4095) = 11
	 *  stat("/dev/pts/15", <ptr>) = -1 ENOENT (No such file or directory)
	 * This either needs to get fixed in the kernel, or we need to work around
	 * this by opening a pty pair here, and copy data inbetween _our_ tty and
	 * the slave tty.
	 */

	command = cb->argv[0];
	execvp(command, cb->argv);

	log_error("Unable to execute %s: %m", command);
	return false;
}

static bool
wormhole_namespace_response_callback(struct wormhole_message_namespace_response *msg, int nsfd, void *closure)
{
	struct wormhole_digger_config *cb = closure;

	/* Apply any environment variables sent to us by the server. */
	if (msg->environment_vars != NULL) {
		char **env = msg->environment_vars;
		unsigned int i;

		for (i = 0; env[i]; ++i)
			putenv(env[i]);
	}

	if (msg->server_socket) {
		setenv("WORMHOLE_SOCKET", msg->server_socket, 1);
	}

	if (setns(nsfd, CLONE_NEWNS) < 0) {
		log_error("setns: %m");
		return false;
	}

	/* We no longer need this fd and should not pass it on to the executed command */
	close(nsfd);

	return wormhole_digger_setup_environment(cb);
}

int
wormhole_digger(int argc, char **argv)
{
	struct wormhole_digger_config closure;
	char *shell_argv[] = { "/bin/bash", NULL };
	static const char *overlay_dirs[] = {
		"/bin",
		"/boot",
		"/dev",
		"/etc",
		"/lib",
		"/lib64",
		"/opt",
		"/sbin",
		"/usr",
		NULL,
	};

	memset(&closure, 0, sizeof(closure));
	if (argc != 0) {
		closure.argv = argv;
	} else {
		shell_argv[0] = getenv("SHELL");
		if (shell_argv[0] == NULL)
			shell_argv[0] = "/bin/sh";
		closure.argv = shell_argv;
	}

	if (getuid() != 0) {
		log_error("You must be root to run this program\n");
		return 1;
	}

	if (!validate_overlay_mounts(opt_overlay_root, overlay_dirs))
		log_fatal("Invalid arguments");

	if (fsutil_makedirs(opt_overlay_root, 0755) < 0)
		log_fatal("Unable to create overlay root at %s", opt_overlay_root);

	closure.overlays = prepare_overlay_mounts(opt_overlay_root, overlay_dirs);

	if (opt_base_environment != 0) {
		wormhole_client_namespace_request(opt_base_environment, wormhole_namespace_response_callback, &closure);
	} else {
		wormhole_digger_setup_environment(&closure);
	}

	/* If we get here, something failed. */
	return 12;
}
