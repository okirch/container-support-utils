/*
 * sidecar-console
 *
 * This utility helps you run a shell command in a container of your
 * choice, and talk to it through a socket connection.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "shell.h"

static unsigned int	opt_port = 24666;

int main(void)
{
	struct sockaddr_in sin;
	struct endpoint *ep;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(opt_port);

	ep = io_shell_service_create_listener(NULL, &sin);
	io_register_endpoint(ep);

	io_mainloop(-1);

	fprintf(stderr, "io_mainloop() returned unexpectedly\n");
	return 1;
}
