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

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "tracing.h"
#include "util.h"


const char *
concat_argv(int argc, char **argv)
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
