/*
 * wormhole wire protocol
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


#include <netinet/in.h>
#include <string.h>

#include "protocol.h"

struct buf *
wormhole_message_build(int opcode, const void *payload, size_t payload_len)
{
	struct wormhole_message msg;
	struct buf *bp = buf_alloc();

	assert(payload_len < 0x10000);

	memset(&msg, 0, sizeof(msg));
	msg.version = htons(WORMHOLE_PROTOCOL_VERSION);
	msg.opcode = htons(opcode);
	msg.payload_len = htons(payload_len);

	buf_put(bp, &msg, sizeof(msg));
	if (payload_len)
		buf_put(bp, payload, payload_len);

	return bp;
}

struct buf *
wormhole_message_build_status(unsigned int status)
{
	uint32_t status32;

	status32 = htonl(status);
	return wormhole_message_build(WORMHOLE_OPCODE_STATUS, &status32, sizeof(status32));
}

bool
wormhole_message_dissect(struct buf *bp, struct wormhole_message *msg, const void **payloadp)
{
	unsigned int avail = buf_available(bp);
	unsigned int msglen = sizeof(*msg);

	if (avail < sizeof(*msg))
		return false;

	if (buf_get(bp, msg, msglen) < msglen)
		return false;

	msg->version = ntohs(msg->version);
	msg->opcode = ntohs(msg->opcode);
	msg->payload_len = ntohs(msg->payload_len);

	*payloadp = NULL;
	if (WORMHOLE_PROTOCOL_MAJOR(msg->version) != WORMHOLE_PROTOCOL_VERSION_MAJOR)
		return true;

	if (msg->payload_len) {
		msglen += msg->payload_len;
		if (avail < msglen)
			return false;

		*payloadp = buf_head(bp) + sizeof(*msg);
	}

	__buf_advance_head(bp, msglen);
	return true;
}
