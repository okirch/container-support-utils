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
#include "tracing.h"

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
	uint32_t payload = htonl(status);

	return wormhole_message_build(WORMHOLE_OPCODE_STATUS, &payload, sizeof(payload));
}

static bool
__wormhole_message_put_string(char buffer[WORMHOLE_PROTOCOL_STRING_MAX], const char *s)
{
	if (s == NULL)
		return true;

	if (strlen(s) >= WORMHOLE_PROTOCOL_STRING_MAX)
		return false;
	strcpy(buffer, s);
	return true;
}

struct buf *
wormhole_message_build_namespace_request(const char *name)
{
	struct wormhole_message_namespace_request payload;

	memset(&payload, 0, sizeof(payload));
	if (!__wormhole_message_put_string(payload.profile, name))
		return NULL;

	return wormhole_message_build(WORMHOLE_OPCODE_NAMESPACE_REQUEST, &payload, sizeof(payload));
}

struct buf *
wormhole_message_build_namespace_response(unsigned int status, const char *cmd)
{
	struct wormhole_message_namespace_response payload;

	memset(&payload, 0, sizeof(payload));
	payload.status = htonl(status);

	if (status == WORMHOLE_STATUS_OK
	 && !__wormhole_message_put_string(payload.command, cmd))
		return NULL;

	return wormhole_message_build(WORMHOLE_OPCODE_NAMESPACE_RESPONSE, &payload, sizeof(payload));
}

static inline bool
__wormhole_message_protocol_compatible(const struct wormhole_message *msg)
{
	return (WORMHOLE_PROTOCOL_MAJOR(msg->version) == WORMHOLE_PROTOCOL_VERSION_MAJOR);
}

static bool
__wormhole_message_dissect_header(struct buf *bp, struct wormhole_message *msg, bool consume)
{
	unsigned int hdrlen = sizeof(struct wormhole_message);

	if (buf_get(bp, msg, hdrlen) < hdrlen)
		return false;

	msg->version = ntohs(msg->version);
	msg->opcode = ntohs(msg->opcode);
	msg->payload_len = ntohs(msg->payload_len);

	if (buf_available(bp) < hdrlen + msg->payload_len)
		return false;

	if (consume)
		__buf_advance_head(bp, hdrlen);

	return true;
}

bool
wormhole_message_complete(struct buf *bp)
{
	struct wormhole_message msg;

	return __wormhole_message_dissect_header(bp, &msg, false);
}

struct wormhole_message_parsed *
wormhole_message_parse(struct buf *bp, uid_t sender_uid)
{
	struct wormhole_message_parsed *pmsg;

	pmsg = calloc(1, sizeof(*pmsg));

	if (!__wormhole_message_dissect_header(bp, &pmsg->hdr, true)) {
		/* should not happen. */
		log_fatal("%s: unable to parse message header", __func__);
	}

	if (!__wormhole_message_protocol_compatible(&pmsg->hdr)) {
                log_error("message from uid %d: incompatible protocol message (version 0x%x)",
				sender_uid, pmsg->hdr.version);
                goto failed;
        }

	if (pmsg->hdr.payload_len > sizeof(pmsg->payload)) {
                log_error("message from uid %d: payload of %u bytes too big",
				sender_uid, pmsg->hdr.payload_len);
		goto failed;
	}

	{
		unsigned int len = pmsg->hdr.payload_len;

		assert(buf_get(bp, &pmsg->payload, len) == len);
		__buf_advance_head(bp, len);
	}

	switch (pmsg->hdr.opcode) {
	case WORMHOLE_OPCODE_STATUS:
		pmsg->payload.status.status = ntohl(pmsg->payload.status.status);
		break;

	case WORMHOLE_OPCODE_NAMESPACE_REQUEST:
		if (pmsg->payload.namespace_request.profile[WORMHOLE_PROTOCOL_STRING_MAX-1] != '\0') {
			log_error("message from uid %d: unterminated profile argument", sender_uid);
			goto failed;
		}
		break;
	case WORMHOLE_OPCODE_NAMESPACE_RESPONSE:
		pmsg->payload.namespace_response.status = ntohl(pmsg->payload.namespace_response.status);

		if (pmsg->payload.namespace_response.command[WORMHOLE_PROTOCOL_STRING_MAX-1] != '\0') {
			log_error("message from uid %d: unterminated string argument", sender_uid);
			goto failed;
		}
		break;

	default:
		log_error("message from uid %d: unexpected opcode %d", sender_uid, pmsg->hdr.opcode);
		goto failed;
	}

	return pmsg;

failed:
	/* FIXME: mark socket for closing */
	wormhole_message_free_parsed(pmsg);
	return NULL;
}

void
wormhole_message_free_parsed(struct wormhole_message_parsed *pmsg)
{
	free(pmsg);
}
