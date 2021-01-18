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

bool
wormhole_message_parse_status(struct buf *bp, struct wormhole_message_parsed *pmsg)
{
	uint32_t payload;

	if (pmsg->hdr.payload_len != sizeof(payload))
		return false;

	if (!buf_get(bp, &payload, sizeof(payload)))
		return false;

	pmsg->payload.status.status = ntohl(payload);
	return true;
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

static bool
wormhole_message_parse_namespace_request(struct buf *bp, struct wormhole_message_parsed *pmsg)
{
	unsigned int len = pmsg->hdr.payload_len;

	if (buf_get(bp, &pmsg->payload, len) != len)
		return false;

	if (pmsg->payload.namespace_request.profile[WORMHOLE_PROTOCOL_STRING_MAX-1] != '\0') {
		log_error("unterminated profile argument");
		return false;
	}

	return true;
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

static bool
wormhole_message_parse_namespace_response(struct buf *bp, struct wormhole_message_parsed *pmsg)
{
	unsigned int len = pmsg->hdr.payload_len;

	if (buf_get(bp, &pmsg->payload, len) != len)
		return false;

	pmsg->payload.namespace_response.status = ntohl(pmsg->payload.namespace_response.status);

	if (pmsg->payload.namespace_request.profile[WORMHOLE_PROTOCOL_STRING_MAX-1] != '\0') {
		log_error("unterminated profile argument");
		return false;
	}

	return true;
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

	if (pmsg->hdr.payload_len > BUF_SZ) {
		log_error("message from uid %d: payload of %u bytes too big",
				sender_uid, pmsg->hdr.payload_len);
		goto failed;
	}

	switch (pmsg->hdr.opcode) {
	case WORMHOLE_OPCODE_STATUS:
		if (!wormhole_message_parse_status(bp, pmsg))
			goto failed;
		break;

	case WORMHOLE_OPCODE_NAMESPACE_REQUEST:
		if (!wormhole_message_parse_namespace_request(bp, pmsg))
			goto failed;
		break;
	case WORMHOLE_OPCODE_NAMESPACE_RESPONSE:
		if (!wormhole_message_parse_namespace_response(bp, pmsg))
			goto failed;
		break;

	default:
		log_error("message from uid %d: unexpected opcode %d", sender_uid, pmsg->hdr.opcode);
		goto failed;
	}

	/* Consume the message payload */
	__buf_advance_head(bp, pmsg->hdr.payload_len);

	return pmsg;

failed:
	/* FIXME: mark socket for closing */
	log_error("bad message from uid %d", sender_uid);
	wormhole_message_free_parsed(pmsg);
	return NULL;
}

void
wormhole_message_free_parsed(struct wormhole_message_parsed *pmsg)
{
	free(pmsg);
}
