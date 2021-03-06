/*
 * queue.c
 *
 * Simple send buffer management for sockets, ttys etc
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <buffer.h>

void
queue_init(struct queue *q)
{
	memset(q, 0, sizeof(*q));
}

static inline void
queue_validate(const struct queue *q)
{
	unsigned int count = 0;
	const struct buf *bp;

	for (bp = q->head; bp; bp = bp->next)
		count += buf_available(bp);
	assert(q->size == count);
	assert(q->size <= QUEUE_SZ);
}

void
queue_destroy(struct queue *q)
{
	struct buf *bp;

	while ((bp = q->head) != NULL) {
		q->head = bp->next;
		q->size -= buf_available(bp);
		buf_free(bp);
	}
}

unsigned long
queue_available(const struct queue *q)
{
	return q->size;
}

unsigned long
queue_tailroom(const struct queue *q)
{
	return QUEUE_SZ - q->size;
}

bool
queue_full(const struct queue *q)
{
	return q->size == QUEUE_SZ;
}

static inline void
__queue_peek(const struct queue *q, void *p, unsigned int count)
{
	const struct buf *bp;

	assert(count <= q->size);

	for (bp = q->head; count; bp = bp->next) {
		unsigned int n;

		assert(bp);

		n = buf_available(bp);
		if (n > count)
			n = count;

		memcpy(p, buf_head(bp), n);
		count -= n;
		p += n;
	}

	assert(count == 0);
}

void
queue_append(struct queue *q, const void *p, size_t count)
{
	struct buf *bp, **pos;

	queue_validate(q);
	assert(QUEUE_SZ - q->size >= count);

	/* Find the list tail */
	for (pos = &q->head; (bp = *pos) != NULL; pos = &bp->next)
		;

	while (count) {
		unsigned int n;

		bp = buf_alloc();
		n = buf_put(bp, p, count);

		count -= n;
		p += n;

		*pos = bp;
		pos = &bp->next;
		q->size += n;
	}
}

const void *
queue_peek(const struct queue *q, void *p, size_t count)
{
	struct buf *bp;

	queue_validate(q);
	assert(q->size >= count);

	if (count == 0)
		return p;

	bp = q->head;
	if (buf_available(bp) >= count) {
		/* fast path w/o data copies */
		return buf_head(bp);
	}
	
	/* slow path: linearize data */
	__queue_peek(q, p, count);
	return p;
}

const void *
queue_get(struct queue *q, void *p, size_t count)
{
	queue_validate(q);
	assert(q->size >= count);

	if (count == 0)
		return p;

	/* slow path: linearize data */
	__queue_peek(q, p, count);
	queue_advance_head(q, count);
	return p;
}

void
queue_advance_head(struct queue *q, size_t count)
{
        struct buf *bp;

	queue_validate(q);
        while (count) {
                unsigned int avail;

                bp = q->head;
                assert(bp);

                avail = buf_available(bp);
                if (avail > count) {
                        __buf_advance_head(bp, count);
			q->size -= count;
                        return;
                }

		q->size -= avail;
                count -= avail;
		q->head = bp->next;
                buf_free(bp);
        }
}

void
queue_transfer(struct queue *dstq, struct queue *srcq, size_t count)
{
	void *buffer;
	const void *p;

	assert(queue_tailroom(dstq) >= count);
	assert(queue_available(srcq) >= count);

	buffer = alloca(count);
        p = queue_peek(srcq, buffer, count);
        queue_append(dstq, p, count);
        queue_advance_head(srcq, count);

}
