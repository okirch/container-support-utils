/*
 * buffer.h
 *
 */

#ifndef _BUF_H
#define _BUF_H

#include <stdlib.h>
#include <stdbool.h>

#define BUF_SZ		1024
#define QUEUE_SZ	(64 * BUF_SZ)

struct buf {
	struct buf *	next;
	unsigned char	data[BUF_SZ];
	unsigned int	head, tail;
};

struct queue {
	unsigned long	size;
	struct buf *	head;
};

extern struct buf *	buf_alloc(void);
extern void		buf_free(struct buf *bp);
extern unsigned int	buf_put(struct buf *bp, const void *p, unsigned int len);
extern unsigned long	buf_get(struct buf *bp, void *p, unsigned long size);
extern void		buf_consumed(struct buf **list, unsigned long amount);

extern void		queue_init(struct queue *);
extern void		queue_destroy(struct queue *);
extern size_t		queue_available(const struct queue *);
extern size_t		queue_tailroom(const struct queue *);
extern bool		queue_full(const struct queue *);
extern void		queue_append(struct queue *, const void *, size_t);
extern const void *	queue_peek(const struct queue *q, void *p, size_t count);
extern void		queue_advance_head(struct queue *q, size_t count);

static inline unsigned int
buf_tailroom(const struct buf *bp)
{
	return BUF_SZ - bp->tail;
}

static inline unsigned int
buf_available(const struct buf *bp)
{
	return bp->tail - bp->head;
}

static inline const void *
buf_head(const struct buf *bp)
{
	if (bp->head == bp->tail)
		return NULL;

	return bp->data + bp->head;
}

static inline void
__buf_advance_head(struct buf *bp, unsigned int len)
{
	assert(bp->tail - bp->head >= len);
	bp->head += len;
}

#endif /* _BUF_H */
