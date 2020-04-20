/*
 * endpoint.h
 *
 * Wrapper class for sockets, ttys etc
 */

#ifndef _ENDPOINT_H
#define _ENDPOINT_H

#include <sys/poll.h>
#include <buffer.h>

struct endpoint {
	/* For now, we support only endpoints with a single fd.
	 * If needed, stuff like pairs of named pipes could be added
	 * later */
	int		fd;

	unsigned int	write_shutdown_requested : 1,
			write_shutdown_sent : 1,
			read_shutdown_received : 1;

	bool		debug;
	const char *	debug_name;

	struct queue	sendq;
	struct queue *	recvq;

	/* A size hint for how much we can (try to) send in one go.
	 */
	unsigned int	send_size_hint;

	/* A mask of POLL* constants.
	 * A socket in listen mode will assert POLLIN only.
	 * A connected socket will set this to POLLIN|POLLOUT initially.
	 *   When the remote closes the socket, we should clean POLLIN
	 *   and wait until we have drained any queued up data.
	 *
	 * A pty master will set this to POLLIN|POLLOUT, and clear
	 *   the mask when receiving a hangup indication from the
	 *   slave.
	 */
	int		poll_mask;

	void		(*data_source_callback)(struct queue *, void *);
	void		(*data_sink_callback)(struct queue *, void *);
	void		(*close_callback)(struct endpoint *, void *);
	void *		app_handle;

	const struct endpoint_ops *ops;
};

struct endpoint_ops {
	int		(*poll)(const struct endpoint *, struct pollfd *, unsigned int mask);
	size_t		(*send_size_hint)(const struct endpoint *);
	int		(*send)(struct endpoint *, const void *, size_t);
	int		(*recv)(struct endpoint *, void *, size_t);
	int		(*shutdown_write)(struct endpoint *);
};

extern struct endpoint *endpoint_new_socket(int fd);
extern struct endpoint *endpoint_new_pty(int fd);
extern void		endpoint_error(const struct endpoint *, const char *fmt, ...);
extern void		endpoint_debug(const struct endpoint *, const char *fmt, ...);
extern const char *	endpoint_debug_name(const struct endpoint *);
extern void		endpoint_shutdown_write(struct endpoint *);
extern void		endpoint_close(struct endpoint *);
extern void		endpoint_free(struct endpoint *);
extern unsigned int	endpoint_tailroom(const struct endpoint *ep);
extern int		endpoint_enqueue(struct endpoint *ep, const void *, size_t);
extern int		endpoint_transmit(struct endpoint *ep);
extern int		endpoint_receive(struct endpoint *ep);

extern void		io_register_endpoint(struct endpoint *ep);
extern int		io_mainloop(long timeout);
extern void		io_close_all(void);

static inline size_t
endpoint_send_size_hint(const struct endpoint *ep)
{
	if (ep->ops->send_size_hint == NULL)
		return 0;

	return ep->ops->send_size_hint(ep);
}

static inline int
endpoint_poll(const struct endpoint *ep, struct pollfd *pfd, unsigned int mask)
{
	return ep->ops->poll(ep, pfd, mask);
}

static inline int
endpoint_send(struct endpoint *ep, const void *p, size_t len)
{
	return ep->ops->send(ep, p, len);
}

static inline int
endpoint_recv(struct endpoint *ep, void *p, size_t len)
{
	return ep->ops->recv(ep, p, len);
}

#endif /* _ENDPOINT_H */
