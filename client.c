/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "compat.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <phos.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if HAVE_ASR_RUN
# include <asr.h>
#endif

static char *fallback_err = "fallback error message, memory exhausted?";

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define ERRF(t, fmt, ...)						\
	do {								\
		char *errf_e;						\
		if ((t)->err != NULL && (t)->err != fallback_err)	\
			free((t)->err);					\
		if (asprintf(&errf_e, (fmt), __VA_ARGS__) == -1)	\
			(t)->err = fallback_err;			\
		else							\
			(t)->err = errf_e;				\
	} while(0)

static inline int	mark_nonblock(int);
static inline void	advance_buf(struct phos_client*, size_t);

static int		open_conn(struct phos_client*);

#if HAVE_ASR_RUN
static int		async_resolv(struct phos_client*);
#else
static int		blocking_resolv(struct phos_client*, const char*, struct addrinfo*);
#endif

static int		do_connect(struct phos_client*);
static int		setup_tls(struct phos_client*);
static int		write_request(struct phos_client*);
static int		read_reply(struct phos_client*);
static int		parse_reply(struct phos_client*);
static int		close_conn(struct phos_client*);

static inline int	run_tick(struct phos_client*);
static void		clear_data(struct phos_client*);
static int		until_state(struct phos_client*, int);
static int		until_state_sync(struct phos_client*, int);

enum phos_client_state {
	S_START,
	S_RESOLUTION,
	S_CONNECT,
	S_HANDSHAKE,
	S_POST_HANDSHAKE,
	S_WRITING_REQ,
	S_READING_HEADER,
	S_REPLY_READY,
	S_BODY,
	S_CLOSING,
	S_EOF,
	S_ERROR,
};

static inline int
mark_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		return -1;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		return -1;
	return 0;
}

static inline void
advance_buf(struct phos_client *client, size_t len)
{
	client->off -= len;
	memmove(client->buf, client->buf + len, client->off);
}

static int
open_conn(struct phos_client *client)
{
	struct addrinfo		 hints;
	const char		*proto = "1965";

	if (*client->port != '\0')
		proto = client->port;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

#ifdef HAVE_ASR_RUN
	client->asr = getaddrinfo_async(client->host, proto, &hints, NULL);
	if (client->asr == NULL) {
		ERRF(client, "can't resolve \"%s\": couldn't create the asr ctx",
		    client->host);
		client->asr = NULL;
		client->c_errno = ENOMEM;
		return -1;
	}

	return async_resolv(client);
#else
	return blocking_resolv(client, proto, &hints);
#endif
}

#if HAVE_ASR_RUN
static int
async_resolv(struct phos_client *client)
{
	struct asr_result	 res;

	client->state = S_RESOLUTION;

	if (asr_run(client->asr, &res)) {
		if (res.ar_gai_errno != 0) {
			ERRF(client, "couldn't resolve \"%s\": %s",
			    client->host, gai_strerror(res.ar_gai_errno));
			client->gai_errno = res.ar_gai_errno;
			client->asr = NULL;
			return -1;
		}

		client->servinfo = res.ar_addrinfo;
		client->p = res.ar_addrinfo;
		return do_connect(client);
	}

	return res.ar_cond == ASR_WANT_READ ? PHOS_WANT_READ : PHOS_WANT_WRITE;
}
#else
static int
blocking_resolv(struct phos_client *client, const char *proto, struct addrinfo *hints)
{
	int status;

	if ((status = getaddrinfo(client->host, proto, hints, &client->servinfo)) != 0) {
		ERRF(client, "couldn't resolve \"%s\": %s",
		    client->host, gai_strerror(status));
		client->gai_errno = status;
		return -1;
	}

	client->fd = -1;
	client->p = client->servinfo;
	return do_connect(client);
}
#endif

static int
do_connect(struct phos_client *client)
{
	socklen_t	len = sizeof(client->c_errno);

	client->state = S_CONNECT;

	for (; client->p != NULL; client->p = client->p->ai_next) {
		if (client->fd != -1) {
			if (getsockopt(client->fd, SOL_SOCKET, SO_ERROR,
			    &client->c_errno, &len) == -1 || client->c_errno != 0) {
				ERRF(client, "can't connect to \"%s\": (connect) %s",
				    client->host, strerror(client->c_errno));
				close(client->fd);
				client->fd = -1;
				continue;
			}
			break;
		}

		client->fd = socket(client->p->ai_family, client->p->ai_socktype,
		    client->p->ai_protocol);
		if (client->fd == -1) {
			client->c_errno = errno;
			ERRF(client, "can't connect to \"%s\": (socket) %s",
			    client->host, strerror(client->c_errno));
			continue;
		}

		if (mark_nonblock(client->fd) == -1) {
			client->c_errno = errno;
			ERRF(client, "can't connect to \"%s\": (mark_nonblock) %s",
			    client->host, strerror(client->c_errno));
			return -1;
		}

		if (connect(client->fd, client->p->ai_addr,
		    client->p->ai_addrlen) == 0)
			break;
		return PHOS_WANT_WRITE;
	}

	freeaddrinfo(client->servinfo);
	client->servinfo = NULL;

	if (client->p == NULL) {
		client->proto_err = 1;
		return -1;
	}

	client->p = NULL;
	return setup_tls(client);
}

static int
setup_tls(struct phos_client *client)
{
	int r;

	client->state = S_HANDSHAKE;

	r= client->io->setup_client_socket(client->tls, client->fd, client->host);
	if (r == -1) {
		ERRF(client, "TLS setup error: %s", client->io->err(client->tls));
		client->io_err = 1;
		return r;
	}
	if (r != 1)
		return r;

	client->off = 0;

	client->state = S_POST_HANDSHAKE;
	return PHOS_WANT_WRITE;
}

static int
write_request(struct phos_client *client)
{
	ssize_t	r;
	size_t	len;

	client->state = S_WRITING_REQ;

	len = strlen(client->req);
	for (;;) {
		r= client->io->write(client->tls, client->req + client->off,
		    len - client->off);
		switch (r) {
		case -1:
			ERRF(client, "TLS write error: %s", client->io->err(client->tls));
			client->io_err = 1;
		case 0:
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			return r;
		default:
			if (client->off + r >= len) {
				client->off = 0;
				return read_reply(client);
			}

			client->off += r;
		}
	}
}

static int
read_reply(struct phos_client *client)
{
	size_t	 len;
	ssize_t	 r;
	char	*buf;

	client->state = S_READING_HEADER;

	buf = client->buf + client->off;
	len = sizeof(client->buf) - client->off;

	for (;;) {
		switch (r = client->io->read(client->tls, buf, len)) {
		case -1:
			ERRF(client, "TLS read error: %s", client->io->err(client->tls));
			client->io_err = 1;
		case 0:
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			return r;
		default:
			client->off += r;

			if (memmem(client->buf, client->off, "\r\n", 2) != NULL)
				goto end;
			else if (client->off == sizeof(client->buf)) {
				ERRF(client, "%s",
				    "malformed reply: more than 1026 bytes recv'd and yet no CRLF");
				client->proto_err = 1;
				return -1;
			}
		}
	}

end:
	if ((r = parse_reply(client)) == -1) {
		ERRF(client, "%s", "malformed reply: can't parse header");
		client->proto_err = 1;
	}
	return r;
}

static int
parse_reply(struct phos_client *client)
{
	char	*e;
	size_t	 len;

	client->state = S_REPLY_READY;

	if (client->off < 4)
		return -1;

	if (!isdigit(client->buf[0]) || !isdigit(client->buf[1]))
		return -1;

	client->code = (client->buf[0] - '0') * 10 + (client->buf[1] - '0');

	if (!isspace(client->buf[2]))
		return -1;

	advance_buf(client, 3);
	if ((e = memmem(client->buf, client->off, "\r\n", 2)) == NULL)
		return -1;
	*e = '\0';
	len = e - client->buf;

	client->meta = strdup(client->buf);
	if (client->meta == NULL) {
		client->c_errno = errno;
		return -1;
	}

	advance_buf(client, len+2);
	client->meta = client->buf;
	return PHOS_WANT_READ;
}

static int
close_conn(struct phos_client *client)
{
	int r;

	client->state = S_CLOSING;

	if ((r = client->io->close(client->tls)) == 0)
		client->state = S_EOF;
	if (r == -1) {
		ERRF(client, "TLS close error: %s", client->io->err(client->tls));
		client->io_err = 1;
	}

	return r;
}

static inline int
run_tick(struct phos_client *client)
{
	/* otherwise run a tick */
	switch (client->state) {
	case S_START:
		return open_conn(client);
#if HAVE_ASR_RUN
	case S_RESOLUTION:
		return async_resolv(client);
#endif
	case S_CONNECT:
		return do_connect(client);
	case S_HANDSHAKE:
		return setup_tls(client);
	case S_POST_HANDSHAKE:
	case S_WRITING_REQ:
		return write_request(client);
	case S_READING_HEADER:
		return read_reply(client);
	case S_REPLY_READY:
	case S_BODY:
		/*
		 * it's an error to call a function that call into
		 * until_state after that phos_client_response has
		 * successfully returned 1.
		 */
		ERRF(client, "%s",
		    "calling into something that waited while you should read the body instead.");
		client->proto_err = 1;
		return -1;
	case S_CLOSING:
		return close_conn(client);
	case S_EOF:
		return 0;
	default:
		/* calling when already in error? */
		client->proto_err = 1;
		return -1;
	}
}

static void
clear_data(struct phos_client *client)
{
	if (client->fd != -1) {
		close(client->fd);
		client->fd = -1;
	}
	client->meta = NULL;
	client->code = 0;

	free(client->req);
	client->req = NULL;
}

static int
until_state(struct phos_client *client, int state)
{
	int r;

	if (client->state == S_EOF && state == S_EOF)
		return 0;

	if (client->state == S_EOF ||
	    client->state == S_ERROR ||
	    client->state == S_BODY) {
		client->proto_err = 1;
		return -1;
	}

	if (client->state >= state)
		return 1;

	if ((r = run_tick(client)) == -1)
		client->state = S_ERROR;

	if (client->state == S_ERROR || client->state == S_EOF)
		clear_data(client);

	return r;
}

static int
until_state_sync(struct phos_client *client, int state)
{
	struct pollfd	pfd;
	int		r;

	for (;;) {
		switch (r = until_state(client, state)) {
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			pfd.fd = client->fd;
			pfd.events = r == PHOS_WANT_READ ? POLLIN : POLLOUT;
			if (poll(&pfd, 1, -1) == -1) {
				client->c_errno = errno;
				ERRF(client, "poll: %s", strerror(client->c_errno));
				return -1;
			}
			break;
		default:
			return r;
		}
	}
}


/* public api */

struct phos_client *
phos_client_new(void)
{
	struct phos_client *client;

	if ((client = calloc(1, sizeof(*client))) == NULL)
		return NULL;

	if (phos_client_init(client) == -1) {
		free(client);
		return NULL;
	}

	return client;
}

int
phos_client_init(struct phos_client *client)
{
	explicit_bzero(client, sizeof(*client));

	client->fd = -1;
	client->io = &phos_libtls;

	if ((client->tls = client->io->client_new()) == NULL) {
		client->io_err = 1;
		return -1;
	}

	return 0;
}

int
phos_client_req(struct phos_client *client, const char *host, const char *port,
    const char *req)
{
	size_t		 len;
	const char	*p = "1965";

	if (client->state != S_START &&
	    client->state != S_EOF &&
	    client->state != S_ERROR) {
		client->state = S_ERROR;
		return -1;
	}

	if (port != NULL && *port != '\0')
		p = port;

	len = sizeof(client->host);
	if (strlcpy(client->host, host, len) >= len) {
		ERRF(client, "host too long: max allowed %zu bytes", len);
		client->proto_err = 1;
		return -1;
	}

	len = sizeof(client->port);
	if (strlcpy(client->port, p, len) >= len) {
		ERRF(client, "port too long: max allowed %zu bytes", len);
		client->proto_err = 1;
		return -1;
	}

	/* URL + \client\n */
	if (strlen(req) > 1026) {
		ERRF(client, "request too long: max allowed %d", 1026);
		client->proto_err = 1;
		return -1;
	}

	if ((client->req = strdup(req)) == NULL) {
		client->c_errno = errno;
		ERRF(client, "strdup: %s", strerror(client->c_errno));
		return -1;
	}

	client->state = S_START;
	return 0;
}

int
phos_client_req_uri(struct phos_client *client, struct phos_uri *uri)
{
	/* URL + \client\n\0 */
	char	buf[1027];

	if (!phos_serialize_uri(uri, buf, 1025)) {
		ERRF(client, "%s", "can't serialize URI");
		client->proto_err = 1;
		return -1;
	}

	strlcat(buf, "\r\n", sizeof(buf));

	return phos_client_req(client, uri->host, uri->port, buf);
}

int
phos_client_handshake(struct phos_client *client)
{
	return until_state(client, S_POST_HANDSHAKE);
}

int
phos_client_handshake_sync(struct phos_client *client)
{
	return until_state_sync(client, S_POST_HANDSHAKE);
}

int
phos_client_response(struct phos_client *client)
{
	return until_state(client, S_REPLY_READY);
}

int
phos_client_response_sync(struct phos_client *client)
{
	return until_state_sync(client, S_REPLY_READY);
}

ssize_t
phos_client_read(struct phos_client *client, void *data, size_t len)
{
	size_t	l;
	ssize_t	r;

	if (client->state == S_REPLY_READY) {
		if (client->off > 0) {
			l = MIN(len, client->off);
			memcpy(data, client->buf, l);
			advance_buf(client, l);
			return l;
		}
		client->state = S_BODY;
	}

	if (client->state == S_CLOSING ||
	    client->state == S_EOF)
		return 0;

	if (client->state != S_BODY) {
		ERRF(client, "%s",
		    "called phos_client_read on a non-ready client");
		client->proto_err = 1;
		return -1;
	}

	r = client->io->read(client->tls, data, len);
	if (r == -1) {
		ERRF(client, "TLS read error: %s", client->io->err(client->tls));
		client->state = S_ERROR;
		client->io_err = 1;
		clear_data(client);
	}
	if (r == 0)
		client->state = S_CLOSING;
	return r;
}

ssize_t
phos_client_read_sync(struct phos_client *client, void *data, size_t len)
{
	ssize_t		r;
	struct pollfd	pfd;

	for (;;) {
		switch (r = phos_client_read(client, data, len)) {
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			pfd.fd = client->fd;
			pfd.events = r == PHOS_WANT_READ ? POLLIN : POLLOUT;
			if (poll(&pfd, 1, -1) == -1) {
				client->c_errno = errno;
				ERRF(client, "poll: %s", strerror(client->c_errno));
				return -1;
			}
			break;
		default:
			return r;
		}
	}
}

int
phos_client_abort(struct phos_client *client)
{
#if HAVE_ASR_RUN
	if (client->state == S_RESOLUTION) {
		asr_abort(client->asr);
		client->asr = NULL;

		free(client->req);
		client->req = NULL;

		client->state = S_EOF;
		return 0;
	}
#endif

	if (client->state == S_START ||
	    client->state == S_EOF   ||
	    client->state == S_ERROR) {
		ERRF(client, "%s", "called abort on an non-ready client");
		client->state = S_ERROR;
		client->proto_err = 1;
		clear_data(client);
		return -1;
	}

	client->state = S_CLOSING;
	return until_state(client, S_EOF);
}

int
phos_client_abort_sync(struct phos_client *client)
{
	int r;

	switch (r = phos_client_abort(client)) {
	case 0:
	case -1:
		return r;
	default:
		return phos_client_close_sync(client);
	}
}

int
phos_client_close(struct phos_client *client)
{
	return until_state(client, S_EOF);
}

int
phos_client_close_sync(struct phos_client *client)
{
	return until_state_sync(client, S_EOF);
}

int
phos_client_del(struct phos_client *client)
{
	if (client->io->free(client->tls) == -1)
		return -1;

	return 0;
}

int
phos_client_free(struct phos_client *client)
{
	if (phos_client_del(client) == -1)
		return -1;
	free(client);
	return 0;
}


/* accessors */

int
phos_client_fd(struct phos_client *client)
{
	return client->fd;
}

int
phos_client_rescode(struct phos_client *client)
{
	return client->code;
}

const char *
phos_client_resmeta(struct phos_client *client)
{
	return client->meta;
}
