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

/* #include "compat.h" */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <phos.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline int	mark_nonblock(int);

#if HAVE_ASR_RUN
# include <asr.h>
static int		run_asr_query(struct phos_client*);
#else
static int		blocking_resolv(struct phos_client*, const char*, const char*,
			    struct addrinfo*);
#endif

static int		open_conn(struct phos_client*);
static int		do_connect(struct phos_client*);
static int		setup_tls(struct phos_client*);
static int		write_request(struct phos_client*);
static int		read_reply(struct phos_client*);
static int		parse_reply(struct phos_client*);
static int		copy_body(struct phos_client*);
static int		close_conn(struct phos_client*);

struct phos_resolv {
	struct addrinfo		*servinfo;
	struct addrinfo		*p;

#ifdef HAVE_ASR_RUN
	struct asr_query	*async;
#endif
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

#if HAVE_ASR_RUN
static int
run_asr_query(struct phos_client *client)
{
	struct phos_resolv	*asr = client->asr;
	struct asr_result	 res;

	client->state = PCS_RESOLUTION;

	if (asr_run(asr->async, &res)) {
		if (res.ar_gai_errno != 0) {
			client->gai_errno = res.ar_gai_errno;
			free(asr);
			client->asr = NULL;
			return -1;
		}

		asr->servinfo = res.ar_addrinfo;
		asr->p = req.ar_addrinfo;
		return do_connect(client);
	}

	client->re = &run_asr_query;
	return res.cond == ASR_WANT_READ ? PHOS_WANT_READ : PHOS_WANT_WRITE;
}
#else
static int
blocking_resolv(struct phos_client *client, const char *host, const char *proto,
    struct addrinfo *hints)
{
	struct phos_resolv	*r = client->resolver;
	int status;

	if ((status = getaddrinfo(host, proto, hints, &r->servinfo)) != 0) {
		client->gai_errno = status;
		free(r);
		return -1;
	}

	client->fd = -1;
	r->p = r->servinfo;
	return do_connect(client);
}
#endif

static int
open_conn(struct phos_client *client)
{
	struct addrinfo		 hints;
	struct phos_resolv	*res;
	const char		*proto = "1965";

	if (*client->port != '\0')
		proto = client->port;

	if ((res = calloc(1, sizeof(*res))) == NULL)
		return -1;

	client->resolver = res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

#ifdef HAVE_ASR_RUN
	res->async = getaddrinfo_async(client->host, proto, &hints, NULL);
	if (res->async == NULL) {
		free(asr);
		client->resolver = NULL;
		return -1;
	}

	return run_asr_query(client);
#else
	return blocking_resolv(client, client->host, proto, &hints);
#endif
}

static int
do_connect(struct phos_client *client)
{
	struct phos_resolv	*asr = client->resolver;
	socklen_t		 len = sizeof(client->c_errno);
	struct addrinfo		*p;

	client->state = PCS_CONNECT;

	for (p = asr->p; p != NULL; p = p->ai_next) {
		asr->p = p;

		if (client->fd != -1) {
			if (getsockopt(client->fd, SOL_SOCKET, SO_ERROR,
			    &client->c_errno, &len) == -1 || client->c_errno != 0) {
				close(client->fd);
				client->fd = -1;
				continue;
			}
			break;
		}

		client->fd = socket(asr->p->ai_family, asr->p->ai_socktype,
		    asr->p->ai_protocol);
		if (client->fd == -1) {
			client->c_errno = errno;
			continue;
		}

		if (mark_nonblock(client->fd) == -1) {
			client->c_errno = errno;
			return -1;
		}

		if (connect(client->fd, p->ai_addr, p->ai_addrlen) == 0)
			break;
		return PHOS_WANT_WRITE;
	}

	freeaddrinfo(asr->servinfo);
	free(asr);
	client->resolver = NULL;

	if (p == NULL)
		return -1;

	return setup_tls(client);
}

static int
setup_tls(struct phos_client *client)
{
	int r;

	client->state = PCS_HANDSHAKE;

	if ((r = client->io->setup_socket(client)) == -1) {
		client->io_err = 1;
		return r;
	}
	if (r != 1)
		return r;

	client->state = PCS_POST_HANDSHAKE;
	return PHOS_WANT_WRITE;
}

static int
write_request(struct phos_client *client)
{
	ssize_t	r;
	size_t	len;

	client->state = PCS_WRITING_REQ;

	len = strlen(client->buf);
	for (;;) {
		r = client->io->write(client, client->buf + client->off,
		    len - client->off);
		switch (r) {
		case -1:
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
	size_t		 len;
	ssize_t		 r;
	char		*buf;

	client->state = PCS_READING_HEADER;

	buf = client->buf + client->off;
	len = sizeof(client->buf) - client->off;

	for (;;) {
		switch (r = client->io->read(client, buf, len)) {
		case -1:
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
				client->proto_err = 1;
				return -1;
			}
		}
	}

end:
	if ((r = parse_reply(client)) == -1)
		client->proto_err = 1;
	return r;
}


static int
parse_reply(struct phos_client *client)
{
	char	*e;
	size_t	 len;

	client->state = PCS_REPLY_READY;

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
	return PHOS_WANT_READ;
}

static int
copy_body(struct phos_client *client)
{
	ssize_t r;

	client->state = PCS_BODY;

	r = client->io->read(client, client->buf, sizeof(client->buf));
	switch (r) {
	case -1:
		client->io_err = 1;
	case 0:
	case PHOS_WANT_WRITE:
	case PHOS_WANT_READ:
		return r;
	default:
		client->off = r;
		return 1;
	}
}

static int
close_conn(struct phos_client *client)
{
	int r;

	client->state = PCS_CLOSING;

	if ((r = client->io->close(client)) == 0) {
		close(client->fd);
		client->fd = -1;
		client->state = PCS_EOF;
	}
	if (r == -1)
		client->io_err = 1;

	return r;
}


/* public API */

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
	memset(client, 0, sizeof(*client));

	client->fd = -1;
	client->io = &phos_libtls;
	client->state = PCS_EOF;

	return 0;
}

int
phos_client_req(struct phos_client *client, const char *host, const char *port,
    const char *req)
{
	size_t		 len;
	const char	*p = "1965";

	if ((client->io->client_init(client)) == -1) {
		client->state = PCS_ERROR;
		return -1;
	}

	if (port != NULL && *port != '\0')
		p = port;

	len = sizeof(client->host);
	if (strlcpy(client->host, host, len) >= len) {
		client->state = PCS_ERROR;
		return -1;
	}

	len = sizeof(client->port);
	if (strlcpy(client->port, p, len) >= len) {
		client->state = PCS_ERROR;
		return -1;
	}

	if (strlen(req) > 1024) {
		client->state = PCS_ERROR;
		return -1;
	}

	len = sizeof(client->buf);
	if (strlcpy(client->buf, req, len) >= len) {
		client->state = PCS_ERROR;
		return -1;
	}

	client->state = PCS_START;
	return 0;
}

int
phos_client_req_uri(struct phos_client *client, struct phos_uri *uri)
{
	size_t len = sizeof(client->buf);

	if (!phos_serialize_uri(uri, client->buf, len)) {
		client->state = PCS_ERROR;
		return -1;
	}

	if (strlcat(client->buf, "\r\n", len) >= len) {
		client->state = PCS_ERROR;
		return -1;
	}

	return phos_client_req(client, uri->host, uri->port, client->buf);
}

static int
do_run(struct phos_client *client)
{
	switch (client->state) {
	case PCS_START:
		return open_conn(client);
#ifdef HAVE_ASR_RUN
	case PCS_RESOLUTION:
		return run_asr_query(client);
#endif
	case PCS_CONNECT:
		return do_connect(client);
	case PCS_HANDSHAKE:
		return setup_tls(client);
	case PCS_POST_HANDSHAKE:
	case PCS_WRITING_REQ:
		return write_request(client);
	case PCS_READING_HEADER:
		return read_reply(client);
	case PCS_REPLY_READY:
		client->state = PCS_BODY;
		if (client->code < 20 || client->code >= 30) {
			/* this reply shouldn't have a body */
			client->state = PCS_CLOSING;
			return do_run(client);
		}
		if (client->off != 0)
			return 1;
		/* fallthrough */
	case PCS_BODY:
		client->off = 0;
		return copy_body(client);
	case PCS_CLOSING:
		return close_conn(client);
	case PCS_EOF:
		return 0;
	default:
		return -1;
	}
}

int
phos_client_run(struct phos_client *client)
{
	int r;

	if ((r = do_run(client)) == -1) {
		if (client->fd != -1) {
			close(client->fd);
			client->fd = -1;
		}
		client->state = PCS_ERROR;
	}

	if (r == 0) {
		client->state = PCS_EOF;
	}

	return r;
}

int
phos_client_run_sync(struct phos_client *client)
{
	struct pollfd	pfd;
	int		r;
	enum phos_client_state cs;

	for (;;) {
		cs = client->state;
		switch (r = phos_client_run(client)) {
		case -1:
		case 0:
		case 1:
			return r;
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			if (cs != client->state)
				return 1;
			pfd.fd = client->fd;
			pfd.events = r == PHOS_WANT_READ ? POLLIN : POLLOUT;
			if (poll(&pfd, 1, -1) == -1) {
				client->c_errno = errno;
				return -1;
			}
		}
	}
}

int
phos_client_fd(struct phos_client *client)
{
	return client->fd;
}

enum phos_client_state
phos_client_state(struct phos_client *client)
{
	return client->state;
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

const char *
phos_client_buf(struct phos_client *client)
{
	return client->buf;
}

size_t
phos_client_bufsize(struct phos_client *client)
{
	return client->off;
}

int
phos_client_abort(struct phos_client *client)
{
#if HAVE_ASR_RUN
	struct phos_resolv *res = client->resolver;

	if (client->state == PCS_RESOLUTION) {
		asr_abort(res->async);

		if (client->resolver != NULL)
			free(client->resolver);

		client->resolver = NULL;
		return 0;
	}
#endif

	if (client->state == PCS_START ||
	    client->state == PCS_EOF   ||
	    client->state == PCS_ERROR)
		return -1;

	client->state = PCS_CLOSING;
	return 0;
	/* return phos_client_run(client); */
}

int
phos_client_close(struct phos_client *client)
{
	if (client->state != PCS_EOF)
		return -1;

	free(client->meta);
	client->meta = NULL;
	client->code = 0;

	client->io->close(client);

	return 0;
}

int
phos_client_del(struct phos_client *client)
{
	if (client->tls != NULL)
		client->io->free(client);
	explicit_bzero(client, sizeof(*client));

	return 0;
}

void
phos_client_free(struct phos_client *client)
{
	phos_client_del(client);
	free(client);
}
