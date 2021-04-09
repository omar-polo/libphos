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

#include "phos.h"

#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

struct phos_server *
phos_server_new(const char *hn, const char *port)
{
	struct phos_server *serv;

	if ((serv = calloc(1, sizeof(*serv))) == NULL)
		return NULL;

	if (phos_server_init(serv, hn, port) == -1) {
		free(serv);
		return NULL;
	}

	return serv;
}

int
phos_server_init(struct phos_server *serv, const char *hn, const char *port)
{
	int sock, v;
	struct addrinfo hints, *res;

	if (hn != NULL && *hn == '\0')
		hn = NULL;

	if (port == NULL || *port == '\0')
		port = "1965";

	explicit_bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(hn, port, &hints, &res) != 0)
		return -1;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		goto err;

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) == -1)
		goto err;

	v = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)) == -1)
		goto err;

	if (bind(sock, res->ai_addr, res->ai_addrlen) == -1)
		goto err;

	if (listen(sock, 16) == -1)
                goto err;

	freeaddrinfo(res);
	return phos_server_init_from_fd(serv, sock);

err:
        freeaddrinfo(res);
	close(sock);
	serv->fd = -1;
	return -1;
}

int
phos_server_init_from_fd(struct phos_server *serv, int fd)
{
	serv->io = &phos_libtls;
	if ((serv->tls = serv->io->server_new()) == NULL) {
		serv->io_err = 1;
		return -1;
	}

	if (mark_nonblock(fd) == -1) {
		serv->c_errno = errno;
		return -1;
	}
	serv->fd = fd;
	return 0;
}

static inline int
phos_read_file(const char *path, uint8_t **retm, size_t *retl)
{
	struct stat	st;
	ssize_t		n;
	int		fd, e;

	*retm = NULL;
	if ((fd = open(path, O_RDONLY)) == -1)
		return errno;
	if (fstat(fd, &st) != 0)
		goto err;
	*retl = (size_t)st.st_size;
	if ((*retm = malloc(*retl)) == NULL)
		goto err;
	n = read(fd, *retm, *retl);
	if (n < 0 || (size_t)n != *retl)
		goto err;
	close(fd);
	return 0;

err:
	e = errno;
	close(fd);
	if (*retm != NULL) {
		free(*retm);
		*retm = NULL;
	}
	*retl = 0;
	return e;
}

int
phos_server_load_keypair_file(struct phos_server *serv, const char *cert, const char *key)
{
	uint8_t	*certm, *keym;
	size_t	 certlen, keylen;
	int	 r;

	if ((r = phos_read_file(cert, &certm, &certlen)) != 0) {
		serv->c_errno = r;
		return -1;
	}

	if ((r = phos_read_file(key, &keym, &keylen)) != 0) {
		free(certm);
		serv->c_errno = r;
		return -1;
	}

	r = phos_server_load_keypair_mem(serv, certm, certlen, keym, keylen);
	free(certm);
	free(keym);
	return r;
}

int
phos_server_load_keypair_mem(struct phos_server *serv,
    const uint8_t *certmem, size_t certlen,
    const uint8_t *keymem, size_t keylen)
{
	return serv->io->load_keypair(serv->tls, certmem, certlen, keymem, keylen);
}

int
phos_server_accept(struct phos_server *serv, struct phos_req *req)
{
	struct sockaddr	*saddr;
	socklen_t	 len;
	int		 fd;

	saddr = (struct sockaddr*)&req->addr;
	len = sizeof(req->addr);
	if ((fd = accept(serv->fd, saddr, &len)) == -1) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			return PHOS_WANT_READ;
		serv->c_errno = errno;
		return -1;
	}

	return phos_server_accept_fd(serv, req, fd);
}

int
phos_server_accept_fd(struct phos_server *serv, struct phos_req *req, int fd)
{
	explicit_bzero(req, sizeof(*req));

	req->fd = fd;

	if (mark_nonblock(req->fd) == -1) {
		serv->c_errno = errno;
		goto err;
	}

	req->io = serv->io;
	if ((req->tls = serv->io->setup_server_client(serv->tls, fd)) == NULL) {
		serv->io_err = 1;
		goto err;
	}

	return 0;

err:
	close(req->fd);
	req->fd = -1;
	return -1;
}

int
phos_server_accept_sync(struct phos_server *serv, struct phos_req *req)
{
	int		r;
	struct pollfd	pfd;

	for (;;) {
		if ((r = phos_server_accept(serv, req)) == -1)
			return -1;
		if (r == 0)
			return 0;

		pfd.fd = serv->fd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, -1) == -1) {
			serv->c_errno = errno;
			return -1;
		}
	}
}

int
phos_server_del(struct phos_server *serv)
{
	serv->io->close(serv->tls);
	close(serv->fd);
	return 0;
}

int
phos_server_free(struct phos_server *serv)
{
	if (phos_server_del(serv) == -1)
		return -1;

	free(serv);
	return 0;
}


/* req */

struct phos_req *
phos_req_new(void)
{
	return calloc(1, sizeof(struct phos_req));
}

static int
phos_poll(struct phos_req *req, int cond)
{
	struct pollfd pfd;

	pfd.fd = req->fd;
	pfd.events = cond == PHOS_WANT_READ ? POLLIN : POLLOUT;
	if (poll(&pfd, 1, -1) == -1)
		return -1;
	return 0;
}

int
phos_req_handshake(struct phos_req *req)
{
	return req->io->handshake(req->tls);
}

int
phos_req_handshake_sync(struct phos_req *req)
{
	int r;

	for (;;) {
		switch (r = phos_req_handshake(req)) {
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			if (phos_poll(req, r) == -1)
				return -1;
			break;
		default:
			return r;
		}
	}
}

int
phos_req_read_request(struct phos_req *req)
{
	char	*buf, *e;
	size_t	 len;
	ssize_t	 r;

	for (;;) {
		buf = req->line + req->off;
		len = sizeof(req->line) - req->off;
		switch (r = req->io->read(req->tls, buf, len)) {
		case 0:
		case -1:
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			return r;
		default:
			req->off += r;
			if ((e = memmem(req->line, req->off, "\r\n", 2)) != NULL) {
				*e = '\0';
				return 1;
			} else if (req->off >= sizeof(req->line)) {
				req->proto_err = 1;
				return -1;
			}
		}
	}
}

int
phos_req_read_request_sync(struct phos_req *req)
{
        int r;

	for (;;) {
		switch (r = phos_req_read_request(req)) {
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			if (phos_poll(req, r) == -1)
				return -1;
			break;
		default:
			return r;
		}
	}
}

int
phos_req_reply(struct phos_req *req, int code, const char *meta)
{
	req->off = 0;
	req->code = code;
	if ((req->meta = strdup(meta)) == NULL)
		return -1;
	return 0;
}

int
phos_req_reply_flush(struct phos_req *req)
{
	char	buf[1030], *b;
	size_t	len;

	if ((len = snprintf(buf, sizeof(buf), "%d %s\r\n", req->code, req->meta))
	    >= sizeof(buf))
		return -1;

	if (req->off > len)
		return -1;

	b = buf + req->off;
	len -= req->off;

	return phos_req_write(req, b, len);
}

int
phos_req_reply_sync(struct phos_req *req, int code, const char *meta)
{
	int r;

	if (phos_req_reply(req, code, meta) == -1)
		return -1;

	for (;;) {
		switch (r = phos_req_reply_flush(req)) {
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			if (phos_poll(req, r) == -1)
				return -1;
			break;
		default:
			return r;
		}
	}
}

ssize_t
phos_req_write(struct phos_req *req, const void *data, size_t len)
{
	return req->io->write(req->tls, data, len);
}

int
phos_req_write_sync(struct phos_req *req, const void *data, size_t len)
{
	ssize_t	r;

	for (; len > 0;) {
		switch (r = phos_req_write(req, data, len)) {
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			if (phos_poll(req, r) == -1)
				return -1;
			break;
		case 0:
		case -1:
			return r;
		default:
			/* a bug in the io layer? */
			if (r > len)
				return -1;

			len -= r;
			data += r;
			break;
		}
	}

	return 1;
}

int
phos_req_close(struct phos_req *req)
{
	return req->io->close(req->tls);
}

int
phos_req_close_sync(struct phos_req *req)
{
	int r;

	for (;;) {
		switch (r = phos_req_close(req)) {
		case PHOS_WANT_READ:
		case PHOS_WANT_WRITE:
			if (phos_poll(req, r) == -1)
				return -1;
		default:
			return r;
		}
	}
}

int
phos_req_del(struct phos_req *req)
{
	if (req->io->free(req->tls) == -1)
		return -1;
	close(req->fd);
	free(req->meta);
	req->meta = NULL;
	explicit_bzero(req->line, sizeof(req->line));
	req->fd = -1;
	return 0;
}

int
phos_req_free(struct phos_req *req)
{
	if (phos_req_del(req) == -1)
		return -1;
	free(req);
	return 0;
}


/* accessors */

const char *
phos_req_request_line(struct phos_req *req)
{
	return req->line;
}

int
phos_req_sent_code(struct phos_req *req)
{
	return req->code;
}

const char *
phos_req_sent_meta(struct phos_req *req)
{
	return req->meta;
}
