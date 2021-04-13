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

#include <errno.h>
#include <err.h>
#include <phos.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void *
io_client_new(void)
{
	return malloc(sizeof(int));
}

static void *
io_server_new(void)
{
	return malloc(sizeof(int));
}

static int
io_setup_client_socket(void *data, int fd, const char *servname)
{
	*(int*)data = fd;
	return 1;
}

static void *
io_setup_server_client(void *data, int fd)
{
	int *d;

	if ((d = malloc(sizeof(int))) == NULL)
		return NULL;

	*(int*)d = fd;
	return d;
}

static int
io_load_keypair(void *data, const uint8_t *m1, size_t l1,
    const uint8_t *m2, size_t l2)
{
	return 1;
}

static int
io_handshake(void *data)
{
	return 1;
}

static ssize_t
io_write(void *d, const void *data, size_t len)
{
	ssize_t w;
	if ((w = write(1, data, len)) == -1)
		return PHOS_WANT_WRITE;
	return w;
}

static ssize_t
io_read(void *d, void *data, size_t len)
{
	ssize_t w;
	if ((w = read(*(int*)d, data, len)) == -1)
		return PHOS_WANT_READ;
	return w;
}

static const char *
io_err(void *d)
{
	return strerror(errno);
}

static int
io_close(void *d)
{
	close(*(int*)d);
	return 1;
}

static int
io_free(void *d)
{
	free(d);
	return 1;
}

static struct phos_io plain_io = {
	.client_new =		io_client_new,
	.server_new =		io_server_new,
	.setup_client_socket =	io_setup_client_socket,
	.setup_server_client =	io_setup_server_client,
	.load_keypair =		io_load_keypair,
	.handshake =		io_handshake,
	.write =		io_write,
	.read =			io_read,
	.err =			io_err,
	.close =		io_close,
	.free =			io_free,
};

int
main(void)
{
	struct phos_server	 serv;
	struct phos_req		 req;
	struct phos_uri		 uri;
	const char		*str;

	if (phos_server_init_from_fd(&serv, 0) == -1)
		errx(1, "phos_server_init failed");

	serv.io = &plain_io;

	if (phos_server_accept_fd(&serv, &req, 0) == -1)
		errx(1, "phos_server_accept_sync failed");

	if (phos_req_handshake_sync(&req) == -1)
		errx(1, "failed handshake");

	/* can access peer cert data */

	if (phos_req_read_request_sync(&req) == -1)
		errx(1, "failed to read request");

	if (!phos_parse_absolute_uri(req.line, &uri))
		errx(1, "can't parse %s", req.line);

	warnx("client requested: %s", req.line);

	if (phos_req_reply_sync(&req, 20, "text/gemini") == -1)
		errx(1, "failed to write header");

	str = "# hello, world\n";
	if (phos_req_write_sync(&req, str, strlen(str)) == -1)
		errx(1, "failed to write response");

	phos_req_close_sync(&req);

	phos_req_del(&req);

	phos_server_del(&serv);
	return 0;
}
