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

#include <phos.h>
#include <stdlib.h>
#include <tls.h>

struct phos_libtls {
	struct tls_config	*conf;
	struct tls		*ctx;
};

static int	pltls_init(struct phos_client*);
static int	pltls_setup_socket(struct phos_client*);
static ssize_t	pltls_write(struct phos_client*, const char*, size_t);
static ssize_t	pltls_read(struct phos_client*, char*, size_t);
static int	pltls_close(struct phos_client*);
static int	pltls_free(struct phos_client*);

struct phos_tls phos_libtls = {
	.client_init =	pltls_init,
	.setup_socket =	pltls_setup_socket,
	.write =	pltls_write,
	.read =		pltls_read,
	.close =	pltls_close,
	.free =		pltls_free,
};

static int
pltls_init(struct phos_client *client)
{
	struct phos_libtls *tls;

	if ((tls = calloc(1, sizeof(*tls))) == NULL)
		return -1;

	if ((tls->conf = tls_config_new()) == NULL) {
		free(client->tls);
		client->tls = NULL;
		return -1;
	}

	client->tls = tls;

	tls_config_insecure_noverifycert(tls->conf);
	/* tls_config_insecure_noveryname(tlsconf); */

	return 0;
}

static int
pltls_setup_socket(struct phos_client *client)
{
	struct phos_libtls *tls = client->tls;

	if (tls->ctx == NULL) {
		if ((tls->ctx = tls_client()) == NULL)
			return -1;
		if (tls_configure(tls->ctx, tls->conf) == -1)
			return -1;
		if (tls_connect_socket(tls->ctx, client->fd, client->host) == -1)
			return -1;
	}

	switch (tls_handshake(tls->ctx)) {
	case -1:
		return -1;
	case TLS_WANT_POLLIN:
		return PHOS_WANT_READ;
	case TLS_WANT_POLLOUT:
		return PHOS_WANT_WRITE;
	default:
		return 1;
	}
}

static ssize_t
pltls_write(struct phos_client *client, const char *buf, size_t len)
{
	struct phos_libtls *tls = client->tls;
	ssize_t r;

	switch (r = tls_write(tls->ctx, buf, len)) {
	case TLS_WANT_POLLIN:
		return PHOS_WANT_READ;
	case TLS_WANT_POLLOUT:
		return PHOS_WANT_WRITE;
	default:
		/* 0, -1 or the bytes written */
		return r;
	}
}

static ssize_t
pltls_read(struct phos_client *client, char *buf, size_t len)
{
	struct phos_libtls *tls = client->tls;
	ssize_t r;

	switch (r = tls_read(tls->ctx, buf, len)) {
	case TLS_WANT_POLLIN:
		return PHOS_WANT_READ;
	case TLS_WANT_POLLOUT:
		return PHOS_WANT_WRITE;
	default:
		/* 0, -1 or the bytes written */
		return r;
	}
}

static int
pltls_close(struct phos_client *client)
{
	struct phos_libtls *tls = client->tls;

	if (tls->ctx != NULL) {
		switch (tls_close(tls->ctx)) {
		case TLS_WANT_POLLIN:
			return PHOS_WANT_READ;
		case TLS_WANT_POLLOUT:
			return PHOS_WANT_WRITE;
		}
	}

	tls_free(tls->ctx);
	tls->ctx = NULL;
	return 0;
}

static int
pltls_free(struct phos_client *client)
{
	struct phos_libtls *tls = client->tls;

	tls_config_free(tls->conf);
	free(tls);

	client->tls = NULL;

	return 0;
}
