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

#include <phos.h>
#include <stdlib.h>
#include <tls.h>

struct phos_libtls {
	struct tls_config	*conf;
	struct tls		*ctx;
	int			 keyp_loaded;
};

static void	*pltls_client_new(void);
static void	*pltls_server_new(void);
static int	 pltls_setup_client_socket(void*, int, const char*);
static void	*pltls_setup_server_client(void*, int);
static int	 pltls_load_keypair(void*, const uint8_t*, size_t, const uint8_t*, size_t);
static int	 pltls_handshake(void*);
static ssize_t	 pltls_write(void*, const void*, size_t);
static ssize_t	 pltls_read(void*, void*, size_t);
const char	*pltls_err(void*);
static int	 pltls_close(void*);
static int	 pltls_free(void*);

static void *
pltls_client_new(void)
{
	struct phos_libtls *tls;

	if ((tls = calloc(1, sizeof(*tls))) == NULL)
		return NULL;

	if ((tls->conf = tls_config_new()) == NULL) {
		free(tls);
		return NULL;
	}

	tls_config_insecure_noverifycert(tls->conf);
	/* tls_config_insecure_noveryname(tlsconf); */

	return tls;
}

static void *
pltls_server_new(void)
{
	struct phos_libtls *tls;

	if ((tls = calloc(1, sizeof(*tls))) == NULL)
		goto err;

	if ((tls->conf = tls_config_new()) == NULL)
		goto err;

	/* optionally accept client certs, but don't try to verify them */
	tls_config_verify_client_optional(tls->conf);
	tls_config_insecure_noverifycert(tls->conf);

	return tls;

err:
	if (tls != NULL) {
		if (tls->conf != NULL)
			tls_config_free(tls->conf);
		free(tls);
	}

	return NULL;
}

static int
pltls_setup_client_socket(void *data, int fd, const char *servname)
{
	struct phos_libtls *tls = data;

	if ((tls->ctx = tls_client()) == NULL)
		return -1;
	if (tls_configure(tls->ctx, tls->conf) == -1)
		return -1;
	if (tls_connect_socket(tls->ctx, fd, servname) == -1)
		return -1;
	return 1;
}

static void *
pltls_setup_server_client(void *data, int fd)
{
	struct phos_libtls *tls = data;
	struct phos_libtls *peer;

	if (tls->ctx == NULL) {
		if ((tls->ctx = tls_server()) == NULL)
			return NULL;
		if (tls_configure(tls->ctx, tls->conf) == -1) {
			tls_free(tls->ctx);
			tls->ctx = NULL;
			return NULL;
		}
	}

	if ((peer = calloc(1, sizeof(*peer))) == NULL)
		return NULL;

	if (tls_accept_socket(tls->ctx, &peer->ctx, fd) == -1) {
		free(peer);
		return NULL;
	}

	return peer;
}

static int
pltls_load_keypair(void *data, const uint8_t *cert, size_t certlen,
    const uint8_t *key, size_t keylen)
{
	struct phos_libtls *tls = data;

	if (!tls->keyp_loaded) {
		tls->keyp_loaded = 1;
		return tls_config_set_keypair_mem(tls->conf, cert, certlen,
		    key, keylen);
	}

	return tls_config_add_keypair_mem(tls->conf, cert, certlen,
	    key, keylen);
}

static ssize_t
tls_to_phos(int isbool, ssize_t r)
{
	switch (r) {
	case TLS_WANT_POLLIN:
		return PHOS_WANT_READ;
	case TLS_WANT_POLLOUT:
		return PHOS_WANT_WRITE;
	default:
		if (isbool && r == 0)
			return 1;
		return r;
	}
}

static int
pltls_handshake(void *data)
{
	struct phos_libtls *tls = data;

	return tls_to_phos(1, tls_handshake(tls->ctx));
}

static ssize_t
pltls_write(void *data, const void *buf, size_t len)
{
	struct phos_libtls *tls = data;

	return tls_to_phos(0, tls_write(tls->ctx, buf, len));
}

static ssize_t
pltls_read(void *data, void *buf, size_t len)
{
	struct phos_libtls *tls = data;

	return tls_to_phos(0, tls_read(tls->ctx, buf, len));
}

const char *
pltls_err(void *data)
{
	struct phos_libtls *tls = data;

	return tls_error(tls->ctx);
}

static int
pltls_close(void *data)
{
	struct phos_libtls *tls = data;

	if (tls->ctx != NULL) {
		switch (tls_close(tls->ctx)) {
		case TLS_WANT_POLLIN:
			return PHOS_WANT_READ;
		case TLS_WANT_POLLOUT:
			return PHOS_WANT_WRITE;
		}
		tls_free(tls->ctx);
		tls->ctx = NULL;
	}

	return 0;
}

static int
pltls_free(void *data)
{
	struct phos_libtls *tls = data;

	tls_config_free(tls->conf);
	free(tls);

	return 0;
}
