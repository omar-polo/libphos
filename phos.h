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

#ifndef PHOS_H
#define PHOS_H

#ifdef __cplusplus
#extern "C" {
#endif

#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <tls.h>

#define PHOS_ERROR	-1
#define PHOS_WANT_READ	-2
#define PHOS_WANT_WRITE	-3

#define PHOS_URL_MAX_LEN 1024

struct phos_uri {
	char		scheme[32];
	char		host[1024];
	char		port[6];
	uint16_t	dec_port;
	char		path[1024];
	char		query[1024];
	char		fragment[32];
};

typedef void(*phos_reqcb)(char*, void*);

struct phos_server {
	int		fd;
	phos_reqcb	handlefn;
};

struct phos_client;

/* tls abstractions */
struct phos_tls {
	int	(*client_init)(struct phos_client*);
	int	(*setup_socket)(struct phos_client*);
	ssize_t	(*write)(struct phos_client*, const char*, size_t);
	ssize_t	(*read)(struct phos_client*, char*, size_t);
	int	(*close)(struct phos_client*);
	int	(*free)(struct phos_client*);
};

extern struct phos_tls phos_libtls;

/* client.c */

enum phos_client_state {
	PCS_START,
	PCS_RESOLUTION,
	PCS_CONNECT,
	PCS_HANDSHAKE,
	PCS_POST_HANDSHAKE,
	PCS_WRITING_REQ,
	PCS_READING_HEADER,
	PCS_REPLY_READY,
	PCS_BODY,
	PCS_CLOSING,
	PCS_EOF,
	PCS_ERROR,
	PCS__MAX,		/* unused, only for bound checking */
};

struct phos_client {
	/* internals */
	void			*tls;
	struct phos_tls		*io;
	void			*resolver;
	char			 host[NI_MAXHOST+1];
	char			 port[NI_MAXSERV+1];
	char			 buf[1030];
	size_t			 off;

	/* file descriptor of the request, -1 otherwise  */
	int			 fd;
	enum phos_client_state	 state;

	int			 io_err;
	int			 proto_err;
	int			 gai_errno;
	int			 c_errno;

	int			 code;
	char			*meta;
};

struct phos_client	*phos_client_new(void);
int			 phos_client_init(struct phos_client*);
void			 phos_client_set_io(struct phos_client*, struct phos_tls*);
int			 phos_client_req(struct phos_client*, const char*, const char*, const char*);
int			 phos_client_req_uri(struct phos_client*, struct phos_uri*);
int			 phos_client_run(struct phos_client*);
int			 phos_client_run_sync(struct phos_client*);
int			 phos_client_fd(struct phos_client*);
enum phos_client_state	 phos_client_state(struct phos_client*);
int			 phos_client_rescode(struct phos_client*);
const char		*phos_client_resmeta(struct phos_client*);
const char		*phos_client_buf(struct phos_client*);
size_t			 phos_client_bufsize(struct phos_client*);
int			 phos_client_abort(struct phos_client*);
int			 phos_client_close(struct phos_client*);
int			 phos_client_del(struct phos_client*);
void			 phos_client_free(struct phos_client*);

/* server.c */
int	 phos_server_init(struct phos_server*, const char*, const char*);
int	 phos_server_run(struct phos_server*, void*);
int	 phos_server_run_sync(struct phos_server*, void*);

/* uri.c */
int	 phos_parse_uri_reference(const char*, struct phos_uri*);

int	 phos_parse_absolute_uri(const char*, struct phos_uri*);

/* int	 phos_resolve_uri_from(const struct phos_uri*, const struct phos_uri*, */
    /* struct phos_uri*); */

int	 phos_resolve_uri_from_str(const struct phos_uri*, const char *,
    struct phos_uri*);

int	 phos_serialize_uri(const struct phos_uri*, char*, size_t);

#ifdef __cplusplus
}
#endif

#endif	/* PHOS_H */
