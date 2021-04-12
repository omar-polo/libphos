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

#include <sys/types.h>
#include <sys/socket.h>

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

/* io abstraction */
struct phos_io {
	void		*(*client_new)(void);
	void		*(*server_new)(void);
	int		 (*setup_client_socket)(void*, int, const char*);
	void		*(*setup_server_client)(void*, int);
	int		 (*load_keypair)(void*, const uint8_t*, size_t, const uint8_t*, size_t);
	int		 (*handshake)(void*);
	ssize_t		 (*write)(void*, const void*, size_t);
	ssize_t		 (*read)(void*, void*, size_t);
	const char	*(*err)(void*);
	int		 (*close)(void*);
	int		 (*free)(void*);
};

extern struct phos_io phos_libtls;

/* client.c */

struct phos_client {
	/* internals */
	void			*tls;
	struct phos_io		*io;
	int			 state;
	struct addrinfo		*servinfo, *p;
	void			*asr;
	char			 host[NI_MAXHOST+1];
	char			 port[NI_MAXSERV+1];
	char			*req;
	char			 buf[1027];
	size_t			 off;

	/* file descriptor of the request, -1 otherwise  */
	int			 fd;

	int			 io_err;
	int			 proto_err;
	int			 gai_errno;
	int			 c_errno;
	char			*err;

	int			 code;
	char			*meta;
};

struct phos_client	*phos_client_new(void);
int			 phos_client_init(struct phos_client*);
int			 phos_client_req(struct phos_client*, const char*,
			     const char*, const char*);
int			 phos_client_req_uri(struct phos_client*, struct phos_uri*);
int			 phos_client_handshake(struct phos_client*);
int			 phos_client_handshake_sync(struct phos_client*);
int			 phos_client_response(struct phos_client*);
int			 phos_client_response_sync(struct phos_client*);
ssize_t			 phos_client_read(struct phos_client*, void*, size_t);
ssize_t			 phos_client_read_sync(struct phos_client*, void*, size_t);
int			 phos_client_abort(struct phos_client*);
int			 phos_client_abort_sync(struct phos_client*);
int			 phos_client_close(struct phos_client*);
int			 phos_client_close_sync(struct phos_client*);
int			 phos_client_del(struct phos_client*);
int			 phos_client_free(struct phos_client*);

int			 phos_client_fd(struct phos_client*);
int			 phos_client_rescode(struct phos_client*);
const char		*phos_client_resmeta(struct phos_client*);
const char		*phos_client_err(struct phos_client*);

/* server.c */

struct phos_server {
	int			 fd;
	void			*tls;
	struct phos_io		*io;
	int			 io_err;
	int			 c_errno;
	char			*err;
};

struct phos_req {
	/* internals */
	void			*tls;
	struct phos_io		*io;
	char			*meta;
	int			 code;

	int			 fd;
	struct sockaddr_storage	 addr;
	char			 line[1027];
	size_t			 off;

	int			 io_err;
	int			 proto_err;
	int			 c_errno;
	char			*err;
};

struct phos_server	*phos_server_new(const char*, const char*);
int			 phos_server_init(struct phos_server*, const char*, const char*);
int			 phos_server_init_from_fd(struct phos_server*, int);
int			 phos_server_load_keypair_file(struct phos_server*, const char*, const char*);
int			 phos_server_load_keypair_mem(struct phos_server*, const uint8_t*, size_t, const uint8_t*, size_t);
int			 phos_server_accept(struct phos_server*, struct phos_req*);
int			 phos_server_accept_fd(struct phos_server*, struct phos_req*, int);
int			 phos_server_accept_sync(struct phos_server*, struct phos_req*);
int			 phos_server_del(struct phos_server*);
int			 phos_server_free(struct phos_server*);

struct phos_req		*phos_req_new(void);
int			 phos_req_handshake(struct phos_req*);
int			 phos_req_handshake_sync(struct phos_req*);
int			 phos_req_read_request(struct phos_req*);
int			 phos_req_read_request_sync(struct phos_req*);
int			 phos_req_reply(struct phos_req*, int, const char*);
int			 phos_req_reply_flush(struct phos_req*);
int			 phos_req_reply_sync(struct phos_req*, int, const char*);
ssize_t			 phos_req_write(struct phos_req*, const void*, size_t);
int			 phos_req_write_sync(struct phos_req*, const void*, size_t);
int			 phos_req_close(struct phos_req*);
int			 phos_req_close_sync(struct phos_req*);
int			 phos_req_del(struct phos_req*);
int			 phos_req_free(struct phos_req*);

int			 phos_server_fd(struct phos_server*);
const char		*phos_server_err(struct phos_server*);
int			 phos_req_fd(struct phos_req*);
const char		*phos_req_request_line(struct phos_req*);
int			 phos_req_sent_code(struct phos_req*);
const char		*phos_req_sent_meta(struct phos_req*);
const char		*phos_req_err(struct phos_req*);

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
