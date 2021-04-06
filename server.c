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

#include "phos.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <fcntl.h>
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

int
phos_server_init(struct phos_server *serv, const char *hn, const char *port)
{
	int sock, v;
	struct addrinfo hints, *res;

	if (port == NULL)
		port = "1965";

	memset(&hints, 0, sizeof(hints));
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

	if (mark_nonblock(sock) == -1)
		goto err;

	serv->fd = sock;
        freeaddrinfo(res);
	return 1;

err:
        freeaddrinfo(res);
	close(sock);
	serv->fd = -1;
	return -1;
}

int
phos_server_run(struct phos_server *serv, void *data)
{
	return 0;
}
