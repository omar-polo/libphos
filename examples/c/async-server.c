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

#include <err.h>
#include <event.h>
#include <phos.h>
#include <stdio.h>
#include <string.h>

static struct phos_req *tmpreq;

void
close_request(int fd, short ev, void *data)
{
	struct phos_req	*req = data;

	switch (phos_req_close(req)) {
	case PHOS_WANT_READ:
		event_once(fd, EV_READ, close_request, req, NULL);
		return;
	case PHOS_WANT_WRITE:
		event_once(fd, EV_WRITE, close_request, req, NULL);
		return;
	}

	phos_req_free(req);
}

void
read_request(int fd, short ev, void *data)
{
	struct phos_req	*req = data;
	const char	*str;

	switch (phos_req_read_request(req)) {
	case 0:
		close_request(fd, 0, req);
		return;
	case -1:
		phos_req_free(req);
		return;
	case PHOS_WANT_READ:
		event_once(fd, EV_READ, read_request, req, NULL);
		return;
	case PHOS_WANT_WRITE:
		event_once(fd, EV_WRITE, read_request, req, NULL);
		return;
	}

	printf("GET %s\n", req->line);

	phos_req_reply(req, 20, "text/gemini");
	phos_req_reply_flush(req);

	str = "# hello, world\n";
	phos_req_write(req, str, strlen(str));
	close_request(fd, 0, req);
}

void
do_handshake(int fd, short ev, void *data)
{
	struct phos_req *req = data;

	switch (phos_req_handshake(req)) {
	case -1:
		phos_req_free(req);
		return;
	case PHOS_WANT_READ:
		event_once(fd, EV_READ, do_handshake, req, NULL);
		break;
	case PHOS_WANT_WRITE:
		event_once(fd, EV_READ, do_handshake, req, NULL);
		break;
	}

	read_request(fd, 0, req);
}

void
do_accept(int fd, short ev, void *data)
{
	struct phos_server	*serv = data;
	int			 r;

	if (tmpreq == NULL) {
		if ((tmpreq = phos_req_new()) == NULL)
			err(1, "phos_req_new");
	}

	if ((r = phos_server_accept(serv, tmpreq)) == -1)
		errx(1, "phos_server_accept: %s",
		    phos_server_err(serv));

	if (r == 0) {
		event_once(tmpreq->fd, EV_READ, do_handshake, tmpreq, NULL);
		tmpreq = NULL;
	}
}

int
main(void)
{
	struct phos_server	 serv;
	struct event		 servev;

	if (phos_server_init(&serv, "localhost", "1996") == -1)
		errx(1, "phos_server_init: %s", serv.err);

	if (phos_server_load_keypair_file(&serv, "cert.pem", "key.pem") == -1)
		errx(1, "cannot load keypair: %s", serv.err);

	event_init();

	event_set(&servev, serv.fd, EV_READ | EV_PERSIST, do_accept, &serv);
	event_add(&servev, NULL);

	event_dispatch();
	return 0;
}
