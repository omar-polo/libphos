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
#include <phos.h>
#include <stdio.h>
#include <unistd.h>

int
main(void)
{
	struct phos_client	*client;
	char			 buf[BUFSIZ];
	ssize_t			 r;

	if ((client = phos_client_new()) == NULL)
		errx(1, "failed to create a client");

	phos_client_req(client, "localhost", "1996",
	    "gemini://localhost.it/index.gmi\r\n");

	/* (optional) wait for the handshake */
	if (phos_client_handshake_sync(client) == -1)
		errx(1, "handshake failed");

	if (phos_client_response_sync(client) == -1)
		errx(1, "failed to read reply");

	warnx("code=%d meta=%s", client->code, client->meta);

	for (;;) {
		switch (r = phos_client_read_sync(client, buf, sizeof(buf))) {
		case 0:
			goto eof;
		case -1:
			errx(1, "failure reading server reply");
		default:
			write(1, buf, r);
		}
	}

eof:
	phos_client_close_sync(client);
	phos_client_free(client);

	return 0;
}
