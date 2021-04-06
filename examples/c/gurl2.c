/*
 * sta cosa non compila, ovviamente.  è più dimostrativo che altro 
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <netdb.h>
#include <phos.h>
#include <unistd.h>
#include <string.h>

int
main(void)
{
	struct phos_client *client;
	int r;

	if ((client = phos_client_new()) == NULL)
		err(1, "failed to create a new client");

	/* if (phos_client_init(&client) == -1) */
	/* 	errx(1, "failed to init phos client"); */

	/* setuppa la richiesta */
	phos_client_req(client, "localhost.it", NULL,
	    "gemini://localhost.it/index.gmi\r\n");

	/* main loop */
	for (;;) {
		r = phos_client_run_sync(client);

		switch (client->state) {
		case PCS_START:
			warnx("before start");
			break;
		case PCS_RESOLUTION:
                        warnx("during resolution");
			break;
		case PCS_CONNECT:
			warnx("during connect(2)");
			break;
		case PCS_HANDSHAKE:
                        /* warnx("during handshake"); */
			break;
		case PCS_POST_HANDSHAKE:
                        warnx("handshake done");
			break;
		case PCS_WRITING_REQ:
                        warnx("writing req");
			break;
		case PCS_READING_HEADER:
                        warnx("reading reply");
			break;
		case PCS_REPLY_READY:
			warnx("reply read: %d %s", client->code, client->meta);
			break;
		case PCS_BODY:
                        write(1, client->buf, client->off);
			break;
		case PCS_CLOSING:
			warnx("closing connection");
			break;
		case PCS_EOF:
			warnx("EOF");
			break;
		default:
			warnx("some error (%d, %s, %s)", client->io_err,
			    gai_strerror(client->gai_errno), strerror(client->c_errno));
			break;
		}

		switch (r) {
		/* case PHOS_WANT_READ: */
		/* case PHOS_WANT_WRITE: */
			/* call poll */
			/* break; */
		case -1:
			errx(1, "failure");
		case 0:
			/* EOF */
			goto end;
		}
	}

end:
	phos_client_free(client);
	return 0;
}
