CC =		cc
CFLAGS =	-I../.. -Wall -Wextra -Wno-unused-parameter -g -O0
LDFLAGS =	../../.libs/libphos.a -ltls -levent

.PHONY: all clean

all: async-server blocking-client blocking-server cert.pem

async-server: async-server.o
	${CC} async-server.o -o async-server ${LDFLAGS}

blocking-client: blocking-client.o
	${CC} blocking-client.o -o blocking-client ${LDFLAGS}

blocking-server: blocking-server.o
	${CC} blocking-server.o -o blocking-server ${LDFLAGS}

key.pem: cert.pem

cert.pem:
	openssl req -x509 -newkey rsa:4096 -subj '/CN=localhost' \
		-out cert.pem -keyout key.pem -nodes -days 365

clean:
	rm -f *.o cert.pem key.pem
	rm -f blocking-client blocking-server
