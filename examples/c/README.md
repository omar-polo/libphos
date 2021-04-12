# libphos c examples

`async-server` is an example of an asynchronous server written using
`libevent(3)`; it can handle multiple connection concurrently.

`blocking-server` is a blocking server, and `blocking-client` is a
blocking client.  One will bind localhost:1966 (note: *not* 1965,
1966!), the other will connect to localhost:1966.

To build, just run `make`.  A self-signed cert for localhost will be
automagically created with the help of `openssl(1)`.

NB: these servers and clients will be listen on the port 1996 and
**not** 1965!
