# libphos

**This library is deprecated!**

I started it as a way to simplify and collect some pieces from
[gmid][gmid] and [telescope][telescope] into a single place, but it
turned out both projects had their different needs and coming up with a
single library was difficult.  Phos continue to live as part of
[telescope][telescope].

[gmid]: https://github.com/omar-polo/gmid
[telescope]: https://github.com/omar-polo/telescope

----

Original readme:

phos is an ambitious project: a library to easily build asynchronous
Gemini servers and clients.

## Goals

- nice to use C API
- easy to call from other languages
- asynchronous API, but support blocking if requested
- clean, portable and free code

## Non-goals

- everything that's not the Gemini protocol
- extensions of any kind (should I even mention this?)

## Maybes

- bundle telescope incremental text/gemini parser too?

## Building

it's the usual spell

	./configure
	make
	sudo make install

eventually with a

	./autogen.sh

if you're building from a git checkout and not a tarball.

## Documentation, Bindings & usage

phos provides a set of manual page to describe the modules, please see

 - `phos_client.3` for the client description
 - `phos_req.3` on how to handle client connections from a server
 - `phos_server.3` for the server description
 - `phos_uri.3` for the URI parser

There are also an example usage in C and some example bindings for
other languages inside the [examples](./examples) directory.

## License

All the phos code is distributed under the ISC licence; some bits
inside the `compat` directory are under the BSD2 or BSD3 licence.
