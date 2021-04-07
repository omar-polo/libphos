#!/usr/bin/env python3

import asyncio
import phos
from phos import lib

START = 0
RESOLUTION = 1
CONNECT = 2
HANDSHAKE = 3
POST_HANDSHAKE = 4
WRITING_REQ = 5
READING_HEADER = 6
REPLY_READY = 7
BODY = 8
CLOSING = 9
EOF = 10
ERROR = 11


class Client:
    """Async Gemini client.

    A client can run only one request at a time, but after one is
    finished (i.e. after client.close() returns), it's possible to
    re-use the same client for another one.

    To start a request use the `request` method.  Then you can either
    run the state machine tick by tick with `run`, or (preferred)
    await for specific conditions using the `handshake`, `header`,
    `recv_chunk` and `close` methods.
    """

    def __init__(self):
        self.future = None
        self.client = lib.phos_client_new()
        if self.client is None:
            raise ValueError('failed to create a new client')

    def request(self, host, port, rawreq):
        """Place a request.

        Prepare the client to make a request on the given `host`, at
        the given `port`, with `rawreq` as request.

        Only one request can be run at a time on a given Client,
        otherwise an execption will be raised (but the ongoing request
        will be untouched.)
        """
        s = self.current_state()
        if s != START and s != EOF and s != ERROR:
            raise ValueError(f'cannot create request in this state ({s})')

        if port is None:
            port = ''

        host = host.encode('utf-8')
        port = port.encode('utf-8')
        rawreq = rawreq.encode('utf-8')
        if lib.phos_client_req(self.client, host, port, rawreq) == -1:
            raise ValueError('cannot create request (rawreq too long?)')
        return True

    def fd(self):
        """Get the file descriptor associated with the request, or -1"""
        return lib.phos_client_fd(self.client)

    def current_state(self):
        """Get the current state of the client."""
        return lib.phos_client_state(self.client)

    def code(self):
        """Get the code of the request.

        It gives a meaningful result only after the REPLY_READY
        state has been reached (i.e. `header` has been awaited)
        """
        return lib.phos_client_rescode(self.client)

    def meta(self):
        """Get the meta of the request.

        It gives a meaningful result only after the REPLY_READY
        state has been reached (i.e. `header` has been awaited)
        """
        return lib.phos_client_resmeta(self.client)

    def chunk(self):
        """Get the received chunk of the page."""
        buf = lib.phos_client_buf(self.client)
        len = lib.phos_client_bufsize(self.client)
        return (buf, len)

    async def run(self):
        """Run the state machine for a tick.

        Returns 0 on EOF, can raise exceptions.
        """
        if self.future is not None:
            await self.future

        res = lib.phos_client_run(self.client)

        if res == phos.WANT_READ:
            self.__schedule_read()
        elif res == phos.WANT_WRITE:
            self.__schedule_write()
        elif res == -1:
            raise IOError('error during request')

        return res

    def __schedule_read(self):
        loop = asyncio.get_running_loop()
        self.future = loop.create_future()
        loop.add_reader(self.fd(), lambda: self.___future_done(True))

    def __schedule_write(self):
        loop = asyncio.get_running_loop()
        self.future = loop.create_future()
        loop.add_writer(self.fd(), lambda: self.___future_done(False))

    def ___future_done(self, is_reader):
        loop = asyncio.get_running_loop()
        fd = lib.phos_client_fd(self.client)
        if is_reader:
            loop.remove_reader(fd)
        else:
            loop.remove_writer(fd)
        self.future.set_result(True)

    async def until_state(self, state):
        """Wait until `state` is reached, return immediately otherwise."""
        s = self.current_state()
        while s < state:
            if s == EOF or s == ERROR:
                return
            await self.run()
            s = self.current_state()

    async def handshake(self):
        """Wait until the TLS handshake is done."""
        await self.until_state(HANDSHAKE)

    async def header(self):
        """Wait until a response is read.  Return the code and the meta."""
        await self.until_state(REPLY_READY)
        return (self.code(), self.meta())

    async def recv_chunk(self):
        """Wait for a chunk, return True if one can be read, False otherwise.

        One should stop looping on `recv_chunk` upon False.
        """
        while True:
            s = self.current_state()
            if s < REPLY_READY:
                raise ValueError(f'cannot fetch chunk in current state ({s})')
            if s >= CLOSING:
                return False

            await self.run()
            if lib.phos_client_bufsize(self.client) != 0:
                return True

    def eof(self):
        """Whether we've reached EOF."""
        return self.current_state() >= CLOSING

    async def close(self):
        """Close the connection"""
        await self.until_state(EOF)

    def __del__(self):
        if self.client is not None:
            lib.phos_client_free(self.client)


async def main():
    import argparse
    from urllib.parse import urlparse

    parser = argparse.ArgumentParser(description='Fetch a Gemini resource.')
    parser.add_argument('url', type=str, nargs=1,
                        help='The URL to fetch')
    parser.add_argument('--verbose', '-v', action='count',
                        default=0, help='Be verbose')
    args = parser.parse_args()
    url = args.url[0]
    if "//" not in url:
        url = "gemini://" + url
    parsed = urlparse(url, scheme='gemini')

    client = Client()
    client.request(parsed.hostname, parsed.port, url + '\r\n')

    await client.handshake()
    if args.verbose > 2:
        print('handshake done')

    (code, meta) = await client.header()
    if args.verbose > 0:
        print(f'code={code} meta={meta}')

    page = bytearray()
    while await client.recv_chunk():
        (chunk, size) = client.chunk()
        if args.verbose > 1:
            print(f'received {size} bytes')
        page[len(page):len(page)] = chunk[:size]
    print(page.decode('utf-8'))

    await client.close()

if __name__ == '__main__':
    asyncio.run(main())
