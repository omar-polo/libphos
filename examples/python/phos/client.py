#!/usr/bin/env python3

import asyncio
import ctypes
import phos
from phos import lib


class Client:
    """Async Gemini client.

    A client can run only one request at a time, but after one is
    finished (i.e. after client.close() has been awaited), it's
    possible to re-use the same client for another one.

    """

    def __init__(self):
        self.client = lib.phos_client_new()
        if self.client is None:
            raise ValueError('failed to create a new client')

    def request(self, host, port, rawreq):
        """Place a request.

        Prepare the client to make a request on the given `host`, at
        the given `port` with `rawreq` as request.

        Only one request can be run at a time on a given Client,
        otherwise an exception will be raised and the existing request
        aborted.

        """
        if port is None:
            port = ''
        if type(port) is int:
            port = str(port)

        host = host.encode('utf-8')
        port = port.encode('utf-8')
        rawreq = rawreq.encode('utf-8')
        if lib.phos_client_req(self.client, host, port, rawreq) == -1:
            raise ValueError('failed to place the request')

    def __fd(self):
        return lib.phos_client_fd(self.client)

    def __code(self):
        return lib.phos_client_rescode(self.client)

    def __meta(self):
        return lib.phos_client_resmeta(self.client)

    async def __wait(self, raise_on_eof, fn):
        while True:
            r = fn()
            if r == phos.WANT_READ:
                await phos.wait_for_read(self.__fd())
            elif r == phos.WANT_WRITE:
                await phos.wait_for_write(self.__fd())
            elif r == -1:
                raise ValueError('error occurred')
            else:
                if r == 0 and raise_on_eof:
                    raise IOError('EOF')
                return r

    async def handshake(self):
        """Wait until the TLS handshake is done."""
        await self.__wait(True, lambda: lib.phos_client_handshake(self.client))

    async def header(self):
        await self.__wait(True, lambda: lib.phos_client_response(self.client))
        return (self.__code(), self.__meta())

    async def body(self):
        """Read the response, one chunk at a time"""
        while True:
            ba = bytearray(1024)
            ca = ctypes.c_char * len(ba)
            r = await self.__wait(
                False,
                lambda: lib.phos_client_read(self.client,
                                             ca.from_buffer(ba),
                                             len(ba)))
            if r == 0:
                await self.__close()
                return
            yield ba[:r]

    async def __close(self):
        await self.__wait(False, lambda: lib.phos_client_close(self.client))

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
    async for chunk in client.body():
        page += chunk
        if args.verbose > 1:
            print(f'received {len(chunk)} bytes...')

    print(page.decode('utf-8'))

if __name__ == '__main__':
    asyncio.run(main())
