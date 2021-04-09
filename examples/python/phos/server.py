#!/usr/bin/env python3

import asyncio
import ctypes
import phos
from phos import lib


class Request:
    def __init__(self):
        self.req = lib.phos_req_new()
        if self.req is None:
            raise ValueError('failed to create a new request')

    def _req(self):
        return self.req

    def __fd(self):
        return lib.phos_req_fd(self.req)

    def __line(self):
        return lib.phos_req_request_line(self.req).decode('utf-8')

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
        await self.__wait(True, lambda: lib.phos_req_handshake(self.req))

    async def read_request(self):
        await self.__wait(True, lambda: lib.phos_req_read_request(self.req))
        return self.__line()

    async def reply(self, code, meta):
        meta = meta.encode('utf-8')
        lib.phos_req_reply(self.req, code, meta)
        await self.__wait(True, lambda: lib.phos_req_reply_flush(self.req))

    async def write(self, buf):
        if type(buf) is str:
            buf = bytearray(buf.encode('utf-8'))

        while len(buf) > 0:
            arr = ctypes.c_char * len(buf)
            r = await self.__wait(True,
                                  lambda: lib.phos_req_write(
                                      self.req,
                                      arr.from_buffer(buf),
                                      len(buf)))
            buf = buf[r:]

    async def close(self):
        await self.__wait(False, lambda: lib.phos_req_close(self.req))

    def __del__(self):
        if self.req is not None:
            lib.phos_req_free(self.req)


class Server:
    """Async Gemini server."""

    def __init__(self, handler, host="localhost", port="1965"):
        print(f'listening on {host}:{port}')
        host = host.encode('utf-8')
        port = port.encode('utf-8')

        self.handler = handler
        self.server = lib.phos_server_new(host, port)
        if self.server is None:
            raise ValueError('failed to create the server')

    def load_certs_file(self, cert=None, key=None):
        if cert is None or key is None:
            raise ValueError('key or cert not given')
        cert = cert.encode('utf-8')
        key = key.encode('utf-8')
        if lib.phos_server_load_keypair_file(self.server, cert, key) == -1:
            raise Exception('failed to load the keypair')

    def __fd(self):
        return lib.phos_server_fd(self.server)

    def __new_req(self):
        s = lib.phos_req_new()
        if s is None:
            raise Exception('failed to allocate a req')
        return s

    async def run(self):
        req = Request()
        while True:
            r = lib.phos_server_accept(self.server, req._req())
            if r == -1:
                raise Exception('phos server failure')
            elif r == 0:
                asyncio.create_task(self.handler(req))
                req = Request()
            else:
                await phos.wait_for_read(self.__fd())

    def __del__(self):
        lib.phos_server_free(self.server)


async def default_handler(req):
    url = await req.read_request()
    print(f'GET {url}')
    await req.reply(20, 'text/gemini')
    await req.write('# hello, world\n')


async def main():
    server = Server(default_handler, host='localhost', port='1996')
    server.load_certs_file(
        cert='/home/op/.local/share/gmid/localhost.cert.pem',
        key='/home/op/.local/share/gmid/localhost.key.pem')
    await server.run()

if __name__ == '__main__':
    asyncio.run(main())
