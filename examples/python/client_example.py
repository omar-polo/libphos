#!/usr/bin/env python3

from phos.client import Client
import asyncio


async def main():
    client = Client()
    client.request('localhost', '1965', 'gemini://localhost/\r\n')

    await client.handshake()
    print('handshake done')

    (code, meta) = await client.header()
    print(f'code={code} meta={meta}')

    page = bytearray()
    while await client.recv_chunk():
        (chunk, size) = client.chunk()
        page[len(page):len(page)] = chunk[:size]
    print("body:")
    print(page.decode('utf-8'))

    await client.close()

if __name__ == '__main__':
    asyncio.run(main())
