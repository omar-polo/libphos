#!/usr/bin/env python3

import phos
# import phos.client as gemclient
from phos.client import Client
import asyncio


async def main():
    print("lib is", phos.lib)
    print("phos is", phos)
    client = Client()
    client.request('localhost.it', '1965', 'gemini://localhost.it/\r\n')

    await client.handshake()
    print('handshake done')

    (code, meta) = await client.header()
    print(f'code={code} meta={meta}')

    page = bytearray()
    while await client.recv_chunk():
        (chunk, size) = client.chunk()
        print(f'received {size} bytes')
        page[len(page):len(page)] = chunk[:size]
    print("body:")
    print(page.decode('utf-8'))

    await client.close()

if __name__ == '__main__':
    asyncio.run(main())
