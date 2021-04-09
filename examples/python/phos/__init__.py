# phos bindings for python.
#
# You probably don't want to import this directly, use rather the
# phos.client and phos.server submodules.

import asyncio
import ctypes

ERROR = -1
WANT_READ = -2
WANT_WRITE = -3


async def wait_for_read(fd):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    loop.add_reader(fd, lambda: future.set_result(None))
    await future
    loop.remove_reader(fd)


async def wait_for_write(fd):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    loop.add_writer(fd, lambda: future.set_result(None))
    await future
    loop.remove_writer(fd)


lib = ctypes.CDLL('libphos.so')

# client:

lib.phos_client_new.argtypes = []
lib.phos_client_new.restype = ctypes.c_voidp

lib.phos_client_req.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                ctypes.c_char_p, ctypes.c_char_p]

lib.phos_client_handshake.argtypes = [ctypes.c_void_p]

lib.phos_client_response.argtypes = [ctypes.c_void_p]

lib.phos_client_read.argtypes = [ctypes.c_void_p,
                                 ctypes.c_void_p, ctypes.c_size_t]
lib.phos_client_read.restype = ctypes.c_ssize_t

lib.phos_client_abort.argtypes = [ctypes.c_void_p]

lib.phos_client_fd.argtypes = [ctypes.c_void_p]

lib.phos_client_rescode.argtypes = [ctypes.c_void_p]

lib.phos_client_resmeta.argtypes = [ctypes.c_void_p]
lib.phos_client_resmeta.restype = ctypes.c_char_p

lib.phos_client_close.argtypes = [ctypes.c_void_p]

lib.phos_client_free.argtypes = [ctypes.c_void_p]
lib.phos_client_free.restype = None


# server:

lib.phos_server_new.argtypes = []
lib.phos_server_new.restype = ctypes.c_void_p

lib.phos_server_load_keypair_file.argtypes = [ctypes.c_void_p,
                                              ctypes.c_char_p,
                                              ctypes.c_char_p]

lib.phos_server_accept.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

lib.phos_server_accept_sync.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

lib.phos_server_free.argtypes = [ctypes.c_void_p]
lib.phos_server_free.restype = None

lib.phos_req_new.argtypes = []
lib.phos_req_new.restype = ctypes.c_void_p

lib.phos_req_handshake.argtypes = [ctypes.c_void_p]

lib.phos_req_read_request.argtypes = [ctypes.c_void_p]

lib.phos_req_reply.argtypes = [ctypes.c_void_p,
                               ctypes.c_int,
                               ctypes.c_char_p]

lib.phos_req_reply_flush.argtypes = [ctypes.c_void_p]

lib.phos_req_write.argtypes = [ctypes.c_void_p,
                               ctypes.c_void_p, ctypes.c_size_t]
lib.phos_req_write.restype = ctypes.c_ssize_t

lib.phos_req_close.argtypes = [ctypes.c_void_p]

lib.phos_req_free.argtypes = [ctypes.c_void_p]
lib.phos_req_free.restype = None

lib.phos_server_fd.argtypes = [ctypes.c_void_p]

lib.phos_req_fd.argtypes = [ctypes.c_void_p]

lib.phos_req_request_line.argtypes = [ctypes.c_void_p]
lib.phos_req_request_line.restype = ctypes.c_char_p
