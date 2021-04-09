# phos bindings for python.
#
# You probably don't want to import this directly, use rather the
# phos.client and phos.server submodules.

import ctypes

ERROR = -1
WANT_READ = -2
WANT_WRITE = -3


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
