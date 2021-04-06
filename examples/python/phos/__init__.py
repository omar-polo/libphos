# phos bindings for python.
#
# You probably don't want to import this directly, use rather the
# phos.client and phos.server submodules.

import ctypes

ERROR = -1
WANT_READ = -2
WANT_WRITE = -3


lib = ctypes.CDLL('libphos.so')
lib.phos_client_new.restype = ctypes.c_voidp

# TODO: phos_client_set_io

lib.phos_client_req.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                ctypes.c_char_p, ctypes.c_char_p]

lib.phos_client_run.argtypes = [ctypes.c_void_p]

lib.phos_client_run_sync.argtypes = [ctypes.c_void_p]

lib.phos_client_fd.argtypes = [ctypes.c_void_p]

lib.phos_client_state.argtypes = [ctypes.c_void_p]

lib.phos_client_rescode.argtypes = [ctypes.c_void_p]

lib.phos_client_resmeta.argtypes = [ctypes.c_void_p]
lib.phos_client_resmeta.restype = ctypes.c_char_p

lib.phos_client_buf.argtypes = [ctypes.c_void_p]
lib.phos_client_buf.restype = ctypes.c_char_p

lib.phos_client_bufsize.argtypes = [ctypes.c_void_p]
lib.phos_client_bufsize.restype = ctypes.c_size_t

lib.phos_client_del.argtypes = [ctypes.c_void_p]

lib.phos_client_free.argtypes = [ctypes.c_voidp]
lib.phos_client_free.restype = None
