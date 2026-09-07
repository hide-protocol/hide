"""ctypes binding to the HIDE C core.

ctypes rather than a compiled extension: the wheel then works on any CPython
without a build step, and there is no second place where the ABI is described.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes.util import find_library
from pathlib import Path

OK = 0
ERR_INVALID_ARGUMENT = 1
ERR_WRONG_PASSPHRASE = 2
ERR_NOT_A_KEY = 3
ERR_AUTHENTICATION = 4
ERR_NO_MATCHING_RECIPIENT = 5
ERR_MALFORMED = 6
ERR_TOO_LARGE = 7
ERR_CHALLENGE_EXPIRED = 8
ERR_CHALLENGE_REPLAYED = 9

KEY_RAW = 0
KEY_PROTECTED = 1

PUBLIC_KEY_LEN = 1216
MIN_PASSPHRASE_LEN = 8
SIGNATURE_LEN = 3373
VERIFYING_KEY_LEN = 1984
NONCE_LEN = 32


class Buffer(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t),
        ("capacity", ctypes.c_size_t),
    ]


def _library_names() -> list[str]:
    if sys.platform == "win32":
        return ["hide_ffi.dll"]
    if sys.platform == "darwin":
        return ["libhide_ffi.dylib"]
    return ["libhide_ffi.so"]


def _load() -> ctypes.CDLL:
    """Finds the shared library: bundled in the wheel first, then the system."""
    here = Path(__file__).parent
    candidates = [here / name for name in _library_names()]

    # Set by developers running against a cargo build tree.
    override = os.environ.get("HIDE_LIBRARY")
    if override:
        candidates.insert(0, Path(override))

    for candidate in candidates:
        if candidate.exists():
            return ctypes.CDLL(str(candidate))

    system = find_library("hide_ffi")
    if system:
        return ctypes.CDLL(system)

    raise ImportError(
        "the HIDE native library was not found. Install a wheel that bundles "
        "it, or set HIDE_LIBRARY to the path of "
        f"{_library_names()[0]} built by `cargo build -p hide-ffi`."
    )


lib = _load()

_SIGNATURES = {
    "hide_error_message": ([ctypes.c_int32], ctypes.c_char_p),
    "hide_version": ([], ctypes.c_char_p),
    "hide_buffer_empty": ([], Buffer),
    "hide_buffer_free": ([ctypes.POINTER(Buffer)], None),
    "hide_keypair_generate": (
        [ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(Buffer)],
        ctypes.c_int32,
    ),
    "hide_inspect_key": (
        [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int32)],
        ctypes.c_int32,
    ),
    "hide_secret_key_open": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_void_p),
        ],
        ctypes.c_int32,
    ),
    "hide_secret_key_protect": (
        [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(Buffer)],
        ctypes.c_int32,
    ),
    "hide_secret_key_public": (
        [ctypes.c_void_p, ctypes.POINTER(Buffer)],
        ctypes.c_int32,
    ),
    "hide_secret_key_free": ([ctypes.c_void_p], None),
    "hide_public_key_armor": (
        [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(Buffer)],
        ctypes.c_int32,
    ),
    "hide_public_key_dearmor": (
        [ctypes.c_char_p, ctypes.POINTER(Buffer)],
        ctypes.c_int32,
    ),
    "hide_encrypt": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(Buffer),
        ],
        ctypes.c_int32,
    ),
    "hide_decrypt": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.POINTER(Buffer),
            ctypes.POINTER(Buffer),
            ctypes.POINTER(Buffer),
        ],
        ctypes.c_int32,
    ),
    "hide_identity_generate": (
        [ctypes.c_char_p, ctypes.POINTER(Buffer)],
        ctypes.c_int32,
    ),
    "hide_signing_identity_open": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_void_p),
        ],
        ctypes.c_int32,
    ),
    "hide_signing_identity_public": (
        [ctypes.c_void_p, ctypes.POINTER(Buffer)],
        ctypes.c_int32,
    ),
    "hide_signing_identity_free": ([ctypes.c_void_p], None),
    "hide_sign_message": (
        [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(Buffer),
        ],
        ctypes.c_int32,
    ),
    "hide_verify_message": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ],
        ctypes.c_int32,
    ),
    "hide_challenge_new": (
        [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(Buffer)],
        ctypes.c_int32,
    ),
    "hide_challenge_answer": (
        [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(Buffer)],
        ctypes.c_int32,
    ),
    "hide_spent_nonces_new": ([], ctypes.c_void_p),
    "hide_spent_nonces_free": ([ctypes.c_void_p], None),
    "hide_challenge_accept": (
        [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint64,
        ],
        ctypes.c_int32,
    ),
}

for _name, (_argtypes, _restype) in _SIGNATURES.items():
    _function = getattr(lib, _name)
    _function.argtypes = _argtypes
    _function.restype = _restype
