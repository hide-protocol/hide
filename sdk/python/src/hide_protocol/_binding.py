"""ctypes binding to the HIDE C core.

ctypes rather than a compiled extension: the wheel then works on any CPython
without a build step, and there is no second place where the ABI is described.
"""

from __future__ import annotations

import ctypes
import importlib.metadata
import os
import platform
import re
import sys
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
ERR_CHALLENGE_AUDIENCE = 11

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


def _locate() -> Path:
    """Finds the shared library: the override if opted in, else the wheel's copy.

    HIDE_LIBRARY replaces the cryptographic core, so it is a development
    override and is ignored unless HIDE_ALLOW_LIBRARY_OVERRIDE=1 is also set.
    Otherwise anyone who can set one environment variable for this process
    substitutes a library that sees every passphrase and plaintext.

    Only absolute paths are ever handed to the loader. A bare file name would
    let it search the current directory, PATH or LD_LIBRARY_PATH, which is
    the same substitution with no opt-in at all. An opted-in override is the
    answer rather than one candidate among several: if it cannot be loaded
    that is an error, not a reason to quietly use another copy.
    """
    override = os.environ.get("HIDE_LIBRARY")
    if override and os.environ.get("HIDE_ALLOW_LIBRARY_OVERRIDE") == "1":
        return Path(override).resolve()

    here = Path(__file__).resolve().parent
    for name in _library_names():
        candidate = here / name
        if candidate.exists():
            return candidate

    raise ImportError(
        f"the HIDE native library ({_library_names()[0]}) was not found for "
        f"{sys.platform} {platform.machine()}. Install a wheel that bundles "
        "it (published for manylinux_2_28_x86_64, win_amd64 and "
        "macosx_11_0_arm64). Developers: set HIDE_LIBRARY to the path of "
        f"{_library_names()[0]} built by `cargo build -p hide-ffi` AND "
        "HIDE_ALLOW_LIBRARY_OVERRIDE=1."
    )


def _binding_version() -> str:
    """The version of this binding, from the manifest it was built from.

    Read rather than repeated here, so there is no second copy of the version
    for a release to forget. In a source checkout the manifest beside ``src``
    answers, because an older installed copy of the distribution must not
    speak for this code; an installed wheel has only its metadata.
    """
    manifest = Path(__file__).resolve().parents[2] / "pyproject.toml"
    try:
        text = manifest.read_text(encoding="utf-8")
    except OSError:
        text = ""
    if re.search(r'(?m)^name = "hide-protocol"$', text):
        declared = re.search(r'(?m)^version = "([^"]+)"', text)
        if declared:
            return declared.group(1)
    try:
        return importlib.metadata.version("hide-protocol")
    except importlib.metadata.PackageNotFoundError:
        raise ImportError(
            "cannot tell which version of hide-protocol this is, so the "
            "native library cannot be checked against it. Install the "
            "package rather than copying its files."
        ) from None


# The core enforces checks this binding only documents (reserved contexts,
# metadata rules, limits), so a stale core beside a newer binding would
# silently lose them: the two must agree exactly, and loading refuses otherwise.
BINDING_VERSION = _binding_version()


def _load(path: Path) -> ctypes.CDLL:
    try:
        return ctypes.CDLL(str(path))
    except OSError as error:
        raise ImportError(
            f"the HIDE native library at {path} could not be loaded: {error}"
        ) from error


def _version_triple(text: str, what: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", text)
    if match is None:
        raise ImportError(f"the {what} version {text!r} is not major.minor.patch")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def check_version(core: str, binding: str = BINDING_VERSION) -> None:
    """Refuses a core whose major.minor.patch differs from this binding's.

    Exact, not merely compatible: a binding documents checks that only the
    core performs, so any difference means the documentation is wrong for
    the code that runs. Pre-release and build suffixes are not compared.
    """
    if _version_triple(core, "core") != _version_triple(binding, "binding"):
        raise ImportError(
            f"the HIDE native library is version {core} but this binding is "
            f"{binding}; install matching versions of both"
        )


LIBRARY_PATH = _locate()
lib = _load(LIBRARY_PATH)

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
    "hide_spent_nonces_new": ([ctypes.c_char_p], ctypes.c_void_p),
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
    "hide_identity_verify": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ],
        ctypes.c_int32,
    ),
    "hide_identity_trusts_device": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_int32),
        ],
        ctypes.c_int32,
    ),
    "hide_identity_head": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(Buffer),
        ],
        ctypes.c_int32,
    ),
    "hide_epoch_verify": (
        [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)],
        ctypes.c_int32,
    ),
    "hide_epoch_public_key": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.POINTER(Buffer),
        ],
        ctypes.c_int32,
    ),
    "hide_transparency_verify_inclusion": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ],
        ctypes.c_int32,
    ),
    "hide_transparency_verify_consistency": (
        [
            ctypes.c_uint64,
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ],
        ctypes.c_int32,
    ),
    "hide_identity_verify_pinned": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ],
        ctypes.c_int32,
    ),
    "hide_epoch_verify_bound": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ],
        ctypes.c_int32,
    ),
    "hide_checkpoint_verify": (
        [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(Buffer),
        ],
        ctypes.c_int32,
    ),
}

for _name, (_argtypes, _restype) in _SIGNATURES.items():
    _function = getattr(lib, _name)
    _function.argtypes = _argtypes
    _function.restype = _restype

check_version(lib.hide_version().decode())
