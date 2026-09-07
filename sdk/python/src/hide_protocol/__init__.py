"""HIDE — encrypt to a person, not to a key.

EXPERIMENTAL AND UNAUDITED. Do not protect data you cannot afford to lose or
expose. A successful decryption proves the data was not altered; it does *not*
prove who created it.

    import hide_protocol as hide

    secret = hide.SecretKey.generate()
    box = hide.encrypt(b"hello", [secret.public_key()])
    assert hide.decrypt(box, secret).data == b"hello"
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Sequence

from . import _binding as _b
from ._binding import MIN_PASSPHRASE_LEN, PUBLIC_KEY_LEN

__all__ = [
    "HideError",
    "AuthenticationError",
    "WrongPassphrase",
    "NoMatchingRecipient",
    "NotAKeyFile",
    "SecretKey",
    "SigningIdentity",
    "SpentNonces",
    "ChallengeExpired",
    "ChallengeReplayed",
    "sign",
    "verify",
    "new_challenge",
    "Decrypted",
    "encrypt",
    "decrypt",
    "armor_public_key",
    "dearmor_public_key",
    "inspect_key",
    "MIN_PASSPHRASE_LEN",
    "PUBLIC_KEY_LEN",
    "SIGNATURE_LEN",
    "VERIFYING_KEY_LEN",
    "__version__",
]

__version__ = _b.lib.hide_version().decode()


class HideError(Exception):
    """Base class for every failure this library reports."""


class AuthenticationError(HideError):
    """The data was altered, or is not a HIDE container."""


class WrongPassphrase(HideError):
    """The passphrase is wrong, or the key file was modified."""


class NoMatchingRecipient(HideError):
    """This key was not one of the recipients."""


class NotAKeyFile(HideError):
    """The bytes are not a HIDE key."""


class ChallengeExpired(HideError):
    """The challenge expired before it was answered."""


class ChallengeReplayed(HideError):
    """This challenge was already answered. Almost certainly a replay."""


_ERRORS = {
    _b.ERR_INVALID_ARGUMENT: ValueError,
    _b.ERR_WRONG_PASSPHRASE: WrongPassphrase,
    _b.ERR_NOT_A_KEY: NotAKeyFile,
    _b.ERR_AUTHENTICATION: AuthenticationError,
    _b.ERR_NO_MATCHING_RECIPIENT: NoMatchingRecipient,
    _b.ERR_MALFORMED: AuthenticationError,
    _b.ERR_TOO_LARGE: ValueError,
    _b.ERR_CHALLENGE_EXPIRED: ChallengeExpired,
    _b.ERR_CHALLENGE_REPLAYED: ChallengeReplayed,
}


def _check(code: int) -> None:
    if code == _b.OK:
        return
    message = _b.lib.hide_error_message(code).decode()
    raise _ERRORS.get(code, HideError)(message)


def _take(buffer: _b.Buffer) -> bytes:
    """Copies a native buffer into Python bytes and frees the original."""
    try:
        if not buffer.data:
            return b""
        return bytes(ctypes.cast(
            buffer.data, ctypes.POINTER(ctypes.c_uint8 * buffer.len)
        ).contents)
    finally:
        _b.lib.hide_buffer_free(ctypes.byref(buffer))


def _take_text(buffer: _b.Buffer) -> str | None:
    """Metadata arrives as length-prefixed UTF-8; empty means absent."""
    raw = _take(buffer)
    return raw.decode("utf-8", "replace") if raw else None


class SecretKey:
    """A secret key. The bytes stay in the native library and are never exposed.

    Release it with ``close()`` or a ``with`` block; it is also released when
    garbage collected.
    """

    __slots__ = ("_handle",)

    def __init__(self, handle: ctypes.c_void_p) -> None:
        self._handle = handle

    @classmethod
    def generate(cls) -> "SecretKey":
        handle = ctypes.c_void_p()
        public = _b.lib.hide_buffer_empty()
        _check(_b.lib.hide_keypair_generate(ctypes.byref(handle), ctypes.byref(public)))
        _b.lib.hide_buffer_free(ctypes.byref(public))
        return cls(handle)

    @classmethod
    def load(cls, data: bytes, passphrase: str | None = None) -> "SecretKey":
        """Loads a key file. A protected key without its passphrase fails."""
        handle = ctypes.c_void_p()
        _check(
            _b.lib.hide_secret_key_open(
                data,
                len(data),
                passphrase.encode() if passphrase is not None else None,
                ctypes.byref(handle),
            )
        )
        return cls(handle)

    def public_key(self) -> bytes:
        self._alive()
        out = _b.lib.hide_buffer_empty()
        _check(_b.lib.hide_secret_key_public(self._handle, ctypes.byref(out)))
        return _take(out)

    def protect(self, passphrase: str) -> bytes:
        """Seals this key with a passphrase, for writing to disk.

        A forgotten passphrase cannot be recovered: there is no escrow.
        """
        self._alive()
        if len(passphrase) < MIN_PASSPHRASE_LEN:
            raise ValueError(
                f"the passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            )
        out = _b.lib.hide_buffer_empty()
        _check(
            _b.lib.hide_secret_key_protect(
                self._handle, passphrase.encode(), ctypes.byref(out)
            )
        )
        return _take(out)

    def close(self) -> None:
        if getattr(self, "_handle", None):
            _b.lib.hide_secret_key_free(self._handle)
            self._handle = None

    def _alive(self) -> None:
        if not getattr(self, "_handle", None):
            raise ValueError("this key has been closed")

    def __enter__(self) -> "SecretKey":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def __repr__(self) -> str:
        # Never render key material, not even a fingerprint of it.
        state = "closed" if not getattr(self, "_handle", None) else "open"
        return f"<hide_protocol.SecretKey {state}>"


@dataclass(frozen=True)
class Decrypted:
    """A verified payload. Reaching this object means it authenticated."""

    data: bytes
    filename: str | None = None
    media_type: str | None = None


def encrypt(
    plaintext: bytes,
    recipients: Sequence[bytes],
    *,
    filename: str | None = None,
    media_type: str | None = None,
) -> bytes:
    """Encrypts for 1..64 recipient public keys."""
    if not 1 <= len(recipients) <= 64:
        raise ValueError("there must be between 1 and 64 recipients")
    joined = bytearray()
    for key in recipients:
        if len(key) != PUBLIC_KEY_LEN:
            raise ValueError(
                f"a public key is {PUBLIC_KEY_LEN} bytes, got {len(key)}"
            )
        joined += key

    out = _b.lib.hide_buffer_empty()
    _check(
        _b.lib.hide_encrypt(
            plaintext,
            len(plaintext),
            bytes(joined),
            len(recipients),
            filename.encode() if filename else None,
            media_type.encode() if media_type else None,
            ctypes.byref(out),
        )
    )
    return _take(out)


def decrypt(container: bytes, secret: SecretKey) -> Decrypted:
    """Decrypts and verifies.

    Nothing is returned unless the whole payload authenticates. The filename is
    attacker-controlled: never use it to choose an output path.
    """
    secret._alive()
    out = _b.lib.hide_buffer_empty()
    filename = _b.lib.hide_buffer_empty()
    media_type = _b.lib.hide_buffer_empty()
    _check(
        _b.lib.hide_decrypt(
            container,
            len(container),
            secret._handle,
            ctypes.byref(out),
            ctypes.byref(filename),
            ctypes.byref(media_type),
        )
    )
    return Decrypted(
        data=_take(out),
        filename=_take_text(filename),
        media_type=_take_text(media_type),
    )


def armor_public_key(public_key: bytes) -> str:
    """Renders a public key as pasteable text."""
    out = _b.lib.hide_buffer_empty()
    _check(
        _b.lib.hide_public_key_armor(public_key, len(public_key), ctypes.byref(out))
    )
    return _take_text(out) or ""


def dearmor_public_key(text: str) -> bytes:
    out = _b.lib.hide_buffer_empty()
    _check(_b.lib.hide_public_key_dearmor(text.encode(), ctypes.byref(out)))
    return _take(out)


def inspect_key(data: bytes) -> str:
    """Returns ``"raw"`` or ``"protected"`` without needing the passphrase."""
    kind = ctypes.c_int32(-1)
    _check(_b.lib.hide_inspect_key(data, len(data), ctypes.byref(kind)))
    return "protected" if kind.value == _b.KEY_PROTECTED else "raw"


SIGNATURE_LEN = _b.SIGNATURE_LEN
VERIFYING_KEY_LEN = _b.VERIFYING_KEY_LEN


class SigningIdentity:
    """A signing key. The seed stays in the native library and is never exposed.

    A key file written before signatures existed carries no signing seed and
    raises :class:`NotAKeyFile` rather than being silently downgraded.
    """

    __slots__ = ("_handle",)

    def __init__(self, handle: ctypes.c_void_p) -> None:
        self._handle = handle

    @staticmethod
    def generate(passphrase: str) -> bytes:
        """Creates an identity, returning the sealed key file to store.

        One seed backs both encryption and signing, so there is a single thing
        to back up. A forgotten passphrase cannot be recovered.
        """
        if len(passphrase) < MIN_PASSPHRASE_LEN:
            raise ValueError(
                f"the passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            )
        out = _b.lib.hide_buffer_empty()
        _check(_b.lib.hide_identity_generate(passphrase.encode(), ctypes.byref(out)))
        return _take(out)

    @classmethod
    def load(cls, data: bytes, passphrase: str | None = None) -> "SigningIdentity":
        handle = ctypes.c_void_p()
        _check(
            _b.lib.hide_signing_identity_open(
                data,
                len(data),
                passphrase.encode() if passphrase is not None else None,
                ctypes.byref(handle),
            )
        )
        return cls(handle)

    def public_key(self) -> bytes:
        """The shareable verifying key, for others to check signatures with."""
        self._alive()
        out = _b.lib.hide_buffer_empty()
        _check(_b.lib.hide_signing_identity_public(self._handle, ctypes.byref(out)))
        return _take(out)

    def sign(self, context: bytes, message: bytes) -> bytes:
        """Signs ``message`` under ``context``.

        ``context`` separates uses of one identity, so a signature made for one
        purpose cannot be replayed as another. Never let a remote party choose
        it.
        """
        self._alive()
        out = _b.lib.hide_buffer_empty()
        _check(
            _b.lib.hide_sign_message(
                self._handle, context, len(context), message, len(message),
                ctypes.byref(out),
            )
        )
        return _take(out)

    def answer(self, challenge: bytes) -> bytes:
        """Answers a challenge, proving possession to whoever issued it."""
        self._alive()
        out = _b.lib.hide_buffer_empty()
        _check(
            _b.lib.hide_challenge_answer(
                self._handle, challenge, len(challenge), ctypes.byref(out)
            )
        )
        return _take(out)

    def close(self) -> None:
        if getattr(self, "_handle", None):
            _b.lib.hide_signing_identity_free(self._handle)
            self._handle = None

    def _alive(self) -> None:
        if not getattr(self, "_handle", None):
            raise ValueError("this identity has been closed")

    def __enter__(self) -> "SigningIdentity":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if not getattr(self, "_handle", None) else "open"
        return f"<hide_protocol.SigningIdentity {state}>"


def sign(identity: SigningIdentity, context: bytes, message: bytes) -> bytes:
    return identity.sign(context, message)


def verify(
    public_key: bytes, context: bytes, message: bytes, signature: bytes
) -> None:
    """Raises :class:`AuthenticationError` unless both halves verify.

    Returns ``None`` on success rather than ``True``: a caller that forgets to
    check a boolean would treat every failure as a pass.
    """
    _check(
        _b.lib.hide_verify_message(
            public_key, len(public_key), context, len(context),
            message, len(message), signature, len(signature),
        )
    )


def new_challenge(audience: str, now: int, valid_for: int) -> bytes:
    """Creates a challenge for a prover to answer.

    A detached signature proves possession at some point, to nobody in
    particular, and can be replayed. A challenge binds a random nonce, an
    audience and an expiry, so an answer is good once, here, now.
    """
    out = _b.lib.hide_buffer_empty()
    _check(
        _b.lib.hide_challenge_new(
            audience.encode(), now, valid_for, ctypes.byref(out)
        )
    )
    return _take(out)


class SpentNonces:
    """The verifier's record of answered challenges.

    Replay can only be detected by the verifier: a replayed answer is a
    genuine signature and nothing about it is invalid on its own. This must
    therefore outlive a single request.
    """

    __slots__ = ("_handle",)

    def __init__(self) -> None:
        self._handle = ctypes.c_void_p(_b.lib.hide_spent_nonces_new())
        if not self._handle:
            raise HideError("could not allocate the nonce record")

    def accept(
        self, challenge: bytes, signature: bytes, public_key: bytes, now: int
    ) -> None:
        """Accepts an answer exactly once.

        Raises :class:`ChallengeReplayed` the second time, :class:`ChallengeExpired`
        after the window, and :class:`AuthenticationError` if it does not verify.
        """
        if not getattr(self, "_handle", None):
            raise ValueError("this record has been closed")
        _check(
            _b.lib.hide_challenge_accept(
                self._handle, challenge, len(challenge), signature, len(signature),
                public_key, len(public_key), now,
            )
        )

    def close(self) -> None:
        if getattr(self, "_handle", None):
            _b.lib.hide_spent_nonces_free(self._handle)
            self._handle = None

    def __enter__(self) -> "SpentNonces":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()
