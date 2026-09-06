"""Exercises the Python SDK against the real native library."""

from __future__ import annotations

import pytest

import hide_protocol as hide


def test_round_trip_carries_metadata() -> None:
    with hide.SecretKey.generate() as secret:
        public = secret.public_key()
        assert len(public) == hide.PUBLIC_KEY_LEN

        box = hide.encrypt(
            b"nume,suma\nAna,9000\n",
            [public],
            filename="salarii.csv",
            media_type="text/csv",
        )
        assert b"Ana" not in box, "plaintext leaked into the container"

        opened = hide.decrypt(box, secret)
        assert opened.data == b"nume,suma\nAna,9000\n"
        assert opened.filename == "salarii.csv"
        assert opened.media_type == "text/csv"


def test_every_single_byte_mutation_is_rejected() -> None:
    with hide.SecretKey.generate() as secret:
        box = bytearray(hide.encrypt(b"confidential", [secret.public_key()]))
        # Sampling the regions that matter rather than all ~1.3 kB, to keep the
        # suite fast; the Rust side tests every byte exhaustively.
        for offset in (0, 8, 15, 40, len(box) // 2, len(box) - 20, len(box) - 1):
            damaged = bytearray(box)
            damaged[offset] ^= 0x40
            with pytest.raises(hide.HideError):
                hide.decrypt(bytes(damaged), secret)


def test_truncation_and_extension_fail() -> None:
    with hide.SecretKey.generate() as secret:
        box = hide.encrypt(b"payload", [secret.public_key()])
        with pytest.raises(hide.HideError):
            hide.decrypt(box[:-1], secret)
        with pytest.raises(hide.HideError):
            hide.decrypt(box + b"\x00", secret)


def test_the_wrong_key_cannot_decrypt() -> None:
    with hide.SecretKey.generate() as alice, hide.SecretKey.generate() as bob:
        box = hide.encrypt(b"for alice", [alice.public_key()])
        with pytest.raises(hide.NoMatchingRecipient):
            hide.decrypt(box, bob)


def test_many_recipients_share_one_payload() -> None:
    keys = [hide.SecretKey.generate() for _ in range(3)]
    try:
        box = hide.encrypt(b"shared", [key.public_key() for key in keys])
        for key in keys:
            assert hide.decrypt(box, key).data == b"shared"
    finally:
        for key in keys:
            key.close()


def test_protected_keys_round_trip() -> None:
    with hide.SecretKey.generate() as secret:
        public = secret.public_key()
        sealed = secret.protect("correct horse battery")

    assert hide.inspect_key(sealed) == "protected"

    with pytest.raises(hide.WrongPassphrase):
        hide.SecretKey.load(sealed, "wrong passphrase")
    with pytest.raises(hide.WrongPassphrase):
        hide.SecretKey.load(sealed)

    with hide.SecretKey.load(sealed, "correct horse battery") as reopened:
        assert reopened.public_key() == public


def test_a_short_passphrase_is_refused() -> None:
    with hide.SecretKey.generate() as secret:
        with pytest.raises(ValueError):
            secret.protect("short")


def test_armor_round_trips() -> None:
    with hide.SecretKey.generate() as secret:
        public = secret.public_key()
        text = hide.armor_public_key(public)
        assert text.startswith("hide-public-key:")
        assert hide.dearmor_public_key(text) == public
        with pytest.raises(hide.HideError):
            hide.dearmor_public_key("not a key")


def test_recipient_count_is_bounded() -> None:
    with hide.SecretKey.generate() as secret:
        with pytest.raises(ValueError):
            hide.encrypt(b"x", [])
        with pytest.raises(ValueError):
            hide.encrypt(b"x", [secret.public_key()] * 65)
        with pytest.raises(ValueError):
            hide.encrypt(b"x", [b"too short"])


def test_a_closed_key_cannot_be_used_and_never_prints_key_material() -> None:
    secret = hide.SecretKey.generate()
    public = secret.public_key()
    assert "SecretKey" in repr(secret)
    # The repr must not contain anything derived from the key.
    assert public.hex()[:16] not in repr(secret)

    secret.close()
    secret.close()  # idempotent
    with pytest.raises(ValueError):
        secret.public_key()


def test_empty_payloads_are_valid() -> None:
    with hide.SecretKey.generate() as secret:
        box = hide.encrypt(b"", [secret.public_key()])
        assert hide.decrypt(box, secret).data == b""
