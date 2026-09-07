"""Exercises the Python SDK against the real native library."""

from __future__ import annotations

import pytest

import hide_protocol as hide

import fixtures as fx


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


PASSPHRASE = "correct horse battery staple"
CONTEXT = b"HIDE/0.5 python test"


def identity() -> hide.SigningIdentity:
    return hide.SigningIdentity.load(
        hide.SigningIdentity.generate(PASSPHRASE), PASSPHRASE
    )


def test_signs_and_verifies() -> None:
    with identity() as signer:
        public = signer.public_key()
        assert len(public) == hide.VERIFYING_KEY_LEN
        signature = signer.sign(CONTEXT, b"the message")
        assert len(signature) == hide.SIGNATURE_LEN
        hide.verify(public, CONTEXT, b"the message", signature)


def test_a_changed_message_does_not_verify() -> None:
    with identity() as signer:
        public = signer.public_key()
        signature = signer.sign(CONTEXT, b"the message")
        with pytest.raises(hide.AuthenticationError):
            hide.verify(public, CONTEXT, b"the messagE", signature)


def test_a_different_context_does_not_verify() -> None:
    with identity() as signer:
        public = signer.public_key()
        signature = signer.sign(CONTEXT, b"the message")
        with pytest.raises(hide.AuthenticationError):
            hide.verify(public, b"another context", b"the message", signature)


def test_another_identity_cannot_be_impersonated() -> None:
    with identity() as signer, identity() as impostor:
        signature = impostor.sign(CONTEXT, b"the message")
        with pytest.raises(hide.AuthenticationError):
            hide.verify(signer.public_key(), CONTEXT, b"the message", signature)


def test_an_encryption_only_key_cannot_sign() -> None:
    with hide.SecretKey.generate() as secret:
        sealed = secret.protect(PASSPHRASE)
    with pytest.raises(hide.NotAKeyFile):
        hide.SigningIdentity.load(sealed, PASSPHRASE)


def test_a_challenge_is_answered_once_and_then_refused() -> None:
    with identity() as prover:
        public = prover.public_key()
        challenge = hide.new_challenge("ssh://host.example", 1_000, 60)
        answer = prover.answer(challenge)

        with hide.SpentNonces() as spent:
            spent.accept(challenge, answer, public, 1_000)
            # The identical valid answer, presented again.
            with pytest.raises(hide.ChallengeReplayed):
                spent.accept(challenge, answer, public, 1_000)


def test_an_answer_after_the_window_is_refused() -> None:
    with identity() as prover:
        public = prover.public_key()
        challenge = hide.new_challenge("ssh://host.example", 1_000, 60)
        answer = prover.answer(challenge)
        with hide.SpentNonces() as spent:
            with pytest.raises(hide.ChallengeExpired):
                spent.accept(challenge, answer, public, 1_100)


def test_a_closed_identity_cannot_sign_and_never_prints_key_material() -> None:
    signer = identity()
    signer.close()
    assert "closed" in repr(signer)
    with pytest.raises(ValueError):
        signer.sign(CONTEXT, b"anything")


def test_an_identity_log_reports_the_devices_it_trusts() -> None:
    # Four events: create, enrol phone, enrol laptop, revoke laptop.
    assert hide.verify_identity(fx.IDENTITY_LOG, fx.IDENTITY_RECOVERY) == 2


def test_a_revoked_device_is_no_longer_trusted() -> None:
    assert hide.identity_trusts_device(
        fx.IDENTITY_LOG, fx.IDENTITY_RECOVERY, fx.IDENTITY_DEVICE_PHONE
    )
    assert not hide.identity_trusts_device(
        fx.IDENTITY_LOG, fx.IDENTITY_RECOVERY, fx.IDENTITY_DEVICE_LAPTOP
    )


def test_a_tampered_log_is_refused() -> None:
    with pytest.raises(hide.AuthenticationError):
        hide.verify_identity(fx.IDENTITY_TAMPERED, fx.IDENTITY_RECOVERY)
    # Bytes that do not decode at all are a different failure from bytes that
    # decode and do not verify.
    with pytest.raises(hide.Malformed):
        hide.verify_identity(b"not a log", fx.IDENTITY_RECOVERY)


def test_the_head_names_this_exact_history() -> None:
    head = hide.identity_head(fx.IDENTITY_LOG, fx.IDENTITY_RECOVERY)
    assert head == fx.IDENTITY_HEAD
    assert len(head) == 32


def test_an_epoch_chain_verifies_and_yields_keys() -> None:
    assert hide.verify_epoch_chain(fx.EPOCH_CHAIN) == 3
    assert hide.epoch_public_key(fx.EPOCH_CHAIN, 1) == fx.EPOCH_PUBLIC_KEY_1


def test_an_epoch_beyond_the_chain_is_refused() -> None:
    with pytest.raises(ValueError):
        hide.epoch_public_key(fx.EPOCH_CHAIN, 3)


def test_a_spliced_epoch_chain_does_not_verify() -> None:
    with pytest.raises(hide.AuthenticationError):
        hide.verify_epoch_chain(fx.EPOCH_BROKEN)


def test_an_inclusion_proof_verifies_only_for_its_own_leaf() -> None:
    hide.verify_inclusion(fx.LEAF, 3, 8, fx.INCLUSION_PATH, fx.TREE_ROOT)
    with pytest.raises(hide.AuthenticationError):
        hide.verify_inclusion(fx.OTHER_LEAF, 3, 8, fx.INCLUSION_PATH, fx.TREE_ROOT)


def test_a_path_that_is_not_whole_hashes_is_refused() -> None:
    with pytest.raises(ValueError):
        hide.verify_inclusion(fx.LEAF, 3, 8, fx.INCLUSION_PATH[:-1], fx.TREE_ROOT)


def test_a_consistency_proof_catches_a_rewritten_history() -> None:
    hide.verify_consistency(5, 8, fx.CONSISTENCY_PATH, fx.ROOT_AT_5, fx.TREE_ROOT)
    # Same size, one entry silently replaced.
    with pytest.raises(hide.AuthenticationError):
        hide.verify_consistency(
            5, 8, fx.CONSISTENCY_PATH, fx.ROOT_AT_5, fx.REWRITTEN_ROOT
        )
