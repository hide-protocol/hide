# hide-protocol for Python

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

Python 3.10+ binding, through `ctypes`, to the same Rust core (`crates/hide-ffi`)
that the CLI and every other HIDE SDK use. This package contains no cryptography
of its own.

## Install

```sh
pip install hide-protocol
```

The wheel bundles the compiled core, so no toolchain is needed. Wheels are
published for three platforms: `manylinux_2_28_x86_64`, `win_amd64` and
`macosx_11_0_arm64`. On any other platform, build the core yourself and point
the binding at it (see [Native library](#native-library)).

## Quick start

```python
import hide_protocol as hide

with hide.SecretKey.generate() as secret:
    box = hide.encrypt(b"hello", [secret.public_key()], filename="note.txt")
    opened = hide.decrypt(box, secret)
    assert opened.data == b"hello" and opened.filename == "note.txt"

    tampered = bytearray(box)
    tampered[-1] ^= 0x01
    try:
        hide.decrypt(bytes(tampered), secret)
    except hide.AuthenticationError as e:
        print("refused:", e)   # refused: authentication failed; the data was altered
```

`encrypt` takes 1..64 recipient public keys, each exactly `PUBLIC_KEY_LEN`
(1216) bytes, plus optional `filename=` and `media_type=`. `decrypt` returns a
`Decrypted` with `.data`, `.filename` and `.media_type`; nothing is returned
unless the whole payload authenticates. The filename is attacker-controlled:
never use it to choose an output path.

Keys on disk: `secret.protect(passphrase)` returns a sealed key file
(`MIN_PASSPHRASE_LEN` is 8, and there is no escrow); `SecretKey.load(data,
passphrase)` opens one; `inspect_key(data)` reports `"raw"` or `"protected"`
without the passphrase. `armor_public_key` / `dearmor_public_key` give a public
key a pasteable text form.

Errors: every failure is a subclass of `hide.HideError` — `AuthenticationError`
(altered, or not a container), its subclass `Malformed` (did not decode at
all), `WrongPassphrase`, `NoMatchingRecipient`, `NotAKeyFile`,
`ChallengeExpired`, `ChallengeReplayed`. Arguments this binding rejects before
calling the core raise `ValueError`.

## Signing and verification

One seed backs both encryption and signing, so there is a single thing to back
up.

```python
sealed = hide.SigningIdentity.generate("correct horse battery")   # store this

with hide.SigningIdentity.load(sealed, "correct horse battery") as signer:
    context, message = b"myapp/v1 release", b"payload"
    signature = signer.sign(context, message)                     # 3373 bytes
    hide.verify(signer.public_key(), context, message, signature) # None, or raises

    # Challenge/response: good once, here, now.
    import time
    now = int(time.time())
    challenge = hide.new_challenge("app.example", now, 60)
    answer = signer.answer(challenge)
    with hide.SpentNonces() as spent:               # must outlive one request
        spent.accept(challenge, answer, signer.public_key(), now)
        spent.accept(challenge, answer, signer.public_key(), now)  # ChallengeReplayed
```

`context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it. `verify`
returns `None` and raises `AuthenticationError` on failure rather than
returning a boolean a caller could forget to check. A key file written before
signatures existed carries no signing seed and raises `NotAKeyFile`.

## Identity logs, epoch chains, transparency proofs

| Function | Returns |
| --- | --- |
| `verify_identity(log, recovery_key)` | `int` — how many devices the log trusts now |
| `identity_trusts_device(log, recovery_key, device_public_key)` | `bool` — membership, after verifying the log |
| `identity_head(log, recovery_key)` | 32 bytes naming this exact history |
| `verify_epoch_chain(chain)` | `int` — how many epochs it holds |
| `epoch_public_key(chain, epoch)` | the public key to encrypt to for `epoch` |
| `verify_inclusion(leaf, index, size, path, root)` | `None` |
| `verify_consistency(old_size, new_size, path, old_root, new_root)` | `None` |

A cryptographic verify **raises** on failure (`Malformed` if the bytes did not
decode, `AuthenticationError` if they decoded but did not verify) and never
returns `False`. The one boolean is `identity_trusts_device`: the log is
verified first, so `False` means "not a member", never "did not verify".

## Native library

The core is located in this order:

1. `HIDE_LIBRARY`, if it names a file **and** `HIDE_ALLOW_LIBRARY_OVERRIDE=1`
   is also set;
2. the library bundled inside the package (`hide_ffi.dll`,
   `libhide_ffi.dylib` or `libhide_ffi.so` beside `_binding.py`);
3. the system loader, by name.

`HIDE_LIBRARY` is a development override: it replaces the entire cryptographic
core, so a single settable environment variable must not be enough to redirect
it. Against a local build:

```sh
cargo build --release -p hide-ffi
export HIDE_LIBRARY="$PWD/target/release/libhide_ffi.so"   # hide_ffi.dll / libhide_ffi.dylib
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
```

## Key material

`SecretKey` and `SigningIdentity` are opaque handles. The seed bytes stay in the
native library and this SDK exposes no accessor for them; `repr()` shows only
whether the handle is open. Release a handle with `close()` or a `with` block
(it is also released on garbage collection, but that leaves key material in
memory for an unbounded time). A closed handle raises `ValueError` on use.

## Limits

- Unaudited. Do not protect data you cannot afford to lose or expose.
- An identity is a key, not a person: a verified signature proves possession of
  a seed, nothing about who holds it.
- Full threat model: [docs/threat-model.md](https://github.com/hide-protocol/hide/blob/main/docs/threat-model.md).

## Links

- Repository: <https://github.com/hide-protocol/hide>
- Documentation: [docs/](https://github.com/hide-protocol/hide/tree/main/docs)
- Specification: [spec/hide-0.1.md](https://github.com/hide-protocol/hide/blob/main/spec/hide-0.1.md)
- [CHANGELOG](https://github.com/hide-protocol/hide/blob/main/CHANGELOG.md)
