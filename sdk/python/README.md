# hide-protocol for Python

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

Python 3.10+ binding, through `ctypes`, to the same Rust core (`crates/hide-ffi`)
that the CLI and every other HIDE SDK use. This package contains no cryptography
of its own.

## Install

```sh
pip install hide-protocol
```

The wheel bundles the compiled core, so no toolchain is needed. PyPI carries
exactly three wheels per release, each tagged `py3-none-<platform>`, and no
source distribution:

| Wheel platform tag | Machine |
| --- | --- |
| `manylinux_2_28_x86_64` | Linux x86-64 with glibc |
| `win_amd64` | Windows x86-64 |
| `macosx_11_0_arm64` | macOS 11 or newer on Apple silicon |

The Linux wheel's core is compiled on Ubuntu 24.04 and then given the
`manylinux_2_28` tag; the tag is not checked against the binary. If it fails
to load on an older distribution, build the core there.

On anything else (Linux arm64, musl distributions such as Alpine, Intel
macOS, Windows on Arm) `pip install hide-protocol` finds nothing to install.
There, install the binding from a checkout (`pip install ./sdk/python`), build
the core yourself and point the binding at it (see
[Native library](#native-library)).

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

A `filename` must be one portable file name, and encryption refuses anything
else: at most 255 bytes, not `.` or `..`, no control characters, none of
`< > : " / \ | ? *`, no trailing dot or space, and not a Windows device name
such as `CON` or `COM1`.

Keys on disk: `secret.protect(passphrase)` returns a sealed key file
(`MIN_PASSPHRASE_LEN` is 8, and there is no escrow); `SecretKey.load(data,
passphrase)` opens one; `inspect_key(data)` reports `"raw"` or `"protected"`
without the passphrase. `armor_public_key` / `dearmor_public_key` give a public
key a pasteable text form.

Errors: every failure is a subclass of `hide.HideError` — `AuthenticationError`
(altered, or not a container), its subclass `Malformed` (did not decode at
all), `WrongPassphrase`, `NoMatchingRecipient`, `NotAKeyFile`,
`ChallengeExpired`, `ChallengeReplayed`. Arguments this binding rejects before
calling the core raise `ValueError`, or `TypeError` when the argument is the
wrong type (text that is not a `str`, a `decrypt` key that is not a
`SecretKey`).

Text arguments must not contain a NUL character. Passphrases, filenames,
media types, audiences, origins and armored keys cross into the core as C
strings, which end at the first NUL: `"longenough\0rest"` would otherwise seal
a key under `"longenough"`. Such text raises `ValueError` instead.

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
cannot be replayed as another; never let a remote party choose it. Contexts
beginning with `HIDE/` are reserved for the protocol: `sign` refuses them with
`ValueError`, while `verify` accepts any context. `verify`
returns `None` and raises `AuthenticationError` on failure rather than
returning a boolean a caller could forget to check. A key file written before
signatures existed carries no signing seed and raises `NotAKeyFile`.

## Threads

- `SpentNonces` may be shared between threads. `accept` takes a per-object
    lock around the native call, which changes the record; `ctypes` releases
    the GIL during that call, so without the lock two threads could both accept
    the same answer. Keep one record per verifier, not one per thread: a replay
    is only caught by the record that saw the first answer.
- `SecretKey` and `SigningIdentity` may be used from several threads at once;
    the native calls only read them. Do not `close()` one while another thread
    is still inside a call on it.
- Module-level functions hold no shared state.

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
| `verify_identity_pinned(log, recovery_binding, pinned_root)` | `int` — devices trusted now, only if the log is the identity under the pinned 32-byte root |
| `verify_epoch_chain_bound(log, recovery_binding, pinned_root, chain, epoch_binding)` | `int` — epochs, only if a device the log trusts signed this chain |
| `verify_checkpoint(note, origin, log_public)` | `(size, root)` — tree size and 32-byte root from a signed checkpoint note |

A cryptographic verify **raises** on failure (`Malformed` if the bytes did not
decode, `AuthenticationError` if they decoded but did not verify) and never
returns `False`. The one boolean is `identity_trusts_device`: the log is
verified first, so `False` means "not a member", never "did not verify".

The pinned checks are what a relying party uses: `pinned_root` is obtained out
of band, and `recovery_binding` establishes the recovery key, so a log extended
by a Recover under a stranger's key raises `AuthenticationError`. A pinned root
that is not 32 bytes raises `ValueError`.

## Native library

The core is loaded from one of two places, always by absolute path:

1. `HIDE_LIBRARY`, if it names a file **and** `HIDE_ALLOW_LIBRARY_OVERRIDE=1`
    is also set. Once opted in it is the only candidate: if it cannot be
    loaded, the import fails rather than falling back to another copy;
2. otherwise the library bundled inside the package (`hide_ffi.dll`,
    `libhide_ffi.dylib` or `libhide_ffi.so` beside `_binding.py`).

The system loader is never asked to search by name, so a library placed in
the working directory, on `PATH` or on `LD_LIBRARY_PATH` is not picked up. If
neither place has the library, `import hide_protocol` raises `ImportError`
naming the platform and what to install.

`HIDE_LIBRARY` is a development override: it replaces the entire cryptographic
core, so a single settable environment variable must not be enough to redirect
it. Against a local build:

```sh
cargo build --release -p hide-ffi
export HIDE_LIBRARY="$PWD/target/release/libhide_ffi.so"   # hide_ffi.dll / libhide_ffi.dylib
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
```

The core and the binding must be the same release. At import the binding
compares the core's `major.minor.patch` with its own and raises `ImportError`
on any difference: the core enforces checks this binding only documents, so
an older core beside a newer binding would silently lose them.
The binding reads its own version from the installed package's metadata, so
an application that freezes or vendors the package must carry that metadata
with it (PyInstaller: `--copy-metadata hide-protocol`).

## Key material

`SecretKey` and `SigningIdentity` are opaque handles. The seed bytes stay in the
native library and this SDK exposes no accessor for them; `repr()` shows only
whether the handle is open. Release a handle with `close()` or a `with` block
(it is also released on garbage collection, but that leaves key material in
memory for an unbounded time). A closed handle raises `ValueError` on use.

A handle cannot be copied: `copy.copy`, `copy.deepcopy` and pickling a
`SecretKey`, `SigningIdentity` or `SpentNonces` raise `TypeError`. A copy
would share the native object, and releasing either one would free it under
the other. To use a key in a second place, pass the same object, or load the
key file again.

## Limits

- Unaudited. Do not protect data you cannot afford to lose or expose.
- An identity is a key, not a person: a verified signature proves possession of
  a seed, nothing about who holds it.
- Full threat model: [docs/threat-model.md](https://github.com/hide-protocol/hide/blob/main/docs/threat-model.md).

## Links

- Repository: <https://github.com/hide-protocol/hide>
- Documentation: [docs/](https://github.com/hide-protocol/hide/tree/main/docs)
- Specification: [spec/hide-1.md](https://github.com/hide-protocol/hide/blob/main/spec/hide-1.md)
- [CHANGELOG](https://github.com/hide-protocol/hide/blob/main/CHANGELOG.md)
