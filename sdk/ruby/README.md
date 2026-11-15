# hide-protocol for Ruby

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

Ruby binding, through `fiddle`, to the same Rust core (`crates/hide-ffi`)
that the CLI and every other HIDE SDK use. This gem contains no cryptography of
its own and no compiled extension. Its one runtime dependency is `fiddle`
(1.0.6 or newer), which every supported Ruby already ships: as a default gem
up to Ruby 3.4, and as a bundled gem from Ruby 4.0, where Bundler only makes
it loadable because this gem declares it.

## Install

```sh
gem install hide-protocol
```

The compiled core ships as seven platform gems, so `gem install` fetches only
the binary for your machine: `x86_64-linux`, `aarch64-linux`,
`x86_64-linux-musl`, `x64-mingw-ucrt`, `aarch64-mingw-ucrt`, `arm64-darwin`,
`x86_64-darwin`. On any other platform, build the core yourself and point the
binding at it (see [Native library](#native-library)).

## Quick start

```ruby
require "hide_protocol"

Hide::SecretKey.generate do |secret|
  box = Hide.encrypt("hello", recipients: [secret.public_key], filename: "note.txt")
  opened = Hide.decrypt(box, secret)
  puts "#{opened.plaintext} #{opened.filename}"   # hello note.txt

  tampered = box.dup
  tampered.setbyte(-1, tampered.getbyte(-1) ^ 1)
  begin
    Hide.decrypt(tampered, secret)
  rescue Hide::AuthenticationError => e
    puts "refused: #{e.message}"                  # refused: authentication failed; the data was altered
  end
end
```

`Hide.encrypt(plaintext, recipients:, filename: nil, media_type: nil)` takes
the recipients as a **keyword** argument: 1..64 public keys, each exactly
`Hide::PUBLIC_KEY_LEN` (1216) bytes. `Hide.decrypt(container, secret)` is
positional and returns a `Hide::Decrypted` with `plaintext`, `filename` and
`media_type`; nothing is returned unless the whole payload authenticates. The
filename is attacker-controlled: never use it to choose an output path. Binary
values in and out are ASCII-8BIT Strings; metadata comes back as UTF-8.

A `filename` must be one portable file name, and encryption refuses anything
else: at most 255 bytes, not `.` or `..`, no control characters, none of
`< > : " / \ | ? *`, no trailing dot or space, and not a Windows device name
such as `CON` or `COM1`.

Keys on disk: `secret.protect(passphrase)` returns a sealed key file
(`Hide::MIN_PASSPHRASE_LEN` is 8, and there is no escrow);
`Hide::SecretKey.open(bytes, passphrase)` opens one; `Hide.inspect_key(bytes)`
reports `"raw"` or `"protected"` without the passphrase.
`Hide.armor_public_key` / `Hide.dearmor_public_key` give a public key a
pasteable text form.

Errors: everything raises a subclass of `Hide::Error` — `AuthenticationError`
(altered, or not a container), its subclass `MalformedError` (did not decode at
all), `WrongPassphraseError`, `NoMatchingRecipientError`, `NotAKeyError`,
`TooLargeError`, `ClosedKeyError`, `ChallengeExpiredError`,
`ChallengeReplayedError`, and `InvalidArgumentError` for arguments this binding
rejects before calling the core.

Text arguments must not contain a NUL character. Passphrases, filenames,
media types, audiences, origins and armored keys cross into the core as C
strings, which end at the first NUL: `"longenough\0rest"` would otherwise seal
a key under `"longenough"`. Such text raises `Hide::InvalidArgumentError`
instead. Text is sent as UTF-8: a String in another encoding is transcoded,
and an ASCII-8BIT String is taken as the UTF-8 bytes it already holds.

## Signing and verification

One seed backs both encryption and signing, so there is a single thing to back
up.

```ruby
sealed = Hide::SigningIdentity.generate("correct horse battery")   # store this

Hide::SigningIdentity.open(sealed, "correct horse battery") do |signer|
  context = "myapp/v1 release"
  message = "payload"
  signature = signer.sign(context, message)                        # 3373 bytes
  Hide.verify(signer.public_key, context, message, signature)      # nil, or raises

  # Challenge/response: good once, here, now.
  now = Time.now.to_i
  challenge = Hide.new_challenge("app.example", now, 60)
  answer = signer.answer(challenge)
  Hide::SpentNonces.open do |spent|                                # must outlive one request
    spent.accept(challenge, answer, signer.public_key, now)
    spent.accept(challenge, answer, signer.public_key, now)        # Hide::ChallengeReplayedError
  end
end
```

`context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it. Contexts
beginning with `HIDE/` are reserved for the protocol: `sign` refuses them with
`Hide::InvalidArgumentError`, while `Hide.verify` accepts any context.
`Hide.verify` returns `nil` and raises `Hide::AuthenticationError` on failure
rather than returning a boolean a caller could forget to check. A key file
written before signatures existed carries no signing seed and raises
`Hide::NotAKeyError`.

## Threads

- `Hide::SpentNonces` may be shared between threads. `accept` takes a
  per-object lock around the native call, which changes the record; `fiddle`
  releases the interpreter lock during that call, so without the lock two
  threads could both accept the same answer. Keep one record per verifier,
  not one per thread: a replay is only caught by the record that saw the
  first answer. A forking server has one record per worker process, and
  those do not see each other's answers.
- `Hide::SecretKey` and `Hide::SigningIdentity` may be used from several
  threads at once; the native calls only read them. Do not `close` one while
  another thread is still inside a call on it.
- Module-level methods hold no shared state.

## Identity logs, epoch chains, transparency proofs

| Method | Returns |
| --- | --- |
| `Hide.verify_identity(log, recovery_key)` | `Integer` — how many devices the log trusts now |
| `Hide.identity_trusts_device(log, recovery_key, device_public_key)` | `true`/`false` — membership, after verifying the log |
| `Hide.identity_head(log, recovery_key)` | 32 bytes naming this exact history |
| `Hide.verify_epoch_chain(chain)` | `Integer` — how many epochs it holds |
| `Hide.epoch_public_key(chain, epoch)` | the public key to encrypt to for `epoch` |
| `Hide.verify_inclusion(leaf, index, size, path, root)` | `nil` |
| `Hide.verify_consistency(old_size, new_size, path, old_root, new_root)` | `nil` |
| `Hide.verify_identity_pinned(log, recovery_binding, pinned_root)` | `Integer` — devices trusted, after checking the log against the 32-byte root you pinned |
| `Hide.verify_epoch_chain_bound(log, recovery_binding, pinned_root, chain, epoch_binding)` | `Integer` — epochs held, after proving the chain belongs to that identity |
| `Hide.verify_checkpoint(note, origin, log_public)` | `[size, root]` — tree size and 32-byte root of a signed checkpoint note |

A cryptographic verify **raises** on failure (`MalformedError` if the bytes did
not decode, `AuthenticationError` if they decoded but did not verify) and never
returns `false`. The one boolean is `identity_trusts_device`: the log is
verified first, so `false` means "not a member", never "did not verify".

`verify_identity_pinned` is the relying-party check (spec §16): a recovery key
taken from the same untrusted source as the log cannot catch a Recover appended
under a stranger's key, but a `recovery_binding` checked against a root you
trust out of band does.

## Native library

The core is loaded from one of two places, always by absolute path:

1. `HIDE_LIBRARY`, if it names a file **and** `HIDE_ALLOW_LIBRARY_OVERRIDE=1`
  is also set. Once opted in it is the only candidate: if it cannot be
  loaded, `require` fails rather than falling back to another copy;
2. otherwise beside the binding, in `lib/hide_protocol/`, where the platform
  gem puts it (`hide_ffi.dll`, `libhide_ffi.dylib` or `libhide_ffi.so`).

The system loader is never asked to search by name, so a library placed in
the working directory, on `PATH` or on `LD_LIBRARY_PATH` is not picked up. If
neither place has the library, `require "hide_protocol"` raises
`Hide::Binding::LibraryNotFound` naming the platform and what to install.

`HIDE_LIBRARY` is a development override: it replaces the entire cryptographic
core, so a single settable environment variable must not be enough to redirect
it. Against a local build:

```sh
cargo build --release -p hide-ffi
export HIDE_LIBRARY="$PWD/target/release/libhide_ffi.so"   # hide_ffi.dll / libhide_ffi.dylib
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
ruby -Ilib -Itest test/test_hide.rb
```

The core and the binding must be the same release. When it is required the
binding compares the core's `major.minor.patch` with its own, read from the
gemspec shipped in the gem, and raises `Hide::Binding::VersionMismatch` on
any difference: the core enforces checks this binding only documents, so an
older core beside a newer binding would silently lose them.

## Key material

`Hide::SecretKey`, `Hide::SigningIdentity` and `Hide::SpentNonces` are opaque
handles. The seed bytes never cross into Ruby and this gem exposes no accessor
for them; `inspect` and `to_s` show only whether the handle is open. Release
with `#close`, or use the block form of `.generate` / `.open`, which always
closes — including when the block raises. A closed handle raises
`Hide::ClosedKeyError` on use.

A handle cannot be copied: `dup`, `clone` and `Marshal.dump` raise
`TypeError`. A copy would share the native object, and closing either one
would free it under the other. To use a key in a second place, pass the same
object, or open the key file again. For the same reason
`Hide::SecretKey.new` and `Hide::SigningIdentity.new` are private: keys come
from `.generate`, `.open` and `.load` only.

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
