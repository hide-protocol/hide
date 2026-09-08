# hide-protocol (Ruby)

Ruby bindings to the HIDE core: hybrid post-quantum encryption for files and
messages (X25519 + ML-KEM-768).

## Read this before using it

**This is experimental and unaudited.** Do not use it to protect data you
cannot afford to lose or expose. The format may change.

**A successful decryption proves the data was not altered. It does *not* prove
who sent it.** Anyone holding your public key can produce a container that
decrypts for you. If you need to know the sender, sign the message with
`Hide::SigningIdentity` and verify it separately.

A decrypted filename is attacker-controlled. Never use it to choose an output
path.

## How it binds

There is no Ruby cryptography here, and no compiled extension. The gem calls
the same Rust core as the CLI through its C ABI, using stdlib `fiddle` — so
installing it needs no compiler and adds no runtime gem dependency.

The native library is found in this order:

1. `HIDE_LIBRARY`, if set AND `HIDE_ALLOW_LIBRARY_OVERRIDE=1` — the full path to
  the shared library. Development only: it replaces the cryptographic core.
2. Beside the gem, in `lib/hide_protocol/`, where the release workflow puts it.
3. The system loader.

Platform names are `hide_ffi.dll` on Windows, `libhide_ffi.dylib` on macOS and
`libhide_ffi.so` elsewhere.

### Running against a local build

```sh
cargo build -p hide-ffi
```

Then point `HIDE_LIBRARY` at the result and enable the override:

```sh
# Linux
export HIDE_LIBRARY="$PWD/target/debug/libhide_ffi.so"
# macOS
export HIDE_LIBRARY="$PWD/target/debug/libhide_ffi.dylib"
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
```

```powershell
# Windows
$env:HIDE_LIBRARY = "$PWD\target\debug\hide_ffi.dll"
$env:HIDE_ALLOW_LIBRARY_OVERRIDE = "1"
```

## Use

```ruby
require "hide_protocol"

Hide::SecretKey.generate do |secret|
  box = Hide.encrypt(
    File.binread("salarii.csv"),
    recipients: [secret.public_key],
    filename: "salarii.csv",
    media_type: "text/csv"
  )

  opened = Hide.decrypt(box, secret)
  opened.plaintext  # => the original bytes
  opened.filename   # => "salarii.csv"
  opened.media_type # => "text/csv"
end
```

The block form always closes the key, including when the block raises. Without
a block, call `#close` yourself.

### Keys

```ruby
secret = Hide::SecretKey.generate
public_key = secret.public_key            # 1216 bytes, binary

sealed = secret.protect("a long passphrase")  # for writing to disk
Hide.inspect_key(sealed)                      # => "protected"

reopened = Hide::SecretKey.open(sealed, "a long passphrase")
```

A passphrase must be at least `Hide::MIN_PASSPHRASE_LEN` (8) characters. A
forgotten passphrase cannot be recovered: there is no escrow.

Secret key material never crosses into Ruby. `inspect` and `to_s` report only
whether the key is open or closed, and a closed key raises on any use.

### Sharing a public key

```ruby
text = Hide.armor_public_key(public_key)  # "hide-public-key:..."
Hide.dearmor_public_key(text)             # back to bytes
```

### Signing

Encryption and signing share one seed, so there is a single thing to back up.

```ruby
sealed = Hide::SigningIdentity.generate("a long passphrase")  # write this to disk

Hide::SigningIdentity.open(sealed, "a long passphrase") do |signer|
  public_key = signer.public_key                  # 1984 bytes, shareable
  signature = signer.sign("myapp/v1 release", bytes)  # 3373 bytes
  Hide.verify(public_key, "myapp/v1 release", bytes, signature)
end
```

`verify` returns `nil` and raises on failure, rather than returning a boolean a
caller could forget to test. The context string separates uses of one identity:
never let a remote party choose it.

### Proving possession live

A detached signature proves possession at some point, to nobody in particular,
and can be replayed. A challenge binds a nonce, an audience and an expiry.

```ruby
challenge = Hide.new_challenge("ssh://host.example", Time.now.to_i, 60)
answer = signer.answer(challenge)

spent = Hide::SpentNonces.new   # must outlive the request
spent.accept(challenge, answer, public_key, Time.now.to_i)
```

The second acceptance of the same answer raises `ChallengeReplayedError`, and
one presented after the window raises `ChallengeExpiredError`.

## API

| | |
|---|---|
| `Hide.version` | version of the native core |
| `Hide.encrypt(plaintext, recipients:, filename: nil, media_type: nil)` | binary String |
| `Hide.decrypt(container, secret)` | `Decrypted` with `plaintext`, `filename`, `media_type` |
| `Hide.armor_public_key` / `Hide.dearmor_public_key` | text form of a public key |
| `Hide.inspect_key(bytes)` | `"raw"` or `"protected"` |
| `Hide::SecretKey.generate` / `.open(bytes, passphrase = nil)` | keys |
| `Hide::SigningIdentity.generate(passphrase)` | sealed key file bytes |
| `Hide::SigningIdentity.open(bytes, passphrase = nil)` | `#public_key`, `#sign`, `#answer`, `#close` |
| `Hide.verify(public_key, context, message, signature)` | raises unless it verifies |
| `Hide.new_challenge(audience, now, valid_for)` | challenge bytes |
| `Hide::SpentNonces#accept(challenge, signature, public_key, now)` | accepts once |
| `Hide::PUBLIC_KEY_LEN` (1216), `Hide::MIN_PASSPHRASE_LEN` (8) | constants |
| `Hide::SIGNATURE_LEN` (3373), `Hide::VERIFYING_KEY_LEN` (1984), `Hide::NONCE_LEN` (32) | constants |

Encryption takes between 1 and 64 recipients, each public key exactly
`Hide::PUBLIC_KEY_LEN` bytes.

All binary values in and out are ASCII-8BIT (binary) Strings. Metadata comes
back as UTF-8.

### Errors

Everything raises a subclass of `Hide::Error`:

`InvalidArgumentError`, `AuthenticationError` (altered data, or not a
container), `WrongPassphraseError`, `NoMatchingRecipientError` (this key was
not a recipient), `NotAKeyError`, `TooLargeError`, `ClosedKeyError`,
`ChallengeExpiredError`, `ChallengeReplayedError`.

## Tests

```sh
HIDE_LIBRARY=/path/to/libhide_ffi.so HIDE_ALLOW_LIBRARY_OVERRIDE=1 ruby -Ilib -Itest test/test_hide.rb
```

## Licence

Apache-2.0.
