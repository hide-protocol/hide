# hide-protocol (Ruby)

Ruby bindings to the HIDE core: hybrid post-quantum encryption for files and
messages (X25519 + ML-KEM-768).

## Read this before using it

**This is experimental and unaudited.** Do not use it to protect data you
cannot afford to lose or expose. The format may change.

**A successful decryption proves the data was not altered. It does *not* prove
who sent it.** Anyone holding your public key can produce a container that
decrypts for you. If you need to know the sender, you need a signature, and
HIDE does not provide one.

A decrypted filename is attacker-controlled. Never use it to choose an output
path.

## How it binds

There is no Ruby cryptography here, and no compiled extension. The gem calls
the same Rust core as the CLI through its C ABI, using stdlib `fiddle` — so
installing it needs no compiler and adds no runtime gem dependency.

The native library is found in this order:

1. `HIDE_LIBRARY`, if set — the full path to the shared library.
2. Beside the gem, in `lib/hide_protocol/`, where the release workflow puts it.
3. The system loader.

Platform names are `hide_ffi.dll` on Windows, `libhide_ffi.dylib` on macOS and
`libhide_ffi.so` elsewhere.

### Running against a local build

```sh
cargo build -p hide-ffi
```

Then point `HIDE_LIBRARY` at the result:

```sh
# Linux
export HIDE_LIBRARY="$PWD/target/debug/libhide_ffi.so"
# macOS
export HIDE_LIBRARY="$PWD/target/debug/libhide_ffi.dylib"
```

```powershell
# Windows
$env:HIDE_LIBRARY = "$PWD\target\debug\hide_ffi.dll"
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

## API

| | |
|---|---|
| `Hide.version` | version of the native core |
| `Hide.encrypt(plaintext, recipients:, filename: nil, media_type: nil)` | binary String |
| `Hide.decrypt(container, secret)` | `Decrypted` with `plaintext`, `filename`, `media_type` |
| `Hide.armor_public_key` / `Hide.dearmor_public_key` | text form of a public key |
| `Hide.inspect_key(bytes)` | `"raw"` or `"protected"` |
| `Hide::SecretKey.generate` / `.open(bytes, passphrase = nil)` | keys |
| `Hide::PUBLIC_KEY_LEN` (1216), `Hide::MIN_PASSPHRASE_LEN` (8) | constants |

Encryption takes between 1 and 64 recipients, each public key exactly
`Hide::PUBLIC_KEY_LEN` bytes.

All binary values in and out are ASCII-8BIT (binary) Strings. Metadata comes
back as UTF-8.

### Errors

Everything raises a subclass of `Hide::Error`:

`InvalidArgumentError`, `AuthenticationError` (altered data, or not a
container), `WrongPassphraseError`, `NoMatchingRecipientError` (this key was
not a recipient), `NotAKeyError`, `TooLargeError`, `ClosedKeyError`.

## Tests

```sh
HIDE_LIBRARY=/path/to/libhide_ffi.so ruby -Ilib -Itest test/test_hide.rb
```

## Licence

Apache-2.0.
