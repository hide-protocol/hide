# HIDE for PHP

**Experimental and unaudited.** Do not use this to protect data you cannot
afford to lose or expose. A successful decryption proves the data was **not
altered**; it does **not** prove **who** created it. There is no sender
authentication in this protocol.

This package does not implement any cryptography. It binds, through PHP's
built-in FFI extension, to the same Rust core (`crates/hide-ffi`) that the CLI
and every other language SDK use.

## Requirements

- PHP 8.1 or newer with `ext-ffi` enabled.
- The HIDE native library for your platform: `libhide_ffi.so` on Linux,
  `libhide_ffi.dylib` on macOS, `hide_ffi.dll` on Windows.

Many distributions ship `ffi.enable=preload`, which leaves FFI unavailable to
ordinary scripts. Either set `ffi.enable=true` in `php.ini`, or pass
`-d ffi.enable=1` on the command line.

## Pointing at a local build

```sh
cargo build -p hide-ffi --release
export HIDE_LIBRARY="$PWD/target/release/libhide_ffi.so"
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
```

The library is located in the same order as the Python binding: `HIDE_LIBRARY`
if it is set and `HIDE_ALLOW_LIBRARY_OVERRIDE=1` (development only: it replaces
the cryptographic core), then a copy sitting beside the package (`src/` or
`lib/`), then whatever the system loader can find by name.

## Usage

```php
<?php

require 'vendor/autoload.php';

use HideProtocol\Hide;
use HideProtocol\SecretKey;

$secret = SecretKey::generate();

$box = Hide::encrypt(
    'hello',
    [$secret->publicKey()],
    filename: 'note.txt',
    mediaType: 'text/plain',
);

$opened = Hide::decrypt($box, $secret);
echo $opened->plaintext;   // hello
echo $opened->filename;    // note.txt
echo $opened->mediaType;   // text/plain

$secret->close();
```

Storing a key on disk, sealed with a passphrase:

```php
$sealed = $secret->protect('correct horse battery');   // >= 8 characters
file_put_contents('me.hide-secret', $sealed);

Hide::inspectKey($sealed);                             // "protected"
$reopened = SecretKey::open($sealed, 'correct horse battery');
```

Sharing a public key as text:

```php
$text = Hide::armorPublicKey($secret->publicKey());    // hide-public-key:...
$key  = Hide::dearmorPublicKey($text);
```

## API

| Symbol | Meaning |
| --- | --- |
| `Hide::version()` | The native core's version. |
| `Hide::encrypt($plaintext, $recipients, $filename, $mediaType)` | Encrypts for 1..64 public keys, each exactly 1216 bytes. |
| `Hide::decrypt($container, $secret)` | Returns a `Decrypted` with `plaintext`, `filename`, `mediaType`. |
| `Hide::armorPublicKey()` / `Hide::dearmorPublicKey()` | Text form of a public key. |
| `Hide::inspectKey($bytes)` | `"raw"` or `"protected"`, without the passphrase. |
| `SecretKey::generate()` / `SecretKey::open($bytes, $passphrase)` | Obtains a key. |
| `$key->publicKey()` / `->protect($passphrase)` / `->close()` | Uses one. |
| `Hide::PUBLIC_KEY_LEN` = 1216, `Hide::MIN_PASSPHRASE_LEN` = 8 | Limits. |

Every failure is a `HideProtocol\HideException`, or an
`InvalidArgumentException` for arguments this binding rejects before calling
the library. The specific subclasses are `AuthenticationException` (altered or
not a container), `WrongPassphraseException`, `NoMatchingRecipientException`
and `NotAKeyException`.

## Things worth knowing

- **A decrypted filename is attacker-controlled.** Never use it to choose an
  output path.
- Key material never crosses into PHP. `SecretKey` has no accessor for it, and
  `var_dump`, `print_r` and string interpolation all show only whether it is
  open or closed.
- `close()` is idempotent, and the key is also released when it is collected.
  A closed key cannot be used again.
- All strings crossing the boundary are handled by explicit length, never as
  NUL-terminated C strings, because metadata is attacker-controlled. A filename
  or media type you *supply* must not contain a NUL; one is refused rather than
  silently truncated.

## Tests

The suite runs against the real native library. PHPUnit is deliberately not a
dependency, so the tests run with nothing installed:

```sh
HIDE_LIBRARY=/path/to/libhide_ffi.so HIDE_ALLOW_LIBRARY_OVERRIDE=1 php -d ffi.enable=1 tests/run.php
```

It prints one line per test and exits non-zero if any failed.
