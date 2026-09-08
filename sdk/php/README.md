# hide-protocol/hide for PHP

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

PHP 8.1+ binding, through the built-in `ext-ffi` extension, to the same Rust
core (`crates/hide-ffi`) that the CLI and every other HIDE SDK use. This
package contains no cryptography of its own.

## Install

Not on Packagist yet. Build from source:

```sh
cargo build --release -p hide-ffi          # produces the native core
composer require hide-protocol/hide        # once published; until then add a `path` repository to sdk/php
```

The package does **not** bundle the native library. Point the binding at your
build — both variables are required (see [Native library](#native-library)):

```sh
export HIDE_LIBRARY="$PWD/target/release/libhide_ffi.so"    # hide_ffi.dll / libhide_ffi.dylib
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
```

Many distributions ship `ffi.enable=preload`, which leaves FFI unavailable to
ordinary scripts: set `ffi.enable=true` in `php.ini` or pass `-d ffi.enable=1`.

## Quick start

```php
<?php

require 'vendor/autoload.php';

use HideProtocol\AuthenticationException;
use HideProtocol\Hide;
use HideProtocol\SecretKey;

$secret = SecretKey::generate();
$box = Hide::encrypt('hello', [$secret->publicKey()], filename: 'note.txt');
$opened = Hide::decrypt($box, $secret);
echo "{$opened->plaintext} {$opened->filename}\n";   // hello note.txt

$tampered = $box;
$tampered[-1] = chr(ord($tampered[-1]) ^ 1);
try {
    Hide::decrypt($tampered, $secret);
} catch (AuthenticationException $e) {
    echo "refused: {$e->getMessage()}\n";            // refused: authentication failed; the data was altered
}
$secret->close();
```

`Hide::encrypt($plaintext, $recipients, $filename, $mediaType)` takes 1..64
recipient public keys, each exactly `Hide::PUBLIC_KEY_LEN` (1216) bytes.
`Hide::decrypt` returns a `Decrypted` with readonly `plaintext`, `filename` and
`mediaType`; nothing is returned unless the whole payload authenticates. The
filename is attacker-controlled: never use it to choose an output path.
Metadata you *supply* must not contain a NUL; it is refused rather than
silently truncated.

Keys on disk: `$secret->protect($passphrase)` returns a sealed key file
(`Hide::MIN_PASSPHRASE_LEN` is 8, and there is no escrow); `SecretKey::open($bytes,
$passphrase)` opens one; `Hide::inspectKey($bytes)` reports `"raw"` or
`"protected"` without the passphrase. `Hide::armorPublicKey` /
`Hide::dearmorPublicKey` give a public key a pasteable text form.

Errors: every failure is a `HideProtocol\HideException` — `AuthenticationException`
(altered, or not a container), its subclass `MalformedException` (did not
decode at all), `WrongPassphraseException`, `NoMatchingRecipientException`,
`NotAKeyException`, `ChallengeExpiredException`, `ChallengeReplayedException`.
Arguments this binding rejects before calling the core throw
`InvalidArgumentException`.

## Signing and verification

One seed backs both encryption and signing, so there is a single thing to back
up.

```php
use HideProtocol\ChallengeReplayedException;
use HideProtocol\SigningIdentity;
use HideProtocol\SpentNonces;

$sealed = SigningIdentity::generate('correct horse battery');   // store this
$signer = SigningIdentity::load($sealed, 'correct horse battery');

$context = 'myapp/v1 release';
$message = 'payload';
$signature = $signer->sign($context, $message);                 // 3373 bytes
Hide::verify($signer->publicKey(), $context, $message, $signature); // void; throws on failure

// Challenge/response: good once, here, now.
$now = time();
$challenge = Hide::newChallenge('app.example', $now, 60);
$answer = $signer->answer($challenge);
$spent = new SpentNonces();                                     // must outlive one request
$spent->accept($challenge, $answer, $signer->publicKey(), $now);
try {
    $spent->accept($challenge, $answer, $signer->publicKey(), $now);
} catch (ChallengeReplayedException) {
    echo "replay refused\n";
}
$spent->close();
$signer->close();
```

`$context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it.
`Hide::verify` returns `void` and throws `AuthenticationException` on failure
rather than returning a boolean a caller could forget to check. A key file
written before signatures existed carries no signing seed and throws
`NotAKeyException`.

## Identity logs, epoch chains, transparency proofs

| Method | Returns |
| --- | --- |
| `Hide::verifyIdentity($log, $recoveryKey)` | `int` — how many devices the log trusts now |
| `Hide::identityTrustsDevice($log, $recoveryKey, $devicePublicKey)` | `bool` — membership, after verifying the log |
| `Hide::identityHead($log, $recoveryKey)` | 32 bytes naming this exact history |
| `Hide::verifyEpochChain($chain)` | `int` — how many epochs it holds |
| `Hide::epochPublicKey($chain, int $epoch)` | the public key to encrypt to for `$epoch` |
| `Hide::verifyInclusion($leaf, int $index, int $size, $path, $root)` | `void` |
| `Hide::verifyConsistency(int $oldSize, int $newSize, $path, $oldRoot, $newRoot)` | `void` |

A cryptographic verify **throws** on failure (`MalformedException` if the bytes
did not decode, `AuthenticationException` if they decoded but did not verify)
and never returns `false`. The one boolean is `identityTrustsDevice`: the log
is verified first, so `false` means "not a member", never "did not verify".

## Native library

The core is located in this order:

1. `HIDE_LIBRARY`, if it names a file **and** `HIDE_ALLOW_LIBRARY_OVERRIDE=1`
   is also set;
2. a copy beside the package, in `src/` or `lib/`;
3. the system loader, by name (`libhide_ffi.so`, `libhide_ffi.dylib`,
   `hide_ffi.dll`).

`HIDE_LIBRARY` is a development override: it replaces the entire cryptographic
core, so a single settable environment variable must not be enough to redirect
it. The test suite runs the same way, with nothing else installed:

```sh
HIDE_LIBRARY=/path/to/libhide_ffi.so HIDE_ALLOW_LIBRARY_OVERRIDE=1 php -d ffi.enable=1 tests/run.php
```

## Key material

`SecretKey`, `SigningIdentity` and `SpentNonces` are opaque handles. The seed
bytes never cross into PHP and this SDK exposes no accessor for them;
`var_dump`, `print_r` and string interpolation show only whether the handle is
open. Release with `close()` (idempotent); a destructor backstops it when the
object is collected, but that leaves key material in memory for an unbounded
time. A closed handle throws `InvalidArgumentException` on use.

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
