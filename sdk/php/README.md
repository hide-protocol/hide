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

The package does **not** bundle the native library, and the binding must be
told where it is: either copy it into the package's `lib/` (or `src/`)
directory, or point at your build — both variables are required (see
[Native library](#native-library)):

```sh
export HIDE_LIBRARY="$PWD/target/release/libhide_ffi.so"    # hide_ffi.dll / libhide_ffi.dylib
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
```

The library must be the same release as the binding: at load the binding
compares `hide_version()` with `Binding::VERSION` (exact major.minor.patch) and
throws `HideException` on a mismatch, because a stale core would load and
silently lack whatever the newer release enforces.

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

**Text arguments must not contain a NUL byte.** Passphrases, the filename, the
media type, the challenge audience, armored key text and the checkpoint origin
cross the C boundary NUL-terminated, so a string carrying `"\0"` would be
silently cut at it: a key would be sealed under the part of the passphrase
before the NUL. Such a string throws `InvalidArgumentException` instead. Binary
arguments (plaintext, context, message, keys) may contain any byte.

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
$spent = new SpentNonces();                                     // one process only: see "Replay protection"
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

### Replay protection under PHP-FPM, mod_php and other per-request runtimes

`SpentNonces` is the verifier's memory of the answers it has accepted, and in
PHP that memory is **one process, one request**. It cannot be serialized, put
in a session, stored in APCu or shared between workers, and under PHP-FPM or
mod_php every request starts with an empty record. So in a normal web
deployment:

- `SpentNonces::accept()` still checks the signature and the expiry, and still
  refuses a second presentation *within the same request*;
- it does **not** stop the same answer being replayed in a later request, or
  to another worker, until the challenge expires.

To get replay protection across requests you must record each accepted
challenge yourself, in storage every worker shares, and make the check and the
record one atomic step — for example an `INSERT` of `hash('sha256', $challenge)`
into a table with a unique key (or a cache `add` that fails when the key
exists), kept until the challenge's expiry. Call `accept()` first; only if it
returns, try the insert, and treat "already there" as a replay. Keep the
validity window (`$validFor`) short: it bounds how long each entry must be
kept. Always pass `accept()` the challenge bytes **you issued** for this
session (store them server-side), never ones echoed back by the client.

In a long-running PHP process (a CLI daemon, Swoole, RoadRunner, FrankenPHP
worker mode) one `SpentNonces` does outlive requests, but still only inside
that one worker process. PHP runs one request at a time per process, so the
record needs no locking.

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
| `Hide::verifyIdentityPinned($log, $recoveryBinding, $pinnedRoot)` | `int` — devices trusted, after checking the log against the 32-byte root you pinned |
| `Hide::verifyEpochChainBound($log, $recoveryBinding, $pinnedRoot, $chain, $epochBinding)` | `int` — epochs held, after proving the chain belongs to that identity |
| `Hide::verifyCheckpoint($note, string $origin, $logPublic)` | `['size' => int, 'root' => string]` — tree size and 32-byte root of a signed checkpoint note |

A cryptographic verify **throws** on failure (`MalformedException` if the bytes
did not decode, `AuthenticationException` if they decoded but did not verify)
and never returns `false`. The one boolean is `identityTrustsDevice`: the log
is verified first, so `false` means "not a member", never "did not verify".

`verifyIdentityPinned` is the relying-party check (spec §16): a recovery key
taken from the same untrusted source as the log cannot catch a Recover appended
under a stranger's key, but a `$recoveryBinding` checked against a root you
trust out of band does.

## Native library

The core is always loaded from an **absolute path**, found in this order:

1. `HIDE_LIBRARY`, if `HIDE_ALLOW_LIBRARY_OVERRIDE=1` is also set (a path that
   is not a file is then an error). Without the opt-in it is ignored, whatever
   it names;
2. `libhide_ffi.so` / `libhide_ffi.dylib` / `hide_ffi.dll` beside the package,
   in `src/` or `lib/`.

If neither finds it, the first call throws `HideException` saying where it
looked and for which platform. The library is **never** left to the system
loader to find by name: `LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH`, `PATH` and the
working directory are not searched, because whoever controls one of those
would otherwise choose the cryptographic core.

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

A handle owns exactly one native object, so it **cannot be copied**: `clone`
is an `Error`, and `serialize()` / `unserialize()` throw `HideException`. Pass
the object itself around (PHP objects are passed by handle), store a key with
`protect()`, and reload it with `SecretKey::open()` or
`SigningIdentity::load()`.

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
