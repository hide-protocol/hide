# hide-protocol for Node.js

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

Node.js binding, through [koffi](https://koffi.dev), to the same Rust core
(`crates/hide-ffi`) that the CLI and every other HIDE SDK use. This package
contains no cryptography of its own. For the browser, use
[`@hide-protocol/wasm`](https://www.npmjs.com/package/@hide-protocol/wasm).

## Install

```sh
npm install hide-protocol
```

The compiled core ships as seven platform packages pulled in through
`optionalDependencies`, so npm fetches only the one for your machine:
`@hide-protocol/darwin-arm64`, `darwin-x64`, `linux-arm64`, `linux-x64`,
`linux-x64-musl`, `win32-arm64`, `win32-x64`. On any other platform, build the
core yourself and point the binding at it (see [Native library](#native-library)).

## Quick start

```js
import { SecretKey, encrypt, decrypt, AuthenticationError } from "hide-protocol";

using secret = SecretKey.generate();
const box = encrypt(Buffer.from("hello"), [secret.publicKey()], { filename: "note.txt" });
const opened = decrypt(box, secret);
console.log(opened.data.toString(), opened.filename); // hello note.txt

const tampered = Buffer.from(box);
tampered[tampered.length - 1] ^= 1;
try {
  decrypt(tampered, secret);
} catch (e) {
  if (e instanceof AuthenticationError) console.log("refused:", e.message);
  // refused: authentication failed; the data was altered
}
```

`encrypt(plaintext, recipients, { filename?, mediaType? })` takes 1..64
recipient public keys, each exactly `PUBLIC_KEY_LEN` (1216) bytes. `decrypt`
returns `{ data, filename?, mediaType? }`; nothing is returned unless the whole
payload authenticates. The filename is attacker-controlled: never use it to
choose an output path.

Keys on disk: `secret.protect(passphrase)` returns a sealed key file
(`MIN_PASSPHRASE_LEN` is 8, and there is no escrow); `SecretKey.load(data,
passphrase)` opens one; `inspectKey(data)` reports `"raw"` or `"protected"`
without the passphrase. `armorPublicKey` / `dearmorPublicKey` give a public key
a pasteable text form.

Errors: every failure is a subclass of `HideError` — `AuthenticationError`
(altered, or not a container), its subclass `MalformedError` (did not decode at
all), `WrongPassphraseError`, `NoMatchingRecipientError`, `NotAKeyError`,
`ChallengeExpiredError`, `ChallengeReplayedError`. Arguments this binding
rejects before calling the core throw `RangeError`.

## Signing and verification

One seed backs both encryption and signing, so there is a single thing to back
up.

```js
import { SigningIdentity, verify, newChallenge, SpentNonces, ChallengeReplayedError } from "hide-protocol";

const sealed = SigningIdentity.generate("correct horse battery");   // store this
using signer = SigningIdentity.load(sealed, "correct horse battery");

const context = Buffer.from("myapp/v1 release");
const message = Buffer.from("payload");
const signature = signer.sign(context, message);                    // 3373 bytes
verify(signer.publicKey(), context, message, signature);            // void; throws on failure

// Challenge/response: good once, here, now.
const now = Math.floor(Date.now() / 1000);
const challenge = newChallenge("app.example", now, 60);
const answer = signer.answer(challenge);
using spent = new SpentNonces();                                    // must outlive one request
spent.accept(challenge, answer, signer.publicKey(), now);
try {
  spent.accept(challenge, answer, signer.publicKey(), now);
} catch (e) {
  if (e instanceof ChallengeReplayedError) console.log("replay refused");
}
```

`context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it. `verify`
returns nothing and throws `AuthenticationError` on failure rather than
returning a boolean a caller could forget to check. A key file written before
signatures existed carries no signing seed and throws `NotAKeyError`.

## Identity logs, epoch chains, transparency proofs

| Function | Returns |
| --- | --- |
| `verifyIdentity(log, recoveryKey)` | `number` — how many devices the log trusts now |
| `identityTrustsDevice(log, recoveryKey, devicePublicKey)` | `boolean` — membership, after verifying the log |
| `identityHead(log, recoveryKey)` | 32-byte `Buffer` naming this exact history |
| `verifyEpochChain(chain)` | `number` — how many epochs it holds |
| `epochPublicKey(chain, epoch)` | the public key to encrypt to for `epoch` |
| `verifyInclusion(leaf, index, size, path, root)` | `void` |
| `verifyConsistency(oldSize, newSize, path, oldRoot, newRoot)` | `void` |

A cryptographic verify **throws** on failure (`MalformedError` if the bytes did
not decode, `AuthenticationError` if they decoded but did not verify) and never
returns `false`. The one boolean is `identityTrustsDevice`: the log is verified
first, so `false` means "not a member", never "did not verify". Integer
arguments accept `number` or `bigint`.

## Native library

The core is located in this order:

1. `HIDE_LIBRARY`, if it names a file **and** `HIDE_ALLOW_LIBRARY_OVERRIDE=1`
   is also set;
2. the platform package for this machine (`@hide-protocol/<platform>-<arch>`);
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
native library and this SDK exposes no accessor for them; `toJSON()` renders
only `"[hide.SecretKey]"`. Release a handle with `close()` or `using` (explicit
resource management, Node 24+); a `FinalizationRegistry` backstop also frees it
on collection, but that leaves key material in memory for an unbounded time. A
closed handle throws `TypeError` on use.

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
