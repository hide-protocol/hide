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

Node.js 22 or newer. The examples below run on every supported version; from
Node.js 24 a handle can also be declared with `using` (see
[Key material](#key-material)).

## Quick start

```js
import { SecretKey, encrypt, decrypt, AuthenticationError } from "hide-protocol";

const secret = SecretKey.generate();
try {
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
} finally {
  secret.close();
}
```

`encrypt(plaintext, recipients, { filename?, mediaType? })` takes 1..64
recipient public keys, each exactly `PUBLIC_KEY_LEN` (1216) bytes. `decrypt`
returns `{ data, filename?, mediaType? }`; nothing is returned unless the whole
payload authenticates. The filename is attacker-controlled: never use it to
choose an output path.

A `filename` must be one portable file name, and encryption refuses anything
else: at most 255 bytes, not `.` or `..`, no control characters, none of
`< > : " / \ | ? *`, no trailing dot or space, and not a Windows device name
such as `CON` or `COM1`.

Keys on disk: `secret.protect(passphrase)` returns a sealed key file
(`MIN_PASSPHRASE_LEN` is 8, and there is no escrow); `SecretKey.load(data,
passphrase)` opens one; `inspectKey(data)` reports `"raw"` or `"protected"`
without the passphrase. `armorPublicKey` / `dearmorPublicKey` give a public key
a pasteable text form.

Errors: every failure is a subclass of `HideError` — `AuthenticationError`
(altered, or not a container), its subclass `MalformedError` (did not decode at
all), `WrongPassphraseError`, `NoMatchingRecipientError`, `NotAKeyError`,
`ChallengeExpiredError`, `ChallengeReplayedError`, `ChallengeAudienceError`.
Arguments this binding rejects before calling the core throw `RangeError`, or
`TypeError` when text is not a string.

Text arguments must not contain a NUL character. Passphrases, filenames,
media types, audiences, origins and armored keys cross into the core as C
strings, which end at the first NUL: `"longenough\0rest"` would otherwise seal
a key under `"longenough"`. Such text throws `RangeError` instead.

## Signing and verification

One seed backs both encryption and signing, so there is a single thing to back
up.

```js
import { SigningIdentity, verify, newChallenge, SpentNonces, ChallengeAudienceError, ChallengeReplayedError } from "hide-protocol";

const sealed = SigningIdentity.generate("correct horse battery");   // store this
const signer = SigningIdentity.load(sealed, "correct horse battery");
const spent = new SpentNonces("app.example");                        // must outlive one request
try {
  const context = Buffer.from("myapp/v1 release");
  const message = Buffer.from("payload");
  const signature = signer.sign(context, message);                  // 3373 bytes
  verify(signer.publicKey(), context, message, signature);          // void; throws on failure

  // Challenge/response: good once, here, now.
  const now = Math.floor(Date.now() / 1000);
  const challenge = newChallenge("app.example", now, 60);
  const answer = signer.answer(challenge);
  spent.accept(challenge, answer, signer.publicKey(), now);
  try {
    spent.accept(challenge, answer, signer.publicKey(), now);
  } catch (e) {
    if (e instanceof ChallengeReplayedError) console.log("replay refused");
  }
} finally {
  spent.close();
  signer.close();
}
```

A record must be built with the name this verifier answers to, exactly the
audience the challenge was issued for: an answer minted for another audience —
a challenge relayed from another service — throws `ChallengeAudienceError`, and
a record built with an empty audience accepts nothing.

`context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it. Contexts
beginning with `HIDE/` are reserved for the protocol: `sign` refuses them with
`RangeError`, while `verify` accepts any context. `verify`
returns nothing and throws `AuthenticationError` on failure rather than
returning a boolean a caller could forget to check. A key file written before
signatures existed carries no signing seed and throws `NotAKeyError`.

## Threads

Every call into the core is synchronous and runs on the thread that made it,
so within one JavaScript thread two calls never overlap and nothing needs a
lock, `SpentNonces.accept` included. The calls are not asynchronous: each
blocks the event loop until it returns, which is longest for the ones that
derive a key from a passphrase (`protect`, `SigningIdentity.generate`, and
`load` of a protected key).

A handle cannot be sent to a worker thread: `postMessage` and
`structuredClone` carry none of its state. Each worker loads its own copy of
this package and must create its own handles. A `SpentNonces` in one worker
therefore knows nothing of answers accepted in another: keep the record on
one thread and route every `accept` to it.

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
| `verifyIdentityPinned(log, recoveryBinding, pinnedRoot)` | `number` — devices trusted now, only if the log is the identity under the pinned 32-byte root |
| `verifyEpochChainBound(log, recoveryBinding, pinnedRoot, chain, epochBinding)` | `number` — epochs, only if a device the log trusts signed this chain |
| `verifyCheckpoint(note, origin, logPublic)` | `{ size: bigint, root: Buffer }` from a signed checkpoint note |

A cryptographic verify **throws** on failure (`MalformedError` if the bytes did
not decode, `AuthenticationError` if they decoded but did not verify) and never
returns `false`. The one boolean is `identityTrustsDevice`: the log is verified
first, so `false` means "not a member", never "did not verify". Integer
arguments accept `number` or `bigint`.

The pinned checks are what a relying party uses: `pinnedRoot` is obtained out
of band, and `recoveryBinding` establishes the recovery key, so a log extended
by a Recover under a stranger's key throws `AuthenticationError`. A pinned root
that is not 32 bytes throws `RangeError`.

## Native library

The core is loaded from the first of these that exists, always by absolute
path:

1. `HIDE_LIBRARY`, if it names a file **and** `HIDE_ALLOW_LIBRARY_OVERRIDE=1`
  is also set. Once opted in it is the only candidate: if it cannot be
  loaded, the import fails rather than falling back to another copy;
2. the platform package for this machine (`@hide-protocol/<platform>-<arch>`,
  with `-musl` on musl Linux), looked up in the `node_modules` directories
  above this package, the way Node finds any dependency;
3. a copy inside this package itself (`dist/`, the package root, or
  `native/`).

Nothing else is consulted. The system loader is never asked to search by
name, so a library in the working directory, on `PATH` or on
`LD_LIBRARY_PATH` is not picked up; and `NODE_PATH` and the global module
folders are not searched for the platform package, because either would let
one environment variable or one file in a home directory choose the core. A
`node_modules` layout is therefore required (npm, pnpm, or Yarn's
`node-modules` linker). If no candidate exists, importing the package throws
an error naming the platform and the package to install.

`HIDE_LIBRARY` is a development override: it replaces the entire cryptographic
core, so a single settable environment variable must not be enough to redirect
it. Against a local build:

```sh
cargo build --release -p hide-ffi
export HIDE_LIBRARY="$PWD/target/release/libhide_ffi.so"   # hide_ffi.dll / libhide_ffi.dylib
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
```

The core and the binding must be the same release. At import the binding
compares the core's `major.minor.patch` with its own and throws on any
difference: the core enforces checks this binding only documents, so an older
core beside a newer binding would silently lose them.

## Key material

`SecretKey` and `SigningIdentity` are opaque handles. The seed bytes stay in the
native library and this SDK exposes no accessor for them; `toJSON()` renders
only `"[hide.SecretKey]"`. Release a handle with `close()`; a
`FinalizationRegistry` backstop also frees it on collection, but that leaves
key material in memory for an unbounded time. A closed handle throws
`TypeError` on use.

From Node.js 24, which added explicit resource management, a handle can be
declared with `using` and is closed when the block ends:

```js
{
  using secret = SecretKey.generate();
  // ...
} // secret.close() has run
```

On Node.js 22 `using` is a syntax error; call `close()` in a `finally` block
as the examples above do.

Handles come only from `SecretKey.generate()`, `SecretKey.load()`,
`SigningIdentity.load()` and `new SpentNonces()`. `new SecretKey(...)` and
`new SigningIdentity(...)` throw `TypeError`: a second object around the same
native key would free it twice.

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
