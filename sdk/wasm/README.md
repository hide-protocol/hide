# @hide-protocol/wasm

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

HIDE in the browser: the same Rust core the CLI, desktop app and every native
SDK use, compiled to WebAssembly with wasm-bindgen (`--target web`). No
JavaScript cryptography is involved.

A browser is a weaker place to hold a key than a desktop: any script on the page
shares the heap, so an XSS bug is equivalent to key theft. For keys that
matter, prefer the CLI or the desktop application.

## Install

```sh
npm install @hide-protocol/wasm
```

There is **no native library**: the package is `hide_wasm.js`, its `.d.ts` and
`hide_wasm_bg.wasm`, and runs anywhere WebAssembly does. Payloads are capped at
64 MiB in this build. For Node.js servers, prefer
[`hide-protocol`](https://www.npmjs.com/package/hide-protocol), which binds the
native core.

## Quick start

```js
import init, { SecretKey, encrypt, decrypt } from "@hide-protocol/wasm";

await init(); // fetches hide_wasm_bg.wasm relative to the module

const alice = SecretKey.generate();
const bob = SecretKey.generate();

// Recipients are ONE Uint8Array of concatenated 1216-byte public keys.
const alicePublic = alice.publicKey();
const bobPublic = bob.publicKey();
const recipients = new Uint8Array(alicePublic.length + bobPublic.length);
recipients.set(alicePublic, 0);
recipients.set(bobPublic, alicePublic.length);

const box = encrypt(new TextEncoder().encode("hello"), recipients, "note.txt", null);
const opened = decrypt(box, bob);
console.log(new TextDecoder().decode(opened.data), opened.filename); // hello note.txt

const tampered = new Uint8Array(box);
tampered[tampered.length - 1] ^= 1;
try {
	decrypt(tampered, bob);
} catch (e) {
	console.log("refused:", String(e)); // refused: cryptographic authentication failed
}

alice.free();
bob.free();
```

`encrypt(plaintext, recipients, filename | null, mediaType | null)` takes 1..64
recipients **concatenated into a single `Uint8Array`**, not an array of keys.
`decrypt` returns a `Decrypted` with getters `data`, `filename` and
`mediaType`; nothing is returned unless the whole payload authenticates. The
filename is attacker-controlled: never use it to build a path, and escape it
before putting it in the DOM.

Keys on disk: `secret.protect(passphrase)` returns a sealed key file (at least
8 characters, and there is no escrow); `SecretKey.load(bytes, passphrase)` opens
one; `inspectKey(bytes)` reports `"raw"` or `"protected"` without the
passphrase. `armorPublicKey` / `dearmorPublicKey` give a public key a pasteable
text form.

Errors: wasm-bindgen surfaces every failure as a thrown JavaScript `Error`
whose message names the cause (`cryptographic authentication failed`,
`replayed`, `expired`, …). There are no typed subclasses in this build; match
on the message if you must distinguish causes.

## Signing and verification

One seed backs both encryption and signing, so there is a single thing to back
up.

```js
import { SigningIdentity, verify, newChallenge, SpentNonces } from "@hide-protocol/wasm";

const keyFile = SigningIdentity.generate("correct horse battery");   // store this
const identity = SigningIdentity.load(keyFile, "correct horse battery");

const context = new TextEncoder().encode("myapp/v1 release");
const message = new TextEncoder().encode("payload");
const signature = identity.sign(context, message);                  // 3373 bytes
verify(identity.publicKey(), context, message, signature);          // undefined; throws on failure

// Challenge/response: good once, here, now. Integers are BigInt.
const now = BigInt(Math.floor(Date.now() / 1000));
const challenge = newChallenge("app.example", now, 60n);
const answer = identity.answer(challenge);
const spent = new SpentNonces();                                    // must outlive one request
spent.accept(challenge, answer, identity.publicKey(), now);
spent.accept(challenge, answer, identity.publicKey(), now);         // throws: replayed

identity.free();
```

`context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it. `verify`
returns nothing and throws on failure rather than returning a boolean a caller
could forget to check. A key file written before signatures existed carries no
signing seed and `SigningIdentity.load` throws rather than silently downgrading
it.

## Identity logs, epoch chains, transparency proofs

| Function | Returns |
| --- | --- |
| `verifyIdentity(log, recovery)` | `number` — how many devices the log trusts now |
| `identityTrustsDevice(log, recovery, devicePublic)` | `boolean` — membership, after verifying the log |
| `identityHead(log, recovery)` | 32-byte `Uint8Array` naming this exact history |
| `verifyEpochChain(chain)` | `number` — how many epochs it holds |
| `epochPublicKey(chain, epoch: bigint)` | the public key to encrypt to for `epoch` |
| `verifyInclusion(leaf, index: bigint, size: bigint, path, root)` | `undefined` |
| `verifyConsistency(oldSize: bigint, newSize: bigint, path, oldRoot, newRoot)` | `undefined` |

A cryptographic verify **throws** on failure and never returns `false`. The one
boolean is `identityTrustsDevice`: the log is verified first, so `false` means
"not a member", never "did not verify".

## Native library

None. The core is compiled into `hide_wasm_bg.wasm`, loaded by `init()` from a
URL relative to `hide_wasm.js` (or pass `init(bytesOrUrl)` explicitly). There
is no `HIDE_LIBRARY` override in this build: the module you import is the
cryptographic core, so pin the package version and check its integrity through
your lockfile.

## Key material

`SecretKey`, `SigningIdentity` and `SpentNonces` are opaque handles into WASM
linear memory; the seed bytes are never returned to JavaScript and there is no
accessor for them. Call `free()` when finished to zeroize and release the
handle — the garbage collector does not do it for you. The linear memory is
still readable by any script on the page, which is why a browser key is weaker
than a desktop one.

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
