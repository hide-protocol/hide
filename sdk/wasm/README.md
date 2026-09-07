# @hide-protocol/wasm

HIDE in the browser, compiled to WebAssembly from the same Rust core the CLI
and desktop application use.

> **Experimental and unaudited.** Do not protect data you cannot afford to lose
> or expose. A successful decryption proves the data was not altered; it does
> **not** prove who sent it.
>
> A browser is also a weaker place to hold a key than a desktop: any script on
> the page shares the heap, so an XSS bug is equivalent to key theft. For keys
> that matter, prefer the CLI or the desktop application.

## Install

```sh
npm install @hide-protocol/wasm
```

## Use

```js
import init, { SecretKey, encrypt, decrypt } from "@hide-protocol/wasm";

await init();

const secret = SecretKey.generate();
const publicKey = secret.publicKey();

const box = encrypt(new TextEncoder().encode("hello"), publicKey, "note.txt", null);
const opened = decrypt(box, secret);
console.log(new TextDecoder().decode(opened.data));
```

`encrypt` takes recipients as concatenated public keys, so encrypting to
several people is one buffer:

```js
const recipients = new Uint8Array(alice.length + bob.length);
recipients.set(alice, 0);
recipients.set(bob, alice.length);
const box = encrypt(payload, recipients, null, null);
```

## Storing a key

```js
const sealed = secret.protect("a long passphrase");   // Argon2id + ChaCha20-Poly1305
const reopened = SecretKey.load(sealed, "a long passphrase");
```

A forgotten passphrase cannot be recovered: there is no escrow and no reset.

## Signing

```js
import { SigningIdentity, verify } from "@hide-protocol/wasm";

const keyFile = SigningIdentity.generate("a long passphrase"); // store this
const identity = SigningIdentity.load(keyFile, "a long passphrase");

const context = new TextEncoder().encode("myapp/invoice");
const signature = identity.sign(context, payload);
verify(identity.publicKey(), context, payload, signature); // throws if it fails
```

`context` separates uses of one identity, so a signature made for one purpose
cannot be replayed as another. Never let a remote party choose it. `verify`
returns nothing and throws on failure, so a forgotten check cannot read as a
pass.

A key file written before signatures existed carries no signing seed, and
`SigningIdentity.load` throws rather than silently downgrading it.

## Proving possession

A detached signature proves possession at some point, to nobody in particular,
and can be replayed. A challenge binds a nonce, an audience and an expiry:

```js
import { newChallenge, SpentNonces } from "@hide-protocol/wasm";

const now = BigInt(Math.floor(Date.now() / 1000));
const challenge = newChallenge("app.example", now, 60n);
const answer = identity.answer(challenge);

const spent = new SpentNonces();            // must outlive a single request
spent.accept(challenge, answer, identity.publicKey(), now);
spent.accept(challenge, answer, identity.publicKey(), now); // throws "replayed"
```

Only the verifier can catch a replay: a replayed answer is a genuine signature
and nothing about it is invalid on its own.

## What it does not do

The container is verified as intact, but nothing binds it to a person. Any
filename it carries is attacker-controlled: never use it to build a path, and
escape it before putting it in the DOM.

Full protocol limits: [SECURITY.md](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).
