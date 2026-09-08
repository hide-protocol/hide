# hide-wasm

WebAssembly bindings for the [HIDE](https://github.com/hide-protocol/hide)
protocol: hybrid post-quantum encryption (X25519 + ML-KEM-768) and signatures
(Ed25519 + ML-DSA-65) in the browser, plus verifiers for identity logs, epoch
chains and transparency proofs. It wraps the same crates the CLI uses and adds
no cryptography of its own; randomness comes from `crypto.getRandomValues`.

This crate is `publish = false`: it is built with `wasm-pack` and shipped to
npm as [`@hide-protocol/wasm`](https://www.npmjs.com/package/@hide-protocol/wasm).

```js
import init, { SecretKey, encrypt, decrypt, armor_public_key } from "@hide-protocol/wasm";

await init();
const secret = SecretKey.generate();
const publicKey = secret.public_key();           // 1216 bytes
console.log(armor_public_key(publicKey));

const container = encrypt(new TextEncoder().encode("hello"), publicKey, "hello.txt", "text/plain");
const opened = decrypt(container, secret);       // throws unless every chunk authenticates
console.log(new TextDecoder().decode(opened.data()), opened.filename());
```

The browser build works on whole buffers rather than streams and caps the
payload size; large files belong to the CLI or the desktop app. A decrypted
filename is attacker-controlled and must never be used to choose a path.

**Experimental and unaudited.** Licensed Apache-2.0.
