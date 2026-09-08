# org.hide-protocol:hide

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

Java binding, through the Foreign Function & Memory API (Java 22+), to the same
Rust core (`crates/hide-ffi`) that the CLI and every other HIDE SDK use. This
package contains no cryptography of its own and needs no JNI glue.

## Install

Not on Maven Central yet. Build from source:

```sh
cargo build --release -p hide-ffi          # produces the native core
cd sdk/java && mvn install                 # installs org.hide-protocol:hide:0.6.2
```

```xml
<dependency>
  <groupId>org.hide-protocol</groupId>
  <artifactId>hide</artifactId>
  <version>0.6.2</version>
</dependency>
```

The jar does **not** bundle the native library. Point the binding at your
build with either the environment pair or the system-property pair — both
halves are required (see [Native library](#native-library)):

```sh
export HIDE_LIBRARY="$PWD/target/release/libhide_ffi.so"    # hide_ffi.dll / libhide_ffi.dylib
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
# or
java -Dhide.library=/path/to/libhide_ffi.so -Dhide.allowLibraryOverride=true ...
```

Run with `--enable-native-access=ALL-UNNAMED` (or grant it to the module) to
silence the FFM restricted-method warning.

## Quick start

```java
import org.hideprotocol.*;
import java.nio.charset.StandardCharsets;
import java.util.List;

try (SecretKey secret = SecretKey.generate()) {
    byte[] box = Hide.encrypt("hello".getBytes(StandardCharsets.UTF_8),
            List.of(secret.publicKey()), "note.txt", null);
    Hide.Decrypted opened = Hide.decrypt(box, secret);
    System.out.println(new String(opened.data(), StandardCharsets.UTF_8) + " " + opened.filename());
    // hello note.txt

    byte[] tampered = box.clone();
    tampered[tampered.length - 1] ^= 1;
    try {
        Hide.decrypt(tampered, secret);
    } catch (HideException.Authentication e) {
        System.out.println("refused: " + e.getMessage());
        // refused: authentication failed; the data was altered
    }
}
```

`Hide.encrypt(plaintext, recipients, filename, mediaType)` takes 1..64
recipient public keys, each exactly `Hide.PUBLIC_KEY_LEN` (1216) bytes;
metadata may be `null`. `Hide.decrypt` returns a `Hide.Decrypted` record with
`data()`, `filename()` and `mediaType()`; nothing is returned unless the whole
payload authenticates. The filename is attacker-controlled: never use it to
build an output path.

Keys on disk: `secret.protect(passphrase)` returns a sealed key file
(`Hide.MIN_PASSPHRASE_LEN` is 8, and there is no escrow); `SecretKey.load(data,
passphrase)` opens one; `Hide.inspectKey(data)` reports `"raw"` or
`"protected"` without the passphrase. `Hide.armorPublicKey` /
`Hide.dearmorPublicKey` give a public key a pasteable text form.

Errors: every failure is a `HideException` (unchecked) — nested subclasses
`HideException.Authentication` (altered, or not a container), its subclass
`HideException.Malformed` (did not decode at all), `WrongPassphrase`,
`NoMatchingRecipient`, `NotAKey`, `ChallengeExpired`, `ChallengeReplayed`.
Arguments this binding rejects before calling the core throw
`IllegalArgumentException`.

## Signing and verification

One seed backs both encryption and signing, so there is a single thing to back
up.

```java
byte[] sealed = SigningIdentity.generate("correct horse battery");   // store this

try (SigningIdentity signer = SigningIdentity.load(sealed, "correct horse battery");
     SpentNonces spent = new SpentNonces()) {                        // must outlive one request
    byte[] context = "myapp/v1 release".getBytes(StandardCharsets.UTF_8);
    byte[] message = "payload".getBytes(StandardCharsets.UTF_8);
    byte[] signature = signer.sign(context, message);                // 3373 bytes
    Hide.verify(signer.publicKey(), context, message, signature);    // void; throws on failure

    // Challenge/response: good once, here, now.
    long now = System.currentTimeMillis() / 1000;
    byte[] challenge = Hide.newChallenge("app.example", now, 60);
    byte[] answer = signer.answer(challenge);
    spent.accept(challenge, answer, signer.publicKey(), now);
    spent.accept(challenge, answer, signer.publicKey(), now);        // HideException.ChallengeReplayed
}
```

`context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it.
`Hide.verify` returns `void` and throws `HideException.Authentication` on
failure rather than returning a boolean a caller could forget to check.
`Hide.sign(identity, context, message)` is a static alias for `signer.sign`. A
key file written before signatures existed carries no signing seed and throws
`HideException.NotAKey`.

## Identity logs, epoch chains, transparency proofs

| Method | Returns |
| --- | --- |
| `Hide.verifyIdentity(log, recoveryKey)` | `int` — how many devices the log trusts now |
| `Hide.identityTrustsDevice(log, recoveryKey, devicePublicKey)` | `boolean` — membership, after verifying the log |
| `Hide.identityHead(log, recoveryKey)` | 32 bytes naming this exact history |
| `Hide.verifyEpochChain(chain)` | `int` — how many epochs it holds |
| `Hide.epochPublicKey(chain, long epoch)` | the public key to encrypt to for `epoch` |
| `Hide.verifyInclusion(leaf, long index, long size, path, root)` | `void` |
| `Hide.verifyConsistency(long oldSize, long newSize, path, oldRoot, newRoot)` | `void` |

A cryptographic verify **throws** on failure (`HideException.Malformed` if the
bytes did not decode, `HideException.Authentication` if they decoded but did
not verify) and never returns `false`. The one boolean is
`identityTrustsDevice`: the log is verified first, so `false` means "not a
member", never "did not verify".

## Native library

The core is located in this order:

1. `-Dhide.library=<path>`, then `HIDE_LIBRARY`, if the file exists **and**
   either `-Dhide.allowLibraryOverride=true` or `HIDE_ALLOW_LIBRARY_OVERRIDE=1`
   is also set;
2. the system loader, by name (`hide_ffi.dll`, `libhide_ffi.dylib`,
   `libhide_ffi.so`) — put it on `java.library.path` / `PATH` /
   `LD_LIBRARY_PATH`, or beside the executable.

The jar does not carry a copy. The override is for development only: it
replaces the entire cryptographic core, so a single settable property or
environment variable must not be enough to redirect it.

## Key material

`SecretKey`, `SigningIdentity` and `SpentNonces` are opaque handles
implementing `AutoCloseable`. The seed bytes stay in the native library and
this SDK exposes no accessor for them; `toString()` shows only whether the
handle is open. Release with `close()` or try-with-resources. A closed handle
throws `IllegalStateException` on use.

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
