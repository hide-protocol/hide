# HideProtocol for .NET

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

.NET 8+ binding, through P/Invoke, to the same Rust core (`crates/hide-ffi`)
that the CLI and every other HIDE SDK use. This package contains no
cryptography of its own.

## Install

```sh
dotnet add package HideProtocol
```

One nupkg carries the compiled core for all seven runtime identifiers under
`runtimes/<rid>/native/`: `linux-x64`, `linux-arm64`, `linux-musl-x64`,
`win-x64`, `win-arm64`, `osx-x64`, `osx-arm64`. The runtime picks the right
one; no toolchain is needed. On any other platform, build the core yourself and
point the binding at it (see [Native library](#native-library)).

## Quick start

```csharp
using HideProtocol;

using (SecretKey secret = SecretKey.Generate())
{
    byte[] box = Hide.Encrypt("hello"u8, [secret.PublicKey()], filename: "note.txt");
    Decrypted opened = Hide.Decrypt(box, secret);
    Console.WriteLine($"{System.Text.Encoding.UTF8.GetString(opened.Plaintext)} {opened.FileName}");
    // hello note.txt

    byte[] tampered = (byte[])box.Clone();
    tampered[^1] ^= 1;
    try
    {
        Hide.Decrypt(tampered, secret);
    }
    catch (AuthenticationException e)
    {
        Console.WriteLine($"refused: {e.Message}");
        // refused: authentication failed; the data was altered
    }
}
```

`Hide.Encrypt(plaintext, recipients, filename?, mediaType?)` takes 1..64
recipient public keys, each exactly `Hide.PublicKeyLength` (1216) bytes.
`Hide.Decrypt` returns a `Decrypted` record with `Plaintext`, `FileName` and
`MediaType`; nothing is returned unless the whole payload authenticates.
`FileName` is attacker-controlled: never use it to choose an output path.
Metadata passed *into* `Encrypt` may not contain a NUL byte; it is rejected
rather than silently truncated.

Keys on disk: `secret.Protect(passphrase)` returns a sealed key file
(`Hide.MinPassphraseLength` is 8, and there is no escrow); `SecretKey.Open(bytes,
passphrase)` opens one; `Hide.InspectKey(bytes)` reports `KeyKind.Raw` or
`KeyKind.Protected` without the passphrase. `Hide.ArmorPublicKey` /
`Hide.DearmorPublicKey` give a public key a pasteable text form.

Errors: every failure is a `HideException` — `AuthenticationException`
(altered, or not a container), its subclass `MalformedException` (did not
decode at all), `WrongPassphraseException`, `NoMatchingRecipientException`,
`NotAKeyException`, `ChallengeExpiredException`, `ChallengeReplayedException`.
Arguments this binding rejects before calling the core throw
`ArgumentException`.

## Signing and verification

One seed backs both encryption and signing, so there is a single thing to back
up.

```csharp
byte[] sealedKey = SigningIdentity.Generate("correct horse battery");   // store this

using (SigningIdentity signer = SigningIdentity.Load(sealedKey, "correct horse battery"))
using (SpentNonces spent = new())                                        // must outlive one request
{
    byte[] context = "myapp/v1 release"u8.ToArray();
    byte[] message = "payload"u8.ToArray();
    byte[] signature = signer.Sign(context, message);                    // 3373 bytes
    Hide.Verify(signer.PublicKey(), context, message, signature);        // void; throws on failure

    // Challenge/response: good once, here, now.
    ulong now = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    byte[] challenge = Hide.NewChallenge("app.example", now, 60);
    byte[] answer = signer.Answer(challenge);
    spent.Accept(challenge, answer, signer.PublicKey(), now);
    spent.Accept(challenge, answer, signer.PublicKey(), now);            // ChallengeReplayedException
}
```

`context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it.
`Hide.Verify` returns `void` and throws `AuthenticationException` on failure
rather than returning a boolean a caller could forget to check. A key file
written before signatures existed carries no signing seed and throws
`NotAKeyException`.

## Identity logs, epoch chains, transparency proofs

| Method | Returns |
| --- | --- |
| `Hide.VerifyIdentity(log, recoveryKey)` | `int` — how many devices the log trusts now |
| `Hide.IdentityTrustsDevice(log, recoveryKey, devicePublicKey)` | `bool` — membership, after verifying the log |
| `Hide.IdentityHead(log, recoveryKey)` | 32 bytes naming this exact history |
| `Hide.VerifyEpochChain(chain)` | `int` — how many epochs it holds |
| `Hide.EpochPublicKey(chain, ulong epoch)` | the public key to encrypt to for `epoch` |
| `Hide.VerifyInclusion(leaf, ulong index, ulong size, path, root)` | `void` |
| `Hide.VerifyConsistency(ulong oldSize, ulong newSize, path, oldRoot, newRoot)` | `void` |

A cryptographic verify **throws** on failure (`MalformedException` if the bytes
did not decode, `AuthenticationException` if they decoded but did not verify)
and never returns `false`. The one boolean is `IdentityTrustsDevice`: the log
is verified first, so `false` means "not a member", never "did not verify".

## Native library

The core is located in this order:

1. `HIDE_LIBRARY`, if it names a file **and** `HIDE_ALLOW_LIBRARY_OVERRIDE=1`
   is also set;
2. `hide_ffi.dll` / `libhide_ffi.dylib` / `libhide_ffi.so` beside the assembly
   — the package's `runtimes/<rid>/native/` copy lands here;
3. the platform's default probing paths.

`HIDE_LIBRARY` is a development override: it replaces the entire cryptographic
core, so a single settable environment variable must not be enough to redirect
it. Against a local build:

```powershell
cargo build --release -p hide-ffi
$env:HIDE_LIBRARY = "$PWD\target\release\hide_ffi.dll"
$env:HIDE_ALLOW_LIBRARY_OVERRIDE = '1'
```

```sh
cargo build --release -p hide-ffi
export HIDE_LIBRARY="$PWD/target/release/libhide_ffi.so"   # libhide_ffi.dylib on macOS
export HIDE_ALLOW_LIBRARY_OVERRIDE=1
```

## Key material

`SecretKey`, `SigningIdentity` and `SpentNonces` are opaque `IDisposable`
handles. The seed bytes never cross into managed memory and this SDK exposes no
accessor for them; `ToString()` renders nothing derived from the key. Release
with `Dispose()` or a `using` statement; a finalizer backstops it, but relying
on it keeps key material in memory for an unbounded time. A disposed handle
throws `ObjectDisposedException` on use.

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
