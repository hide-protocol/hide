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
`win-x64`, `win-arm64`, `osx-x64`, `osx-arm64`. The binding picks the right
one; no toolchain is needed. On any other platform the first call throws
`PlatformNotSupportedException` naming the runtime identifier; build the core
yourself and point the binding at it (see [Native library](#native-library)).
The package also carries the Apache-2.0 `LICENSE` text.

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

**Text arguments must not contain a NUL character.** Passphrases, the
filename, the media type, the challenge audience, armored key text and the
checkpoint origin cross the C boundary NUL-terminated, so a `string` carrying
`'\0'` would be silently cut at it: a key would be sealed under the part of the
passphrase before the NUL. Such a string throws `ArgumentException` instead.
Binary arguments (`ReadOnlySpan<byte>`: plaintext, context, message, keys) may
contain any byte.

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
| `Hide.VerifyIdentityPinned(log, recoveryBinding, pinnedRoot)` | `int` — devices trusted now, only if the log is the pinned identity |
| `Hide.VerifyEpochChain(chain)` | `int` — how many epochs it holds |
| `Hide.VerifyEpochChainBound(log, recoveryBinding, pinnedRoot, chain, epochBinding)` | `int` — epochs, only if a device the pinned log trusts signed this chain |
| `Hide.EpochPublicKey(chain, ulong epoch)` | the public key to encrypt to for `epoch` |
| `Hide.VerifyInclusion(leaf, ulong index, ulong size, path, root)` | `void` |
| `Hide.VerifyConsistency(ulong oldSize, ulong newSize, path, oldRoot, newRoot)` | `void` |
| `Hide.VerifyCheckpoint(note, string origin, logPublicKey)` | `(ulong Size, byte[] Root)` of a signed checkpoint |

A cryptographic verify **throws** on failure (`MalformedException` if the bytes
did not decode, `AuthenticationException` if they decoded but did not verify)
and never returns `false`. The one boolean is `IdentityTrustsDevice`: the log
is verified first, so `false` means "not a member", never "did not verify".

## Native library

The core is always loaded from an **absolute path**, found in this order:

1. `HIDE_LIBRARY`, if it names a file **and** `HIDE_ALLOW_LIBRARY_OVERRIDE=1`
   is also set. Without the opt-in it is ignored, whatever it names;
2. `hide_ffi.dll` / `libhide_ffi.dylib` / `libhide_ffi.so` beside the
   application or beside the `HideProtocol` assembly, or in
   `runtimes/<rid>/native/` under either — where the package's copy lands on
   build and publish;
3. `runtimes/<rid>/native/` of the NuGet package folder the assembly was
   loaded from.

If none of these has it, the first call throws `DllNotFoundException` saying
what was searched. The library is **never** looked up by name through the
system loader: the working directory, `PATH` and `LD_LIBRARY_PATH` /
`DYLD_LIBRARY_PATH` are not searched, because whoever controls one of those
would otherwise choose the cryptographic core. (The assembly also sets
`DefaultDllImportSearchPaths(AssemblyDirectory | SafeDirectories)`.)

The library must be the same release as the binding: at load the binding
compares `hide_version()` with its own assembly version (exact
major.minor.patch) and throws `HideException` on a mismatch, because a stale
core would load and silently lack whatever the newer release enforces.

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

Each handle wraps a `SafeHandle`, so the native object cannot be freed — by
the finalizer, or by `Dispose()` on another thread — while a call that uses it
is still running; the release waits for that call to return.

## Threads

Every static method of `Hide` is safe to call from any number of threads.

`SpentNonces` is safe for concurrent use: `Accept` serialises on an internal
lock, so one record can be shared by every request thread (register it as a
singleton), and an answer presented by many threads at once is accepted by
exactly one of them. The record is in-process memory: it is not shared between
processes and does not survive a restart, so replay protection across several
server instances needs the accepted nonces in shared storage as well.

`SecretKey` and `SigningIdentity` may be used from several threads at once;
the core only reads them.

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
