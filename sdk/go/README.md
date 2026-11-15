# github.com/hide-protocol/hide/sdk/go

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

Go binding, through cgo, to the same Rust core (`crates/hide-ffi`) that the CLI
and every other HIDE SDK use. This package contains no cryptography of its own.

## Install

**`go get github.com/hide-protocol/hide/sdk/go` alone does not give you a
package that compiles.** The core is **statically linked**: the cgo directives
in `hide.go` expect `include/hide.h` and `lib/libhide_ffi.a` beside the
package, and neither is committed (they are build outputs of the Rust core, and
the module cache is read-only). Clone the repository and build the core first.
You need Go 1.24+, `CGO_ENABLED=1`, a C toolchain and a Rust toolchain.

Linux and macOS:

```sh
git clone https://github.com/hide-protocol/hide && cd hide
cargo build --release -p hide-ffi
mkdir -p sdk/go/include sdk/go/lib
cp crates/hide-ffi/include/hide.h sdk/go/include/
cp target/release/libhide_ffi.a sdk/go/lib/
cd sdk/go && CGO_ENABLED=1 go test ./...
```

Windows (PowerShell). The archive must be GNU-ABI, because MinGW gcc cannot
link an MSVC-built static library, so build for the `x86_64-pc-windows-gnu`
target with a MinGW-w64 `gcc` on `PATH`:

```powershell
git clone https://github.com/hide-protocol/hide; cd hide
rustup target add x86_64-pc-windows-gnu
cargo build --release -p hide-ffi --target x86_64-pc-windows-gnu
New-Item -ItemType Directory -Force sdk\go\include, sdk\go\lib | Out-Null
Copy-Item crates\hide-ffi\include\hide.h sdk\go\include\
Copy-Item target\x86_64-pc-windows-gnu\release\libhide_ffi.a sdk\go\lib\
cd sdk\go; $env:CGO_ENABLED = '1'; go test ./...
```

Then point your own module at the checkout:

```sh
go mod edit -replace github.com/hide-protocol/hide/sdk/go=/path/to/hide/sdk/go
go get github.com/hide-protocol/hide/sdk/go
```

What a missing piece looks like:

- no header: the build stops with `sdk/go/include/hide.h is missing. ...` and
  these instructions;
- `CGO_ENABLED=0`: `undefined:
  hide_needs_CGO_ENABLED_1_and_a_C_toolchain__see_sdk_go_README_md`;
- an operating system other than Linux, macOS or Windows: `undefined:
  hide_links_only_on_linux_darwin_and_windows__see_sdk_go_README_md`;
- an archive left over from another release: the package panics at start-up
  with `this binding is version X but the linked native core reports "Y"`.
  `hide.BindingVersion` must equal `hide.Version()` exactly
  (major.minor.patch), because a stale core links cleanly and silently lacks
  whatever the newer release enforces. Rebuild and copy the archive again.

## Quick start

```go
package main

import (
	"bytes"
	"errors"
	"fmt"

	hide "github.com/hide-protocol/hide/sdk/go"
)

func main() {
	secret, err := hide.GenerateKey()
	if err != nil {
		panic(err)
	}
	defer secret.Close()

	public, _ := secret.PublicKey()
	box, err := hide.Encrypt([]byte("hello"), [][]byte{public}, hide.Options{Filename: "note.txt"})
	if err != nil {
		panic(err)
	}

	opened, err := hide.Decrypt(box, secret)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(opened.Data), opened.Filename) // hello note.txt

	tampered := bytes.Clone(box)
	tampered[len(tampered)-1] ^= 1
	if _, err := hide.Decrypt(tampered, secret); errors.Is(err, hide.ErrAuthentication) {
		fmt.Println("refused:", err) // refused: hide: authentication failed; the data was altered
	}
}
```

`Encrypt(plaintext, recipients, Options{Filename, MediaType})` takes 1..64
recipient public keys, each exactly `PublicKeyLen` (1216) bytes. `Decrypt`
returns a `*Decrypted` with `Data`, `Filename` and `MediaType`; nothing is
returned unless the whole payload authenticates. `Filename` is
attacker-controlled: never use it to build an output path.

Keys on disk: `secret.Protect(passphrase)` returns a sealed key file
(`MinPassphraseLen` is 8, and there is no escrow); `LoadKey(data, passphrase)`
opens one (pass `""` for a raw key); `InspectKey(data)` reports `"raw"` or
`"protected"` without the passphrase. `ArmorPublicKey` / `DearmorPublicKey`
give a public key a pasteable text form.

Errors are sentinel values for `errors.Is`: `ErrAuthentication` (altered, or not
a container), `ErrMalformed` (did not decode at all — wraps
`ErrAuthentication`), `ErrInvalidArgument`, `ErrWrongPassphrase`,
`ErrNoMatchingRecipient`, `ErrNotAKey`, `ErrClosed`, `ErrChallengeExpired`,
`ErrChallengeReplayed`, `ErrChallengeAudience`. Arguments this package rejects
before calling the core (recipient count, key length, a short passphrase, a nil
key, a NUL in text) are `ErrInvalidArgument` too.

**Text arguments must not contain a NUL byte.** Passphrases, `Options.Filename`,
`Options.MediaType`, the challenge audience, armored key text and the
checkpoint origin cross the C boundary NUL-terminated, so a string carrying a
NUL would be silently cut at it: a key would be sealed under the part of the
passphrase before the NUL. Such a string returns `ErrInvalidArgument` instead.
Binary arguments (`[]byte`: plaintext, context, message, keys) may contain any
byte.

## Signing and verification

One seed backs both encryption and signing, so there is a single thing to back
up.

```go
sealed, _ := hide.GenerateIdentity("correct horse battery") // store this
signer, err := hide.LoadSigningIdentity(sealed, "correct horse battery")
if err != nil {
	panic(err)
}
defer signer.Close()

verifying, _ := signer.PublicKey()
context, message := []byte("myapp/v1 release"), []byte("payload")
signature, _ := signer.Sign(context, message)                       // 3373 bytes
if err := hide.Verify(verifying, context, message, signature); err != nil {
	panic(err) // nil on success; ErrAuthentication otherwise
}

// Challenge/response: good once, here, now.
now := uint64(time.Now().Unix())
challenge, _ := hide.NewChallenge("app.example", now, 60)
answer, _ := signer.Answer(challenge)
spent, _ := hide.NewSpentNonces("app.example") // the name this verifier answers to
defer spent.Close()                            // the record must outlive one request
_ = spent.Accept(challenge, answer, verifying, now)
err = spent.Accept(challenge, answer, verifying, now)
fmt.Println(errors.Is(err, hide.ErrChallengeReplayed)) // true
```

`context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it. `Verify`
returns an `error`, never a `bool`. A key file written before signatures
existed carries no signing seed and returns `ErrNotAKey`.

The nonce record must be built with the name this verifier answers to — the
same `audience` passed to `NewChallenge` — because an answer minted for a
different audience is refused with `ErrChallengeAudience`, so a challenge
relayed from another service cannot be answered here. A record built with an
empty audience accepts nothing.

## Identity logs, epoch chains, transparency proofs

| Function | Returns |
| --- | --- |
| `VerifyIdentity(log, recoveryKey)` | `(int, error)` — how many devices the log trusts now |
| `IdentityTrustsDevice(log, recoveryKey, devicePublicKey)` | `(bool, error)` — membership, after verifying the log |
| `IdentityHead(log, recoveryKey)` | `([]byte, error)` — 32 bytes naming this exact history |
| `VerifyIdentityPinned(log, recoveryBinding, pinnedRoot)` | `(int, error)` — devices trusted now, only if the log is the pinned identity |
| `VerifyEpochChain(chain)` | `(int, error)` — how many epochs it holds |
| `VerifyEpochChainBound(log, recoveryBinding, pinnedRoot, chain, epochBinding)` | `(int, error)` — epochs, only if a device the pinned log trusts signed this chain |
| `EpochPublicKey(chain, epoch uint64)` | `([]byte, error)` — the key to encrypt to for `epoch` |
| `VerifyInclusion(leaf, index, size, path, root)` | `error` |
| `VerifyConsistency(oldSize, newSize, path, oldRoot, newRoot)` | `error` |
| `VerifyCheckpoint(note, origin, logPublicKey)` | `(uint64, []byte, error)` — tree size and 32-byte root of a signed checkpoint |

A cryptographic verify returns a non-nil `error` on failure (`ErrMalformed` if
the bytes did not decode, `ErrAuthentication` if they decoded but did not
verify) and never a bare `false`. The one boolean is `IdentityTrustsDevice`,
and it is paired with an error: the log is verified first, so `false, nil`
means "not a member", never "did not verify".

## Concurrency

Every package-level function is safe to call from any number of goroutines.

`*SpentNonces` is safe for concurrent use: `Accept` and `Close` serialise on an
internal mutex, so one record can be shared by every request handler, and an
answer presented by many goroutines at once is accepted by exactly one of them.
The record is in-process memory: it is not shared between processes and does
not survive a restart, so replay protection across several server instances
needs the accepted nonces in shared storage as well.

`*SecretKey` and `*SigningIdentity` may be *used* from several goroutines at
once (the core only reads them), but `Close` must not race with a call in
flight on the same handle: close a handle only when nothing else is using it.

## Native library

Unlike the dynamic SDKs there is no runtime lookup, nothing is loaded from
disk when your program runs, and there is no `HIDE_LIBRARY` override:
`libhide_ffi.a` is linked into your binary at build time from `sdk/go/lib/`, so
the core cannot be swapped after compilation and there is no search path to
plant a library on. Linux links `-lm -ldl -lpthread`, macOS `-framework
Security`, Windows `-lbcrypt -ladvapi32 -luserenv -lntdll -lws2_32`.

## Key material

`*SecretKey` and `*SigningIdentity` are opaque handles. The seed bytes stay in
the native library and this package exposes no accessor for them; `String()`
shows only whether the handle is open. Call `Close()` when finished (`defer`
is the idiom); a finalizer is registered as a backstop, but relying on it keeps
key material in memory for an unbounded time. The finalizer cannot run while a
call on the handle is still in progress. A closed handle returns `ErrClosed`.

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
