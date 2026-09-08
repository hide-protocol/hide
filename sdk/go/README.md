# github.com/hide-protocol/hide/sdk/go

*Experimental and unaudited. HIDE is hybrid post-quantum (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65). See the [security policy](https://github.com/hide-protocol/hide/blob/main/SECURITY.md).*

Go binding, through cgo, to the same Rust core (`crates/hide-ffi`) that the CLI
and every other HIDE SDK use. This package contains no cryptography of its own.

## Install

```sh
go get github.com/hide-protocol/hide/sdk/go
```

Go 1.24+, `CGO_ENABLED=1` and a C toolchain. The core is **statically linked**:
the cgo directives in `hide.go` expect `include/hide.h` and
`lib/libhide_ffi.a` beside the package, and neither is committed. Build them
from the repository:

```sh
cargo build --release -p hide-ffi
mkdir -p sdk/go/include sdk/go/lib
cp crates/hide-ffi/include/hide.h sdk/go/include/
cp target/release/libhide_ffi.a sdk/go/lib/
cd sdk/go && CGO_ENABLED=1 go test ./...
```

On Windows the archive must be GNU-ABI, because MinGW gcc cannot link an
MSVC-built staticlib: `cargo build --release -p hide-ffi --target
x86_64-pc-windows-gnu` and copy from `target/x86_64-pc-windows-gnu/release/`.

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
`ErrChallengeReplayed`.

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
spent, _ := hide.NewSpentNonces() // must outlive one request
defer spent.Close()
_ = spent.Accept(challenge, answer, verifying, now)
err = spent.Accept(challenge, answer, verifying, now)
fmt.Println(errors.Is(err, hide.ErrChallengeReplayed)) // true
```

`context` separates uses of one identity so a signature made for one purpose
cannot be replayed as another; never let a remote party choose it. `Verify`
returns an `error`, never a `bool`. A key file written before signatures
existed carries no signing seed and returns `ErrNotAKey`.

## Identity logs, epoch chains, transparency proofs

| Function | Returns |
| --- | --- |
| `VerifyIdentity(log, recoveryKey)` | `(int, error)` — how many devices the log trusts now |
| `IdentityTrustsDevice(log, recoveryKey, devicePublicKey)` | `(bool, error)` — membership, after verifying the log |
| `IdentityHead(log, recoveryKey)` | `([]byte, error)` — 32 bytes naming this exact history |
| `VerifyEpochChain(chain)` | `(int, error)` — how many epochs it holds |
| `EpochPublicKey(chain, epoch uint64)` | `([]byte, error)` — the key to encrypt to for `epoch` |
| `VerifyInclusion(leaf, index, size, path, root)` | `error` |
| `VerifyConsistency(oldSize, newSize, path, oldRoot, newRoot)` | `error` |

A cryptographic verify returns a non-nil `error` on failure (`ErrMalformed` if
the bytes did not decode, `ErrAuthentication` if they decoded but did not
verify) and never a bare `false`. The one boolean is `IdentityTrustsDevice`,
and it is paired with an error: the log is verified first, so `false, nil`
means "not a member", never "did not verify".

## Native library

Unlike the dynamic SDKs there is no runtime lookup and no `HIDE_LIBRARY`
override: `libhide_ffi.a` is linked into your binary at build time from
`sdk/go/lib/`, so the core cannot be swapped after compilation. Linux links
`-lm -ldl -lpthread`, macOS `-framework Security`, Windows `-lbcrypt
-ladvapi32 -luserenv -lntdll -lws2_32`.

## Key material

`*SecretKey` and `*SigningIdentity` are opaque handles. The seed bytes stay in
the native library and this package exposes no accessor for them; `String()`
shows only whether the handle is open. Call `Close()` when finished (`defer`
is the idiom); a finalizer is registered as a backstop, but relying on it keeps
key material in memory for an unbounded time. A closed handle returns
`ErrClosed`.

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
