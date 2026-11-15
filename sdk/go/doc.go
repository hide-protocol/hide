// Package hide is the Go binding to HIDE: encrypt to a person, not to a key.
//
// EXPERIMENTAL AND UNAUDITED. HIDE is hybrid post-quantum (X25519 + ML-KEM-768
// for encryption, Ed25519 + ML-DSA-65 for signatures). Do not protect data you
// cannot afford to lose or expose. See the security policy at
// https://github.com/hide-protocol/hide/blob/main/SECURITY.md.
//
// This package contains no cryptography. It statically links the same C core
// (crates/hide-ffi) that the CLI and every other HIDE SDK use, so there is one
// implementation rather than one per language.
//
// # Building
//
// `go get` alone does NOT produce a package that compiles. The C header and
// the static archive are build outputs of the Rust core and are not committed,
// so clone the repository and build the core first:
//
//	git clone https://github.com/hide-protocol/hide && cd hide
//	cargo build --release -p hide-ffi
//	mkdir -p sdk/go/include sdk/go/lib
//	cp crates/hide-ffi/include/hide.h sdk/go/include/
//	cp target/release/libhide_ffi.a sdk/go/lib/
//
// On Windows the archive must be built for the GNU ABI (add
// `--target x86_64-pc-windows-gnu` and copy from
// target/x86_64-pc-windows-gnu/release/), because MinGW gcc cannot link an
// MSVC-built static library. Then use a `replace` directive pointing at
// sdk/go in that checkout. CGO_ENABLED=1 and a C toolchain are required. The
// package refuses to start if the linked core is not exactly BindingVersion.
//
// # Text arguments and concurrency
//
// Passphrases, file names, media types, audiences, armored keys and origins
// cross the C boundary NUL-terminated; a string containing a NUL byte returns
// ErrInvalidArgument rather than being silently cut. SpentNonces is safe for
// concurrent use. SecretKey and SigningIdentity may be used from several
// goroutines, but Close must not race with a call in flight.
//
// # Encrypting and decrypting
//
//	secret, err := hide.GenerateKey()
//	if err != nil {
//		return err
//	}
//	defer secret.Close()
//
//	public, _ := secret.PublicKey()
//	box, err := hide.Encrypt([]byte("hello"), [][]byte{public}, hide.Options{})
//	if err != nil {
//		return err
//	}
//
//	opened, err := hide.Decrypt(box, secret)
//	if err != nil {
//		return err // errors.Is(err, hide.ErrAuthentication) when altered
//	}
//	fmt.Println(string(opened.Data))
//
// Nothing is returned from Decrypt unless the whole payload authenticates.
// The Filename it carries is attacker-controlled: never use it to build an
// output path.
//
// # Signing
//
// One seed backs both encryption and signing. GenerateIdentity returns a
// sealed key file; LoadSigningIdentity opens it; Sign produces a detached
// signature under a caller-chosen context, and Verify returns an error rather
// than a bool so a forgotten check cannot read as a pass. NewChallenge,
// SigningIdentity.Answer and SpentNonces.Accept implement a replay-resistant
// challenge/response.
//
// # Identity logs, epoch chains, transparency proofs
//
// VerifyIdentity, IdentityTrustsDevice, IdentityHead, VerifyEpochChain,
// EpochPublicKey, VerifyInclusion and VerifyConsistency verify the structures
// published by the identity, epoch and transparency subsystems.
// VerifyIdentityPinned, VerifyEpochChainBound and VerifyCheckpoint are the
// relying-party checks: the log is the identity whose root was pinned out of
// band, the epoch chain was signed by a device it trusts, and a checkpoint
// was signed by the named log. Every
// cryptographic check reports failure through its error return; the only
// boolean, IdentityTrustsDevice, is a membership query answered after the log
// has already verified.
//
// # Key material
//
// SecretKey and SigningIdentity are opaque handles. The seed bytes stay in
// the native library and there is deliberately no accessor for them. Close a
// handle when finished; a finalizer is registered as a backstop, but relying
// on it keeps key material in memory for an unbounded time.
package hide
