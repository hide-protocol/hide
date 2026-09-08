// Package hide is the Go binding to HIDE: encrypt to a person, not to a key.
//
// EXPERIMENTAL AND UNAUDITED. HIDE is hybrid post-quantum (X25519 + ML-KEM-768
// for encryption, Ed25519 + ML-DSA-65 for signatures). Do not protect data you
// cannot afford to lose or expose. See the security policy at
// https://github.com/hide-protocol/hide/blob/main/SECURITY.md.
//
// This package contains no cryptography. It statically links the same C core
// (crates/hide-ffi) that the CLI and every other HIDE SDK use, so there is one
// implementation rather than one per language. The archive is not committed:
// build it with `cargo build --release -p hide-ffi` and copy
// crates/hide-ffi/include/hide.h into include/ and libhide_ffi.a into lib/.
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
// published by the identity, epoch and transparency subsystems. Every
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
