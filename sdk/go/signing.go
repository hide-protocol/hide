package hide

/*
#include <stdlib.h>
#include "hide.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Sizes of the signing material, fixed by the protocol.
const (
	SignatureLen    = C.HIDE_SIGNATURE_LEN
	VerifyingKeyLen = C.HIDE_VERIFYING_KEY_LEN
	NonceLen        = C.HIDE_NONCE_LEN
)

// Errors specific to challenges.
var (
	ErrChallengeExpired  = errors.New("hide: this challenge is no longer valid")
	ErrChallengeReplayed = errors.New("hide: this challenge has already been answered")
)

// SigningIdentity is a signing key. The seed stays inside the native library
// and is never exposed to Go; there is deliberately no accessor for it.
//
// Close it when finished. A finalizer is registered as a backstop, but relying
// on it keeps key material in memory for an unbounded time.
type SigningIdentity struct {
	handle *C.HideSigningIdentity
}

func wrapIdentity(handle *C.HideSigningIdentity) *SigningIdentity {
	identity := &SigningIdentity{handle: handle}
	runtime.SetFinalizer(identity, func(i *SigningIdentity) { i.Close() })
	return identity
}

// GenerateIdentity creates an identity and returns the sealed key file to store.
//
// One seed backs both encryption and signing, so there is a single thing to
// back up. A forgotten passphrase cannot be recovered.
func GenerateIdentity(passphrase string) ([]byte, error) {
	if len(passphrase) < MinPassphraseLen {
		return nil, fmt.Errorf("hide: the passphrase must be at least %d characters", MinPassphraseLen)
	}
	cPassphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPassphrase))

	var out C.HideBuffer = C.hide_buffer_empty()
	if err := status(C.hide_identity_generate(cPassphrase, &out)); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// LoadSigningIdentity reads a key file. Pass an empty passphrase for a raw key.
//
// A key file written before signatures existed carries no signing seed and
// fails with ErrNotAKey rather than being silently downgraded.
func LoadSigningIdentity(data []byte, passphrase string) (*SigningIdentity, error) {
	var cPassphrase *C.char
	if passphrase != "" {
		cPassphrase = C.CString(passphrase)
		defer C.free(unsafe.Pointer(cPassphrase))
	}
	var handle *C.HideSigningIdentity
	code := C.hide_signing_identity_open(
		bytePointer(data), C.size_t(len(data)), cPassphrase, &handle,
	)
	runtime.KeepAlive(data)
	if err := status(code); err != nil {
		return nil, err
	}
	return wrapIdentity(handle), nil
}

// PublicKey returns the shareable verifying key, for others to check
// signatures with.
func (i *SigningIdentity) PublicKey() ([]byte, error) {
	if i.handle == nil {
		return nil, ErrClosed
	}
	var out C.HideBuffer = C.hide_buffer_empty()
	if err := status(C.hide_signing_identity_public(i.handle, &out)); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Sign signs message under context.
//
// context separates uses of one identity, so a signature made for one purpose
// cannot be replayed as another. Never let a remote party choose it.
func (i *SigningIdentity) Sign(context, message []byte) ([]byte, error) {
	if i.handle == nil {
		return nil, ErrClosed
	}
	var out C.HideBuffer = C.hide_buffer_empty()
	code := C.hide_sign_message(
		i.handle,
		bytePointer(context), C.size_t(len(context)),
		bytePointer(message), C.size_t(len(message)),
		&out,
	)
	runtime.KeepAlive(context)
	runtime.KeepAlive(message)
	if err := status(code); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Answer answers a challenge, proving possession to whoever issued it.
func (i *SigningIdentity) Answer(challenge []byte) ([]byte, error) {
	if i.handle == nil {
		return nil, ErrClosed
	}
	var out C.HideBuffer = C.hide_buffer_empty()
	code := C.hide_challenge_answer(
		i.handle, bytePointer(challenge), C.size_t(len(challenge)), &out,
	)
	runtime.KeepAlive(challenge)
	if err := status(code); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Close releases the identity and zeroizes its material. Safe to call twice.
func (i *SigningIdentity) Close() {
	if i.handle != nil {
		C.hide_signing_identity_free(i.handle)
		i.handle = nil
		runtime.SetFinalizer(i, nil)
	}
}

// String never renders key material, not even a fingerprint of it.
func (i *SigningIdentity) String() string {
	if i.handle == nil {
		return "hide.SigningIdentity(closed)"
	}
	return "hide.SigningIdentity"
}

// Verify reports whether a signature is genuine. It returns nil only if both
// the Ed25519 and ML-DSA halves verify.
//
// An error is returned rather than a bool: a caller who forgets to check a
// bool would treat every failure as a pass.
func Verify(publicKey, context, message, signature []byte) error {
	code := C.hide_verify_message(
		bytePointer(publicKey), C.size_t(len(publicKey)),
		bytePointer(context), C.size_t(len(context)),
		bytePointer(message), C.size_t(len(message)),
		bytePointer(signature), C.size_t(len(signature)),
	)
	runtime.KeepAlive(publicKey)
	runtime.KeepAlive(context)
	runtime.KeepAlive(message)
	runtime.KeepAlive(signature)
	return status(code)
}

// NewChallenge creates a challenge for a prover to answer, valid for validFor
// seconds from now.
//
// A detached signature proves possession at some point, to nobody in
// particular, and can be replayed. A challenge binds a random nonce, an
// audience and an expiry, so an answer is good once, here, now.
func NewChallenge(audience string, now, validFor uint64) ([]byte, error) {
	cAudience := C.CString(audience)
	defer C.free(unsafe.Pointer(cAudience))

	var out C.HideBuffer = C.hide_buffer_empty()
	code := C.hide_challenge_new(cAudience, C.uint64_t(now), C.uint64_t(validFor), &out)
	if err := status(code); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// SpentNonces is the verifier's record of answered challenges.
//
// Replay can only be detected by the verifier: a replayed answer is a genuine
// signature and nothing about it is invalid on its own. This must therefore
// outlive a single request.
type SpentNonces struct {
	handle *C.HideSpentNonces
}

// NewSpentNonces allocates an empty record.
func NewSpentNonces() (*SpentNonces, error) {
	handle := C.hide_spent_nonces_new()
	if handle == nil {
		return nil, errors.New("hide: could not allocate the nonce record")
	}
	record := &SpentNonces{handle: handle}
	runtime.SetFinalizer(record, func(s *SpentNonces) { s.Close() })
	return record, nil
}

// Accept accepts an answer exactly once.
//
// It returns ErrChallengeReplayed the second time, ErrChallengeExpired after
// the window, and ErrAuthentication if the answer does not verify.
func (s *SpentNonces) Accept(challenge, signature, publicKey []byte, now uint64) error {
	if s.handle == nil {
		return ErrClosed
	}
	code := C.hide_challenge_accept(
		s.handle,
		bytePointer(challenge), C.size_t(len(challenge)),
		bytePointer(signature), C.size_t(len(signature)),
		bytePointer(publicKey), C.size_t(len(publicKey)),
		C.uint64_t(now),
	)
	runtime.KeepAlive(challenge)
	runtime.KeepAlive(signature)
	runtime.KeepAlive(publicKey)
	return status(code)
}

// Close releases the record. Safe to call twice.
func (s *SpentNonces) Close() {
	if s.handle != nil {
		C.hide_spent_nonces_free(s.handle)
		s.handle = nil
		runtime.SetFinalizer(s, nil)
	}
}
