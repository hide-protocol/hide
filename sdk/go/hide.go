// Package hide provides HIDE encryption: encrypt to a person, not to a key.
//
// EXPERIMENTAL AND UNAUDITED. Do not protect data you cannot afford to lose or
// expose. A successful decryption proves the data was not altered; it does not
// prove who created it.
//
// This package binds the same C core the CLI and every other SDK use, so there
// is one implementation of the cryptography rather than one per language.
package hide

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo linux LDFLAGS: -L${SRCDIR}/lib -lhide_ffi -lm -ldl -lpthread
#cgo darwin LDFLAGS: -L${SRCDIR}/lib -lhide_ffi -framework Security
#cgo windows LDFLAGS: -L${SRCDIR}/lib -lhide_ffi -lbcrypt -ladvapi32 -luserenv -lntdll -lws2_32
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

// PublicKeyLen is the exact size of a HIDE public key.
const PublicKeyLen = C.HIDE_PUBLIC_KEY_LEN

// MinPassphraseLen is the shortest passphrase that will be accepted.
const MinPassphraseLen = C.HIDE_MIN_PASSPHRASE_LEN

// Errors callers are expected to handle distinctly.
var (
	ErrAuthentication = errors.New("hide: authentication failed; the data was altered")
	// ErrMalformed wraps ErrAuthentication, so code that only cares that
	// something failed is unaffected, while a caller that must tell corruption
	// from forgery can test for this one specifically.
	ErrMalformed           = fmt.Errorf("%w: the bytes did not decode at all", ErrAuthentication)
	ErrInvalidArgument     = errors.New("hide: an argument was rejected before it reached the core")
	ErrWrongPassphrase     = errors.New("hide: incorrect passphrase, or the key file was modified")
	ErrNoMatchingRecipient = errors.New("hide: no matching recipient for this key")
	ErrNotAKey             = errors.New("hide: not a HIDE key file")
	ErrClosed              = errors.New("hide: this key has been closed")
)

func status(code C.int32_t) error {
	switch code {
	case C.HIDE_OK:
		return nil
	case C.HIDE_ERR_AUTHENTICATION:
		return ErrAuthentication
	case C.HIDE_ERR_MALFORMED:
		return ErrMalformed
	case C.HIDE_ERR_INVALID_ARGUMENT:
		return fmt.Errorf("%w: %s", ErrInvalidArgument, C.GoString(C.hide_error_message(code)))
	case C.HIDE_ERR_WRONG_PASSPHRASE:
		return ErrWrongPassphrase
	case C.HIDE_ERR_NO_MATCHING_RECIPIENT:
		return ErrNoMatchingRecipient
	case C.HIDE_ERR_NOT_A_KEY:
		return ErrNotAKey
	case C.HIDE_ERR_CHALLENGE_EXPIRED:
		return ErrChallengeExpired
	case C.HIDE_ERR_CHALLENGE_REPLAYED:
		return ErrChallengeReplayed
	default:
		return fmt.Errorf("hide: %s", C.GoString(C.hide_error_message(code)))
	}
}

// take copies a native buffer into Go memory and frees the original, so the
// caller never holds a pointer into the C heap.
func take(buffer *C.HideBuffer) []byte {
	defer C.hide_buffer_free(buffer)
	if buffer.data == nil || buffer.len == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(buffer.data), C.int(buffer.len))
}

// Version reports the version of the underlying native library.
func Version() string {
	return C.GoString(C.hide_version())
}

// SecretKey is a secret key. The bytes stay inside the native library and are
// never exposed to Go; there is deliberately no accessor for them.
//
// Close it when finished. A finalizer is registered as a backstop, but relying
// on it keeps key material in memory for an unbounded time.
type SecretKey struct {
	handle *C.HideSecretKey
}

func wrap(handle *C.HideSecretKey) *SecretKey {
	key := &SecretKey{handle: handle}
	runtime.SetFinalizer(key, func(k *SecretKey) { k.Close() })
	return key
}

// GenerateKey creates a new key pair.
func GenerateKey() (*SecretKey, error) {
	var handle *C.HideSecretKey
	var public C.HideBuffer = C.hide_buffer_empty()
	if err := status(C.hide_keypair_generate(&handle, &public)); err != nil {
		return nil, err
	}
	C.hide_buffer_free(&public)
	return wrap(handle), nil
}

// LoadKey reads a key file. Pass an empty passphrase for a raw key; a protected
// key without its passphrase fails rather than guessing.
func LoadKey(data []byte, passphrase string) (*SecretKey, error) {
	var handle *C.HideSecretKey
	var cPassphrase *C.char
	if passphrase != "" {
		cPassphrase = C.CString(passphrase)
		defer C.free(unsafe.Pointer(cPassphrase))
	}
	code := C.hide_secret_key_open(
		bytePointer(data), C.size_t(len(data)), cPassphrase, &handle,
	)
	if err := status(code); err != nil {
		return nil, err
	}
	return wrap(handle), nil
}

// PublicKey derives the shareable public key.
func (k *SecretKey) PublicKey() ([]byte, error) {
	if k.handle == nil {
		return nil, ErrClosed
	}
	var out C.HideBuffer = C.hide_buffer_empty()
	if err := status(C.hide_secret_key_public(k.handle, &out)); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Protect seals this key with a passphrase, for writing to disk.
//
// A forgotten passphrase cannot be recovered: there is no escrow and no reset.
func (k *SecretKey) Protect(passphrase string) ([]byte, error) {
	if k.handle == nil {
		return nil, ErrClosed
	}
	if len(passphrase) < MinPassphraseLen {
		return nil, fmt.Errorf("hide: the passphrase must be at least %d characters", MinPassphraseLen)
	}
	cPassphrase := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cPassphrase))

	var out C.HideBuffer = C.hide_buffer_empty()
	if err := status(C.hide_secret_key_protect(k.handle, cPassphrase, &out)); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Close releases the key and zeroizes its material. It is safe to call twice.
func (k *SecretKey) Close() {
	if k.handle != nil {
		C.hide_secret_key_free(k.handle)
		k.handle = nil
		runtime.SetFinalizer(k, nil)
	}
}

// String never renders key material, not even a fingerprint of it.
func (k *SecretKey) String() string {
	if k.handle == nil {
		return "hide.SecretKey(closed)"
	}
	return "hide.SecretKey"
}

// Decrypted is a verified payload. Receiving it means it authenticated.
type Decrypted struct {
	Data []byte
	// Filename is attacker-controlled: never use it to build an output path.
	Filename  string
	MediaType string
}

// Options carries the optional metadata stored with a container.
type Options struct {
	Filename  string
	MediaType string
}

// bytePointer returns a pointer usable by cgo, tolerating an empty slice.
func bytePointer(data []byte) *C.uint8_t {
	if len(data) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&data[0]))
}

// Encrypt encrypts for 1..64 recipient public keys.
func Encrypt(plaintext []byte, recipients [][]byte, options Options) ([]byte, error) {
	if len(recipients) < 1 || len(recipients) > 64 {
		return nil, errors.New("hide: there must be between 1 and 64 recipients")
	}
	joined := make([]byte, 0, len(recipients)*PublicKeyLen)
	for _, key := range recipients {
		if len(key) != PublicKeyLen {
			return nil, fmt.Errorf("hide: a public key is %d bytes, got %d", PublicKeyLen, len(key))
		}
		joined = append(joined, key...)
	}

	var filename, mediaType *C.char
	if options.Filename != "" {
		filename = C.CString(options.Filename)
		defer C.free(unsafe.Pointer(filename))
	}
	if options.MediaType != "" {
		mediaType = C.CString(options.MediaType)
		defer C.free(unsafe.Pointer(mediaType))
	}

	var out C.HideBuffer = C.hide_buffer_empty()
	code := C.hide_encrypt(
		bytePointer(plaintext), C.size_t(len(plaintext)),
		bytePointer(joined), C.size_t(len(recipients)),
		filename, mediaType, &out,
	)
	// Keep the Go slices alive until cgo has finished reading them.
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(joined)
	if err := status(code); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Decrypt decrypts and verifies. Nothing is returned unless the entire payload
// authenticates, so a caller cannot act on unverified data.
func Decrypt(container []byte, key *SecretKey) (*Decrypted, error) {
	if key.handle == nil {
		return nil, ErrClosed
	}
	var out, filename, mediaType C.HideBuffer
	out = C.hide_buffer_empty()
	filename = C.hide_buffer_empty()
	mediaType = C.hide_buffer_empty()

	code := C.hide_decrypt(
		bytePointer(container), C.size_t(len(container)),
		key.handle, &out, &filename, &mediaType,
	)
	runtime.KeepAlive(container)
	if err := status(code); err != nil {
		return nil, err
	}
	return &Decrypted{
		Data:      take(&out),
		Filename:  string(take(&filename)),
		MediaType: string(take(&mediaType)),
	}, nil
}

// ArmorPublicKey renders a public key as pasteable text.
func ArmorPublicKey(publicKey []byte) (string, error) {
	var out C.HideBuffer = C.hide_buffer_empty()
	code := C.hide_public_key_armor(bytePointer(publicKey), C.size_t(len(publicKey)), &out)
	runtime.KeepAlive(publicKey)
	if err := status(code); err != nil {
		return "", err
	}
	return string(take(&out)), nil
}

// DearmorPublicKey parses armored public-key text back into bytes.
func DearmorPublicKey(text string) ([]byte, error) {
	cText := C.CString(text)
	defer C.free(unsafe.Pointer(cText))

	var out C.HideBuffer = C.hide_buffer_empty()
	if err := status(C.hide_public_key_dearmor(cText, &out)); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// InspectKey reports "raw" or "protected" without needing the passphrase.
func InspectKey(data []byte) (string, error) {
	var kind C.int32_t
	code := C.hide_inspect_key(bytePointer(data), C.size_t(len(data)), &kind)
	runtime.KeepAlive(data)
	if err := status(code); err != nil {
		return "", err
	}
	if kind == C.HIDE_KEY_PROTECTED {
		return "protected", nil
	}
	return "raw", nil
}
