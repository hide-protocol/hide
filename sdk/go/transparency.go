package hide

/*
#include <stdlib.h>
#include "hide.h"
*/
import "C"

import (
	"runtime"
)

// VerifyIdentity replays an identity log and reports how many devices it
// trusts now.
//
// A log that does not decode returns ErrMalformed; one that decodes and does
// not verify returns ErrAuthentication. That is the distinction that tells
// corruption from forgery. Both satisfy errors.Is(err, ErrAuthentication), so
// a caller that only cares that something failed is unaffected.
//
// A count is returned rather than a bool: a caller who forgets to check a bool
// would treat every failure as a pass.
func VerifyIdentity(log, recoveryKey []byte) (int, error) {
	var devices C.size_t
	code := C.hide_identity_verify(
		bytePointer(log), C.size_t(len(log)),
		bytePointer(recoveryKey), C.size_t(len(recoveryKey)),
		&devices,
	)
	runtime.KeepAlive(log)
	runtime.KeepAlive(recoveryKey)
	if err := status(code); err != nil {
		return 0, err
	}
	return int(devices), nil
}

// IdentityTrustsDevice reports whether the log trusts this device right now.
//
// A bool is right here: this is a membership query, not a cryptographic check.
// The log is still verified first, so false means "not a member", never "did
// not verify" — that arrives as an error.
func IdentityTrustsDevice(log, recoveryKey, devicePublicKey []byte) (bool, error) {
	var trusted C.int32_t
	code := C.hide_identity_trusts_device(
		bytePointer(log), C.size_t(len(log)),
		bytePointer(recoveryKey), C.size_t(len(recoveryKey)),
		bytePointer(devicePublicKey), C.size_t(len(devicePublicKey)),
		&trusted,
	)
	runtime.KeepAlive(log)
	runtime.KeepAlive(recoveryKey)
	runtime.KeepAlive(devicePublicKey)
	if err := status(code); err != nil {
		return false, err
	}
	return trusted != 0, nil
}

// IdentityHead returns the head link: 32 bytes naming this exact history.
func IdentityHead(log, recoveryKey []byte) ([]byte, error) {
	var out C.HideBuffer = C.hide_buffer_empty()
	code := C.hide_identity_head(
		bytePointer(log), C.size_t(len(log)),
		bytePointer(recoveryKey), C.size_t(len(recoveryKey)),
		&out,
	)
	runtime.KeepAlive(log)
	runtime.KeepAlive(recoveryKey)
	if err := status(code); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// VerifyEpochChain verifies a published epoch history and reports how many
// epochs it holds.
func VerifyEpochChain(chain []byte) (int, error) {
	var epochs C.size_t
	code := C.hide_epoch_verify(bytePointer(chain), C.size_t(len(chain)), &epochs)
	runtime.KeepAlive(chain)
	if err := status(code); err != nil {
		return 0, err
	}
	return int(epochs), nil
}

// EpochPublicKey returns the public key a sender should encrypt to for epoch.
//
// The chain is verified first, so a key is never returned from a history that
// does not hold together. An epoch beyond the chain returns
// ErrInvalidArgument.
func EpochPublicKey(chain []byte, epoch uint64) ([]byte, error) {
	var out C.HideBuffer = C.hide_buffer_empty()
	code := C.hide_epoch_public_key(
		bytePointer(chain), C.size_t(len(chain)), C.uint64_t(epoch), &out,
	)
	runtime.KeepAlive(chain)
	if err := status(code); err != nil {
		return nil, err
	}
	return take(&out), nil
}

// VerifyInclusion checks that leaf is entry index of a log of size entries
// under root.
//
// path is the concatenated 32-byte hashes; any other length returns
// ErrInvalidArgument. An error is returned rather than a bool, for the same
// reason Verify returns one.
func VerifyInclusion(leaf []byte, index, size uint64, path, root []byte) error {
	code := C.hide_transparency_verify_inclusion(
		bytePointer(leaf), C.size_t(len(leaf)),
		C.uint64_t(index), C.uint64_t(size),
		bytePointer(path), C.size_t(len(path)),
		bytePointer(root), C.size_t(len(root)),
	)
	runtime.KeepAlive(leaf)
	runtime.KeepAlive(path)
	runtime.KeepAlive(root)
	return status(code)
}

// VerifyConsistency checks that oldRoot really is the root the log had before
// it grew to newRoot. This is the check that catches a rewritten history.
func VerifyConsistency(oldSize, newSize uint64, path, oldRoot, newRoot []byte) error {
	code := C.hide_transparency_verify_consistency(
		C.uint64_t(oldSize), C.uint64_t(newSize),
		bytePointer(path), C.size_t(len(path)),
		bytePointer(oldRoot), C.size_t(len(oldRoot)),
		bytePointer(newRoot), C.size_t(len(newRoot)),
	)
	runtime.KeepAlive(path)
	runtime.KeepAlive(oldRoot)
	runtime.KeepAlive(newRoot)
	return status(code)
}
