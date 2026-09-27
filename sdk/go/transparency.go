package hide

/*
#include <stdlib.h>
#include "hide.h"
*/
import "C"

import (
	"runtime"
	"strings"
	"unsafe"
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

// VerifyIdentityPinned verifies a log as a relying party: its root must equal
// pinnedRoot, the 32-byte identity root trusted out of band, and
// recoveryBinding establishes the recovery key, so a Recover appended under a
// stranger's key does not verify.
//
// Errors follow VerifyIdentity: ErrMalformed for bytes that do not decode,
// ErrAuthentication for a log that is not this identity's.
func VerifyIdentityPinned(log, recoveryBinding, pinnedRoot []byte) (int, error) {
	var devices C.size_t
	code := C.hide_identity_verify_pinned(
		bytePointer(log), C.size_t(len(log)),
		bytePointer(recoveryBinding), C.size_t(len(recoveryBinding)),
		bytePointer(pinnedRoot), C.size_t(len(pinnedRoot)),
		&devices,
	)
	runtime.KeepAlive(log)
	runtime.KeepAlive(recoveryBinding)
	runtime.KeepAlive(pinnedRoot)
	if err := status(code); err != nil {
		return 0, err
	}
	return int(devices), nil
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

// VerifyEpochChainBound verifies an epoch chain AND that it belongs to the
// pinned identity: epochBinding must be signed, over this chain, by a device
// the log trusts now. It reports how many epochs the chain holds.
//
// A chain that verifies on its own proves only that it is self-consistent;
// anyone can publish one. This is the check that says whose it is.
func VerifyEpochChainBound(log, recoveryBinding, pinnedRoot, chain, epochBinding []byte) (int, error) {
	var epochs C.size_t
	code := C.hide_epoch_verify_bound(
		bytePointer(log), C.size_t(len(log)),
		bytePointer(recoveryBinding), C.size_t(len(recoveryBinding)),
		bytePointer(pinnedRoot), C.size_t(len(pinnedRoot)),
		bytePointer(chain), C.size_t(len(chain)),
		bytePointer(epochBinding), C.size_t(len(epochBinding)),
		&epochs,
	)
	runtime.KeepAlive(log)
	runtime.KeepAlive(recoveryBinding)
	runtime.KeepAlive(pinnedRoot)
	runtime.KeepAlive(chain)
	runtime.KeepAlive(epochBinding)
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

// VerifyCheckpoint verifies a C2SP signed checkpoint note from the log named
// origin, signed with HIDE-Sign under logPublicKey, and returns the tree size
// and the 32-byte root it commits to.
//
// A note signed by any other key — a witness, say — or naming another origin
// returns ErrAuthentication; nothing is returned from a note that did not
// verify.
func VerifyCheckpoint(note []byte, origin string, logPublicKey []byte) (uint64, []byte, error) {
	// C.CString would silently truncate at an embedded NUL and check a
	// different origin from the one the caller named.
	if strings.IndexByte(origin, 0) >= 0 {
		return 0, nil, ErrInvalidArgument
	}
	cOrigin := C.CString(origin)
	defer C.free(unsafe.Pointer(cOrigin))
	var size C.uint64_t
	var root C.HideBuffer = C.hide_buffer_empty()
	code := C.hide_checkpoint_verify(
		bytePointer(note), C.size_t(len(note)),
		cOrigin,
		bytePointer(logPublicKey), C.size_t(len(logPublicKey)),
		&size, &root,
	)
	runtime.KeepAlive(note)
	runtime.KeepAlive(logPublicKey)
	if err := status(code); err != nil {
		return 0, nil, err
	}
	return uint64(size), take(&root), nil
}
