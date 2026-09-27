package hide

import (
	"bytes"
	"errors"
	"testing"
)

func TestAnIdentityLogReportsTheDevicesItTrusts(t *testing.T) {
	// Four events: create, enrol phone, enrol laptop, revoke laptop.
	devices, err := VerifyIdentity(identityLog, identityRecovery)
	if err != nil {
		t.Fatalf("a genuine log did not verify: %v", err)
	}
	if devices != 2 {
		t.Fatalf("the log trusts %d devices, want 2", devices)
	}
}

func TestARevokedDeviceIsNoLongerTrusted(t *testing.T) {
	phone, err := IdentityTrustsDevice(identityLog, identityRecovery, identityDevicePhone)
	if err != nil {
		t.Fatalf("trusts device: %v", err)
	}
	if !phone {
		t.Fatal("the enrolled phone is not trusted")
	}

	laptop, err := IdentityTrustsDevice(identityLog, identityRecovery, identityDeviceLaptop)
	if err != nil {
		t.Fatalf("trusts device: %v", err)
	}
	if laptop {
		t.Fatal("a revoked laptop is still trusted")
	}
}

func TestATamperedLogIsRefused(t *testing.T) {
	if _, err := VerifyIdentity(identityTampered, identityRecovery); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a tampered log gave %v, want ErrAuthentication", err)
	}
	// Bytes that do not decode at all are a different failure from bytes that
	// decode and do not verify.
	_, err := VerifyIdentity([]byte("not a log"), identityRecovery)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("undecodable bytes gave %v, want ErrMalformed", err)
	}
}

func TestTheHeadNamesThisExactHistory(t *testing.T) {
	head, err := IdentityHead(identityLog, identityRecovery)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if !bytes.Equal(head, identityHead) {
		t.Fatal("the head does not name this history")
	}
	if len(head) != 32 {
		t.Fatalf("the head is %d bytes, want 32", len(head))
	}
}

func TestAnEpochChainVerifiesAndYieldsKeys(t *testing.T) {
	epochs, err := VerifyEpochChain(epochChain)
	if err != nil {
		t.Fatalf("a genuine chain did not verify: %v", err)
	}
	if epochs != 3 {
		t.Fatalf("the chain holds %d epochs, want 3", epochs)
	}

	key, err := EpochPublicKey(epochChain, 1)
	if err != nil {
		t.Fatalf("epoch public key: %v", err)
	}
	if !bytes.Equal(key, epochPublicKey1) {
		t.Fatal("epoch 1 yielded the wrong public key")
	}
}

func TestAnEpochBeyondTheChainIsRefused(t *testing.T) {
	if _, err := EpochPublicKey(epochChain, 3); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("an out-of-range epoch gave %v, want ErrInvalidArgument", err)
	}
}

func TestASplicedEpochChainDoesNotVerify(t *testing.T) {
	if _, err := VerifyEpochChain(epochBroken); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a spliced chain gave %v, want ErrAuthentication", err)
	}
}

func TestAnInclusionProofVerifiesOnlyForItsOwnLeaf(t *testing.T) {
	if err := VerifyInclusion(leaf, 3, 8, inclusionPath, treeRoot); err != nil {
		t.Fatalf("a genuine inclusion proof did not verify: %v", err)
	}
	if err := VerifyInclusion(otherLeaf, 3, 8, inclusionPath, treeRoot); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a foreign leaf gave %v, want ErrAuthentication", err)
	}
}

func TestAPathThatIsNotWholeHashesIsRefused(t *testing.T) {
	truncated := inclusionPath[:len(inclusionPath)-1]
	if err := VerifyInclusion(leaf, 3, 8, truncated, treeRoot); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("a partial hash gave %v, want ErrInvalidArgument", err)
	}
}

func TestAConsistencyProofCatchesARewrittenHistory(t *testing.T) {
	if err := VerifyConsistency(5, 8, consistencyPath, rootAt5, treeRoot); err != nil {
		t.Fatalf("a genuine consistency proof did not verify: %v", err)
	}
	// Same size, one entry silently replaced.
	err := VerifyConsistency(5, 8, consistencyPath, rootAt5, rewrittenRoot)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a rewritten history gave %v, want ErrAuthentication", err)
	}
}

func TestAPinnedIdentityVerifiesAgainstItsRoot(t *testing.T) {
	devices, err := VerifyIdentityPinned(bindingIdentityLog, bindingRecovery, bindingRoot)
	if err != nil {
		t.Fatalf("a genuine pinned log did not verify: %v", err)
	}
	if devices != 2 {
		t.Fatalf("the pinned log trusts %d devices, want 2", devices)
	}
}

func TestAHijackedIdentityIsRefused(t *testing.T) {
	// A Recover appended under a stranger's key, with the genuine binding and
	// with one forged for the stranger.
	for name, binding := range map[string][]byte{
		"genuine binding": bindingRecovery,
		"forged binding":  bindingRecoveryForged,
	} {
		_, err := VerifyIdentityPinned(bindingHijackedLog, binding, bindingRoot)
		if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("a hijacked log with the %s gave %v, want ErrAuthentication", name, err)
		}
	}
}

func TestAnotherRootIsRefused(t *testing.T) {
	_, err := VerifyIdentityPinned(bindingIdentityLog, bindingRecovery, make([]byte, 32))
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a different pinned root gave %v, want ErrAuthentication", err)
	}
}

func TestATruncatedRecoveryBindingIsMalformed(t *testing.T) {
	_, err := VerifyIdentityPinned(bindingIdentityLog, bindingRecovery[:100], bindingRoot)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("a truncated binding gave %v, want ErrMalformed", err)
	}
}

func TestAnEpochChainBoundToThePinnedIdentityVerifies(t *testing.T) {
	epochs, err := VerifyEpochChainBound(
		bindingIdentityLog, bindingRecovery, bindingRoot, epochChain, bindingEpoch)
	if err != nil {
		t.Fatalf("a genuinely bound chain did not verify: %v", err)
	}
	if epochs != 3 {
		t.Fatalf("the bound chain holds %d epochs, want 3", epochs)
	}
}

func TestAnEpochChainSignedByAStrangerIsRefused(t *testing.T) {
	_, err := VerifyEpochChainBound(
		bindingIdentityLog, bindingRecovery, bindingRoot, epochChain, bindingEpochStranger)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("a stranger's binding gave %v, want ErrAuthentication", err)
	}
}

func TestACheckpointYieldsItsSizeAndRoot(t *testing.T) {
	size, root, err := VerifyCheckpoint(checkpoint3, "log.example/hide", checkpointLogKey)
	if err != nil {
		t.Fatalf("a genuine checkpoint did not verify: %v", err)
	}
	if size != 3 {
		t.Fatalf("the checkpoint size is %d, want 3", size)
	}
	if len(root) != 32 {
		t.Fatalf("the checkpoint root is %d bytes, want 32", len(root))
	}
}

func TestACheckpointIsRefusedUnlessEverythingMatches(t *testing.T) {
	cases := []struct {
		name   string
		note   []byte
		origin string
		key    []byte
	}{
		{"a tampered note", checkpointTampered, "log.example/hide", checkpointLogKey},
		{"another origin", checkpoint3, "other.example", checkpointLogKey},
		{"a witness key", checkpoint3, "log.example/hide", checkpointWitnessKey},
	}
	for _, c := range cases {
		if _, _, err := VerifyCheckpoint(c.note, c.origin, c.key); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("%s gave %v, want ErrAuthentication", c.name, err)
		}
	}
	if _, _, err := VerifyCheckpoint(checkpoint3, "log.example/hide\x00", checkpointLogKey); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("an origin with a NUL gave %v, want ErrInvalidArgument", err)
	}
}
