package hide

import (
	"bytes"
	"errors"
	"testing"
)

const testPassphrase = "correct horse battery"

func newIdentity(t *testing.T) *SigningIdentity {
	t.Helper()
	sealed, err := GenerateIdentity(testPassphrase)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	identity, err := LoadSigningIdentity(sealed, testPassphrase)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	t.Cleanup(identity.Close)
	return identity
}

func TestSignsAndVerifies(t *testing.T) {
	identity := newIdentity(t)

	public, err := identity.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	if len(public) != VerifyingKeyLen {
		t.Fatalf("verifying key is %d bytes, want %d", len(public), VerifyingKeyLen)
	}

	context := []byte("hide.test.v1")
	message := []byte("nume,suma\nAna,9000\n")
	signature, err := identity.Sign(context, message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(signature) != SignatureLen {
		t.Fatalf("signature is %d bytes, want %d", len(signature), SignatureLen)
	}
	if err := Verify(public, context, message, signature); err != nil {
		t.Fatalf("a genuine signature did not verify: %v", err)
	}
}

func TestChangedMessageFailsVerification(t *testing.T) {
	identity := newIdentity(t)
	public, _ := identity.PublicKey()
	context := []byte("hide.test.v1")

	signature, err := identity.Sign(context, []byte("transfer 10"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(public, context, []byte("transfer 90"), signature); err == nil {
		t.Fatal("a changed message verified")
	}
}

func TestDifferentContextFailsVerification(t *testing.T) {
	identity := newIdentity(t)
	public, _ := identity.PublicKey()
	message := []byte("the same bytes")

	signature, err := identity.Sign([]byte("hide.login.v1"), message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(public, []byte("hide.payment.v1"), message, signature); err == nil {
		t.Fatal("a signature verified under a different context")
	}
}

func TestAnotherIdentityCannotBeImpersonated(t *testing.T) {
	alice := newIdentity(t)
	bob := newIdentity(t)

	bobPublic, _ := bob.PublicKey()
	context := []byte("hide.test.v1")
	message := []byte("this is bob")

	signature, err := alice.Sign(context, message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(bobPublic, context, message, signature); err == nil {
		t.Fatal("alice's signature verified as bob")
	}
}

func TestEncryptionOnlyKeyCannotSign(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer key.Close()

	sealed, err := key.Protect(testPassphrase)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if _, err := LoadSigningIdentity(sealed, testPassphrase); !errors.Is(err, ErrNotAKey) {
		t.Fatalf("an encryption-only key was loaded for signing: %v", err)
	}
}

func TestChallengeIsAcceptedOnceThenReplayed(t *testing.T) {
	identity := newIdentity(t)
	public, _ := identity.PublicKey()

	const now = 1_700_000_000
	challenge, err := NewChallenge("hide.example", now, 60)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	answer, err := identity.Answer(challenge)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}

	spent, err := NewSpentNonces()
	if err != nil {
		t.Fatalf("spent nonces: %v", err)
	}
	defer spent.Close()

	if err := spent.Accept(challenge, answer, public, now+1); err != nil {
		t.Fatalf("a fresh answer was rejected: %v", err)
	}
	if err := spent.Accept(challenge, answer, public, now+1); !errors.Is(err, ErrChallengeReplayed) {
		t.Fatalf("expected ErrChallengeReplayed, got %v", err)
	}
}

func TestAnswerAfterTheWindowIsExpired(t *testing.T) {
	identity := newIdentity(t)
	public, _ := identity.PublicKey()

	const now = 1_700_000_000
	challenge, err := NewChallenge("hide.example", now, 60)
	if err != nil {
		t.Fatalf("challenge: %v", err)
	}
	answer, err := identity.Answer(challenge)
	if err != nil {
		t.Fatalf("answer: %v", err)
	}

	spent, err := NewSpentNonces()
	if err != nil {
		t.Fatalf("spent nonces: %v", err)
	}
	defer spent.Close()

	if err := spent.Accept(challenge, answer, public, now+61); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected ErrChallengeExpired, got %v", err)
	}
}

func TestClosedIdentityIsUnusableAndNeverPrintsKeyMaterial(t *testing.T) {
	sealed, _ := GenerateIdentity(testPassphrase)
	identity, err := LoadSigningIdentity(sealed, testPassphrase)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if bytes.Contains([]byte(identity.String()), []byte("=")) {
		t.Fatal("the String form looks like it contains encoded material")
	}

	identity.Close()
	identity.Close() // idempotent

	if _, err := identity.PublicKey(); !errors.Is(err, ErrClosed) {
		t.Fatalf("a closed identity was usable: %v", err)
	}
	if _, err := identity.Sign([]byte("ctx"), []byte("msg")); !errors.Is(err, ErrClosed) {
		t.Fatalf("a closed identity signed: %v", err)
	}
}

func TestShortPassphraseIsRefusedForIdentities(t *testing.T) {
	if _, err := GenerateIdentity("short"); err == nil {
		t.Fatal("a short passphrase was accepted")
	}
}
