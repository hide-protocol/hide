package hide

import (
	"bytes"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

// The core reads every `const char *` up to the first NUL. A binding that
// passes a Go string straight through therefore seals a key under
// "longenough" when the caller typed "longenough\x00rest".
func TestEmbeddedNulIsRefusedInEveryCString(t *testing.T) {
	const cut = "longenough"
	const withNul = cut + "\x00rest"

	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer key.Close()
	public, _ := key.PublicKey()

	sealed, err := key.Protect(withNul)
	if err == nil {
		// Say what actually happened, which is worse than "accepted".
		if reopened, openErr := LoadKey(sealed, cut); openErr == nil {
			reopened.Close()
			t.Fatalf("Protect(%q) sealed the key under the truncated passphrase %q", withNul, cut)
		}
		t.Fatalf("Protect accepted a passphrase containing a NUL")
	}
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Protect with a NUL gave %v, want ErrInvalidArgument", err)
	}

	good, err := key.Protect(cut)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	identityFile, err := GenerateIdentity(cut)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	armored, err := ArmorPublicKey(public)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}

	cases := []struct {
		name string
		call func() error
	}{
		{"LoadKey passphrase", func() error {
			opened, err := LoadKey(good, withNul)
			if err == nil {
				opened.Close()
			}
			return err
		}},
		{"GenerateIdentity passphrase", func() error {
			_, err := GenerateIdentity(withNul)
			return err
		}},
		{"LoadSigningIdentity passphrase", func() error {
			opened, err := LoadSigningIdentity(identityFile, withNul)
			if err == nil {
				opened.Close()
			}
			return err
		}},
		{"Encrypt filename", func() error {
			_, err := Encrypt([]byte("x"), [][]byte{public}, Options{Filename: "safe.txt\x00evil"})
			return err
		}},
		{"Encrypt media type", func() error {
			_, err := Encrypt([]byte("x"), [][]byte{public}, Options{MediaType: "text/pl\x00ain"})
			return err
		}},
		{"NewChallenge audience", func() error {
			_, err := NewChallenge("app.example\x00.evil.example", 1_700_000_000, 60)
			return err
		}},
		{"DearmorPublicKey text", func() error {
			_, err := DearmorPublicKey(armored + "\x00trailing")
			return err
		}},
		{"VerifyCheckpoint origin", func() error {
			_, _, err := VerifyCheckpoint(checkpoint3, "log.example/hide\x00", checkpointLogKey)
			return err
		}},
	}
	for _, c := range cases {
		if err := c.call(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: a NUL gave %v, want ErrInvalidArgument", c.name, err)
		}
	}
}

// The native constructor returns NULL only for a NULL or non-UTF-8 audience.
// Go cannot pass a NULL pointer, so a Go string holding invalid UTF-8 is the
// one way to reach it, and the caller must be told it was their argument — the
// same class of error the core reports for that audience to NewChallenge.
func TestANonUTF8AudienceIsReportedAsAnArgument(t *testing.T) {
	invalid := string([]byte{0xff, 0xfe, 'a'})
	if _, err := NewSpentNonces(invalid); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("a non-UTF-8 audience gave %v, want ErrInvalidArgument", err)
	}
}

// A check made in Go must report the same sentinel as one made by the core,
// so errors.Is is the only test a caller needs.
func TestPreChecksReturnSentinelErrors(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer key.Close()
	public, _ := key.PublicKey()

	many := make([][]byte, 65)
	for i := range many {
		many[i] = public
	}
	cases := []struct {
		name string
		call func() error
	}{
		{"zero recipients", func() error {
			_, err := Encrypt([]byte("x"), nil, Options{})
			return err
		}},
		{"65 recipients", func() error {
			_, err := Encrypt([]byte("x"), many, Options{})
			return err
		}},
		{"a short public key", func() error {
			_, err := Encrypt([]byte("x"), [][]byte{[]byte("short")}, Options{})
			return err
		}},
		{"a short passphrase for Protect", func() error {
			_, err := key.Protect("short")
			return err
		}},
		{"a short passphrase for GenerateIdentity", func() error {
			_, err := GenerateIdentity("short")
			return err
		}},
		{"a nil key for Decrypt", func() error {
			_, err := Decrypt([]byte("anything"), nil)
			return err
		}},
	}
	for _, c := range cases {
		if err := c.call(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s gave %v, want ErrInvalidArgument", c.name, err)
		}
	}
}

// Web servers share one record between request handlers. However many of them
// present the same valid answer at once, exactly one may be told it is fresh.
func TestSpentNoncesAcceptsOneAnswerOnceUnderConcurrency(t *testing.T) {
	identity := newIdentity(t)
	public, _ := identity.PublicKey()

	const now = 1_700_000_000
	const workers = 16
	// Without the lock roughly one round in ten goes wrong, so a handful of
	// rounds would pass by luck.
	rounds := 200
	if testing.Short() {
		rounds = 24
	}

	spent, err := NewSpentNonces("hide.example")
	if err != nil {
		t.Fatalf("spent nonces: %v", err)
	}
	defer spent.Close()

	for round := 0; round < rounds; round++ {
		challenge, err := NewChallenge("hide.example", now, 60)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		answer, err := identity.Answer(challenge)
		if err != nil {
			t.Fatalf("answer: %v", err)
		}

		var accepted, replayed, other atomic.Int32
		var start, done sync.WaitGroup
		start.Add(1)
		for worker := 0; worker < workers; worker++ {
			done.Add(1)
			go func() {
				defer done.Done()
				start.Wait()
				switch err := spent.Accept(challenge, answer, public, now+1); {
				case err == nil:
					accepted.Add(1)
				case errors.Is(err, ErrChallengeReplayed):
					replayed.Add(1)
				default:
					other.Add(1)
				}
			}()
		}
		start.Done()
		done.Wait()

		if accepted.Load() != 1 || replayed.Load() != workers-1 || other.Load() != 0 {
			t.Fatalf("round %d: %d accepted, %d replayed, %d other; want 1, %d, 0",
				round, accepted.Load(), replayed.Load(), other.Load(), workers-1)
		}
	}
}

// A handle whose last use is a native call is unreachable for the whole of
// that call unless the binding keeps it alive, and its finalizer frees the key
// the core is still reading. Every round here ends an object's life in a
// native call while another goroutine forces collections; a freed key shows up
// as a crash or as output that no longer belongs to the key.
func TestHandlesStayAliveForTheWholeNativeCall(t *testing.T) {
	stop := make(chan struct{})
	var collector sync.WaitGroup
	collector.Add(1)
	go func() {
		defer collector.Done()
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	defer func() {
		close(stop)
		collector.Wait()
	}()

	const now = 1_700_000_000
	context := []byte("hide.test.v1")
	message := []byte("payload")

	rounds := 12
	if testing.Short() {
		rounds = 3
	}
	for round := 0; round < rounds; round++ {
		// Protect runs Argon2, the longest window there is. Its result must
		// still be this key: sealing a freed key yields some other key.
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		public, err := key.PublicKey()
		if err != nil {
			t.Fatalf("public key: %v", err)
		}
		box, err := Encrypt(message, [][]byte{public}, Options{})
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		sealed, err := key.Protect(testPassphrase) // the last use of key
		if err != nil {
			t.Fatalf("round %d: protect: %v", round, err)
		}

		reopened, err := LoadKey(sealed, testPassphrase)
		if err != nil {
			t.Fatalf("round %d: the sealed key did not reopen: %v", round, err)
		}
		opened, err := Decrypt(box, reopened) // the last use of reopened
		if err != nil {
			t.Fatalf("round %d: the sealed key is not the key that was sealed: %v", round, err)
		}
		if !bytes.Equal(opened.Data, message) {
			t.Fatalf("round %d: the payload did not round trip", round)
		}

		// The same for a signing identity and a nonce record.
		identityFile, err := GenerateIdentity(testPassphrase)
		if err != nil {
			t.Fatalf("generate identity: %v", err)
		}
		signer, err := LoadSigningIdentity(identityFile, testPassphrase)
		if err != nil {
			t.Fatalf("load identity: %v", err)
		}
		verifying, err := signer.PublicKey()
		if err != nil {
			t.Fatalf("verifying key: %v", err)
		}
		challenge, err := NewChallenge("hide.example", now, 60)
		if err != nil {
			t.Fatalf("challenge: %v", err)
		}
		answer, err := signer.Answer(challenge)
		if err != nil {
			t.Fatalf("answer: %v", err)
		}
		signature, err := signer.Sign(context, message) // the last use of signer
		if err != nil {
			t.Fatalf("round %d: sign: %v", round, err)
		}
		if err := Verify(verifying, context, message, signature); err != nil {
			t.Fatalf("round %d: the signature is not this identity's: %v", round, err)
		}

		spent, err := NewSpentNonces("hide.example")
		if err != nil {
			t.Fatalf("spent nonces: %v", err)
		}
		if err := spent.Accept(challenge, answer, verifying, now+1); err != nil { // the last use of spent
			t.Fatalf("round %d: a fresh answer was rejected: %v", round, err)
		}
	}
}
