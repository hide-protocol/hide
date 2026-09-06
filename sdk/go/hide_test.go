package hide

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRoundTripCarriesMetadata(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer key.Close()

	public, err := key.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	if len(public) != PublicKeyLen {
		t.Fatalf("public key is %d bytes, want %d", len(public), PublicKeyLen)
	}

	message := []byte("nume,suma\nAna,9000\n")
	box, err := Encrypt(message, [][]byte{public}, Options{
		Filename:  "salarii.csv",
		MediaType: "text/csv",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(box, []byte("Ana")) {
		t.Fatal("plaintext leaked into the container")
	}

	opened, err := Decrypt(box, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(opened.Data, message) {
		t.Fatal("payload did not round trip")
	}
	if opened.Filename != "salarii.csv" || opened.MediaType != "text/csv" {
		t.Fatalf("metadata lost: %q %q", opened.Filename, opened.MediaType)
	}
}

func TestSingleByteMutationsAreRejected(t *testing.T) {
	key, _ := GenerateKey()
	defer key.Close()
	public, _ := key.PublicKey()
	box, err := Encrypt([]byte("confidential"), [][]byte{public}, Options{})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	for _, offset := range []int{0, 8, 15, 40, len(box) / 2, len(box) - 1} {
		damaged := append([]byte(nil), box...)
		damaged[offset] ^= 0x40
		if _, err := Decrypt(damaged, key); err == nil {
			t.Fatalf("a mutation at offset %d was accepted", offset)
		}
	}
}

func TestTruncationAndExtensionFail(t *testing.T) {
	key, _ := GenerateKey()
	defer key.Close()
	public, _ := key.PublicKey()
	box, _ := Encrypt([]byte("payload"), [][]byte{public}, Options{})

	if _, err := Decrypt(box[:len(box)-1], key); err == nil {
		t.Fatal("truncation was accepted")
	}
	if _, err := Decrypt(append(box, 0), key); err == nil {
		t.Fatal("trailing data was accepted")
	}
}

func TestWrongKeyCannotDecrypt(t *testing.T) {
	alice, _ := GenerateKey()
	bob, _ := GenerateKey()
	defer alice.Close()
	defer bob.Close()

	public, _ := alice.PublicKey()
	box, _ := Encrypt([]byte("for alice"), [][]byte{public}, Options{})

	if _, err := Decrypt(box, bob); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Fatalf("expected ErrNoMatchingRecipient, got %v", err)
	}
}

func TestManyRecipientsShareOnePayload(t *testing.T) {
	keys := make([]*SecretKey, 3)
	publics := make([][]byte, 3)
	for i := range keys {
		keys[i], _ = GenerateKey()
		defer keys[i].Close()
		publics[i], _ = keys[i].PublicKey()
	}

	box, err := Encrypt([]byte("shared"), publics, Options{})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	for i, key := range keys {
		opened, err := Decrypt(box, key)
		if err != nil {
			t.Fatalf("recipient %d could not decrypt: %v", i, err)
		}
		if string(opened.Data) != "shared" {
			t.Fatalf("recipient %d got the wrong payload", i)
		}
	}
}

func TestProtectedKeysRoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	public, _ := key.PublicKey()
	sealed, err := key.Protect("correct horse battery")
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	key.Close()

	kind, err := InspectKey(sealed)
	if err != nil || kind != "protected" {
		t.Fatalf("inspect: %q %v", kind, err)
	}

	if _, err := LoadKey(sealed, "wrong passphrase"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("a wrong passphrase was accepted: %v", err)
	}
	if _, err := LoadKey(sealed, ""); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("a protected key opened without a passphrase: %v", err)
	}

	reopened, err := LoadKey(sealed, "correct horse battery")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	derived, _ := reopened.PublicKey()
	if !bytes.Equal(derived, public) {
		t.Fatal("the reopened key is a different key")
	}
}

func TestShortPassphraseIsRefused(t *testing.T) {
	key, _ := GenerateKey()
	defer key.Close()
	if _, err := key.Protect("short"); err == nil {
		t.Fatal("a short passphrase was accepted")
	}
}

func TestArmorRoundTrips(t *testing.T) {
	key, _ := GenerateKey()
	defer key.Close()
	public, _ := key.PublicKey()

	text, err := ArmorPublicKey(public)
	if err != nil {
		t.Fatalf("armor: %v", err)
	}
	if !strings.HasPrefix(text, "hide-public-key:") {
		t.Fatalf("unexpected armor: %.32q", text)
	}
	decoded, err := DearmorPublicKey(text)
	if err != nil || !bytes.Equal(decoded, public) {
		t.Fatalf("dearmor: %v", err)
	}
	if _, err := DearmorPublicKey("not a key"); err == nil {
		t.Fatal("rubbish was accepted as a public key")
	}
}

func TestRecipientCountAndKeyLengthAreBounded(t *testing.T) {
	key, _ := GenerateKey()
	defer key.Close()
	public, _ := key.PublicKey()

	if _, err := Encrypt([]byte("x"), nil, Options{}); err == nil {
		t.Fatal("zero recipients accepted")
	}
	many := make([][]byte, 65)
	for i := range many {
		many[i] = public
	}
	if _, err := Encrypt([]byte("x"), many, Options{}); err == nil {
		t.Fatal("65 recipients accepted")
	}
	if _, err := Encrypt([]byte("x"), [][]byte{[]byte("short")}, Options{}); err == nil {
		t.Fatal("a short public key was accepted")
	}
}

func TestClosedKeyIsUnusableAndNeverPrintsKeyMaterial(t *testing.T) {
	key, _ := GenerateKey()
	if strings.Contains(key.String(), "=") {
		t.Fatal("the String form looks like it contains encoded material")
	}

	key.Close()
	key.Close() // idempotent

	if _, err := key.PublicKey(); !errors.Is(err, ErrClosed) {
		t.Fatalf("a closed key was usable: %v", err)
	}
}

func TestEmptyPayloadsAreValid(t *testing.T) {
	key, _ := GenerateKey()
	defer key.Close()
	public, _ := key.PublicKey()

	box, err := Encrypt(nil, [][]byte{public}, Options{})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	opened, err := Decrypt(box, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(opened.Data) != 0 {
		t.Fatal("an empty payload came back non-empty")
	}
}

func TestGarbageIsRejectedNotCrashed(t *testing.T) {
	key, _ := GenerateKey()
	defer key.Close()
	if _, err := Decrypt([]byte("this is not a HIDE container"), key); err == nil {
		t.Fatal("garbage was accepted")
	}
}
