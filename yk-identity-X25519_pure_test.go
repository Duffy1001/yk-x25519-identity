package identity

import (
	"bytes"
	"crypto/rand"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestWrapUnwrapRoundTrip(t *testing.T) {
	// random but deterministic
	var (
		shared       = make([]byte, 32)
		epk          = make([]byte, 32)
		recipientPub = make([]byte, 32)
		fileKeyWant  = make([]byte, 16)
	)
	rand.Read(shared)
	rand.Read(epk)
	rand.Read(recipientPub)
	rand.Read(fileKeyWant)

	// HKDF → wrapping key
	wrapKey, err := deriveWrapKey(shared, epk, recipientPub)
	if err != nil {
		t.Fatalf("deriveWrapKey: %v", err)
	}

	// encrypt file-key exactly as age does (nonce = 0)
	aead, _ := chacha20poly1305.New(wrapKey)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	body := aead.Seal(nil, nonce, fileKeyWant, nil)

	// now unwrap through helper
	fileKeyGot, err := unwrapFileKey(wrapKey, body)
	if err != nil {
		t.Fatalf("unwrapFileKey: %v", err)
	}
	if !bytes.Equal(fileKeyGot, fileKeyWant) {
		t.Fatalf("file-key mismatch: got %x want %x", fileKeyGot, fileKeyWant)
	}
}

func TestErrIncorrectIdentity(t *testing.T) {
	st := &age.Stanza{Type: "X25518"} // wrong tag, so identity shouldn’t touch it
	id := &YkX25519Identity{Priv: nil}

	if _, err := id.Unwrap([]*age.Stanza{st}); err != age.ErrIncorrectIdentity {
		t.Fatalf("expected ErrIncorrectIdentity, got %v", err)
	}
}
