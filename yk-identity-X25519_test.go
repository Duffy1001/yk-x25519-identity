package identity

import (
	"bytes"
	"crypto/ecdh"
	"io"
	"log"
	"math/rand"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/go-piv/piv-go/v2/piv"
)

func prepareYubiKey(t *testing.T) (*piv.X25519PrivateKey, age.Recipient) {
	t.Helper()

	cards, err := piv.Cards()
	if err != nil || len(cards) == 0 {
		t.Skip("no YubiKey present – skipping integration test")
	}
	yk, err := piv.Open(cards[0])
	if err != nil {
		t.Fatalf("piv.Open: %v", err)
	}

	pub, err := yk.GenerateKey(piv.DefaultManagementKey, piv.SlotAuthentication,
		piv.Key{Algorithm: piv.AlgorithmX25519, PINPolicy: piv.PINPolicyNever, TouchPolicy: piv.TouchPolicyNever})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	privAny, err := yk.PrivateKey(piv.SlotAuthentication, pub,
		piv.KeyAuth{PIN: piv.DefaultPIN, PINPolicy: piv.PINPolicyNever})
	if err != nil {
		t.Fatalf("PrivateKey: %v", err)
	}
	priv := privAny.(*piv.X25519PrivateKey)

	recip, _ := RecipientFromPublicKey(priv.Public().(*ecdh.PublicKey))
	return priv, recip
}

func encryptForRecipients(recips []age.Recipient, pt []byte) []byte {
	var buf bytes.Buffer
	w, _ := age.Encrypt(&buf, recips...)
	n, err := w.Write(pt)
	if err != nil {
		log.Println(n, err)
	}
	w.Close()
	return buf.Bytes()
}

func TestYubiKeyMultiStanza(t *testing.T) {
	priv, recipYK := prepareYubiKey(t)

	idA, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	idB, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	recips := []age.Recipient{idA.Recipient(), idB.Recipient(), recipYK}

	// shuffle stanza order
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(recips), func(i, j int) { recips[i], recips[j] = recips[j], recips[i] })
	plain := []byte("hello from yubikey\n")
	cipher := encryptForRecipients(recips, plain)

	identity := &YkX25519Identity{
		Priv:    priv,
		KeyAuth: piv.KeyAuth{PIN: piv.DefaultPIN, PINPolicy: piv.PINPolicyNever},
	}

	r, err := age.Decrypt(bytes.NewReader(cipher), identity)
	if err != nil {
		t.Fatalf("Decrypt header: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("payload mismatch: got %q want %q", out, plain)
	}
}
