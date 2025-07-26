package identity

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"github.com/btcsuite/btcutil/bech32"
	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func RecipientFromPublicKey(pub *ecdh.PublicKey) (age.Recipient, error) {
	rawPub := pub.Bytes()
	data5, err := bech32.ConvertBits(rawPub, 8, 5, true)
	if err != nil {
		return nil, err
	}
	bech, err := bech32.Encode("age", data5)
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Recipient(bech)
}

type YkX25519Identity struct {
	Priv    *piv.X25519PrivateKey // handle returned by piv.PrivateKey(...)
	KeyAuth piv.KeyAuth           // PIN / touch policy if required
}

func (id *YkX25519Identity) Unwrap(stzs []*age.Stanza) ([]byte, error) {
	for _, st := range stzs {
		if st.Type != "X25519" || len(st.Args) != 1 {
			continue
		}
		// 1. decode the sender’s ephemeral pubkey
		epkBytes, err := base64.RawStdEncoding.DecodeString(st.Args[0])
		if err != nil {
			continue
		}
		epk, err := ecdh.X25519().NewPublicKey(epkBytes)
		if err != nil {
			continue
		}

		// 2. perform ECDH on the YubiKey
		shared, err := id.Priv.ECDH(epk)
		if err != nil {
			fmt.Println("ECDH error:", err) // <- add this
			continue                        // try next stanza
		}

		// 3. derive 32-byte wrapping key
		recipientPub := id.Priv.Public().(*ecdh.PublicKey).Bytes()
		wrapKey, err := deriveWrapKey(shared, epkBytes, recipientPub)
		if err != nil {
			fmt.Println("derive wrap error:", err) // <- and this
			return nil, err
		}

		// 4. unwrap the 16-byte file-key
		fileKey, err := unwrapFileKey(wrapKey, st.Body)
		if err == nil {
			fmt.Println("unwrap OK, file-key:", hex.EncodeToString(fileKey))
			return fileKey, nil // ✅ success
		}
	}
	return nil, age.ErrIncorrectIdentity
}

func deriveWrapKey(shared, epk, recipientPub []byte) ([]byte, error) {
	salt := append(epk, recipientPub...) // epk || pkR
	h := hkdf.New(sha256.New, shared, salt,
		[]byte("age-encryption.org/v1/X25519")) // info
	wrapKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrapKey); err != nil {
		return nil, err
	}
	return wrapKey, nil
}

func unwrapFileKey(wrapKey, body []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSize) // all-zero
	fileKey, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, errors.New("age: unwrap failed")
	}
	if len(fileKey) != 16 {
		return nil, errors.New("age: invalid file-key length")
	}
	return fileKey, nil
}
