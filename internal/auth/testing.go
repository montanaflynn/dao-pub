package auth

import (
	"crypto/ed25519"
	"crypto/rand"
)

// NewTestAuth creates a paired signer and key registry with a pre-registered key
// for the given identity ID. Useful for test setup.
func NewTestAuth(identityID string) (signer *Signer, keys *KeyRegistry, pubKey ed25519.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	keys = NewKeyRegistry()
	keys.Add(identityID, "test", pub)
	return NewSigner(priv), keys, pub
}
