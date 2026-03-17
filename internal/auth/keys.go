package auth

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	daov1 "dao.pub/gen/dao/v1"
)

// KeyRegistry manages public keys in memory.
type KeyRegistry struct {
	mu   sync.RWMutex
	keys map[string]*daov1.PublicKey // key ID -> PublicKey
}

func NewKeyRegistry() *KeyRegistry {
	return &KeyRegistry{
		keys: make(map[string]*daov1.PublicKey),
	}
}

// Add registers a public key for an identity.
func (r *KeyRegistry) Add(identityID, label string, pubKey ed25519.PublicKey) *daov1.PublicKey {
	r.mu.Lock()
	defer r.mu.Unlock()

	keyID := fmt.Sprintf("pk_%x", pubKey[:8])
	pk := &daov1.PublicKey{
		Id:         keyID,
		IdentityId: identityID,
		Label:      label,
		PublicKey:  pubKey,
		CreatedAt:  time.Now().Unix(),
	}
	r.keys[keyID] = pk
	return pk
}

// Verify checks a signature against all active keys and returns the identity ID.
func (r *KeyRegistry) Verify(message, signature []byte) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, pk := range r.keys {
		if pk.Revoked {
			continue
		}
		pubKey := ed25519.PublicKey(pk.PublicKey)
		if ed25519.Verify(pubKey, message, signature) {
			return pk.IdentityId, nil
		}
	}
	return "", fmt.Errorf("no matching key")
}

// ListByIdentity returns all keys for a given identity.
func (r *KeyRegistry) ListByIdentity(identityID string) []*daov1.PublicKey {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*daov1.PublicKey
	for _, pk := range r.keys {
		if pk.IdentityId == identityID {
			result = append(result, pk)
		}
	}
	return result
}

// Revoke marks a key as revoked.
func (r *KeyRegistry) Revoke(keyID, identityID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pk, ok := r.keys[keyID]
	if !ok {
		return fmt.Errorf("key not found")
	}
	if pk.IdentityId != identityID {
		return fmt.Errorf("not your key")
	}
	pk.Revoked = true
	return nil
}
