package store

import (
	"sync"

	daov1 "dao.pub/gen/dao/v1"
)

// IdentityStore manages identity persistence.
type IdentityStore interface {
	Put(identity *daov1.Identity)
	Get(id string) (*daov1.Identity, bool)
	ListByOwner(ownerID string, kind daov1.IdentityKind) []*daov1.Identity
}

// MemoryStore is a thread-safe in-memory IdentityStore.
type MemoryStore struct {
	mu         sync.RWMutex
	identities map[string]*daov1.Identity
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		identities: make(map[string]*daov1.Identity),
	}
}

func (s *MemoryStore) Put(identity *daov1.Identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[identity.Id] = identity
}

func (s *MemoryStore) Get(id string) (*daov1.Identity, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ident, ok := s.identities[id]
	return ident, ok
}

func (s *MemoryStore) ListByOwner(ownerID string, kind daov1.IdentityKind) []*daov1.Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*daov1.Identity
	for _, id := range s.identities {
		if id.OwnerId != ownerID {
			continue
		}
		if kind != daov1.IdentityKind_IDENTITY_KIND_UNSPECIFIED && id.Kind != kind {
			continue
		}
		result = append(result, id)
	}
	return result
}
