package store

import (
	"sync"
	"testing"

	daov1 "dao.pub/gen/dao/v1"
)

func makeIdentity(id, name, ownerID string, kind daov1.IdentityKind) *daov1.Identity {
	return &daov1.Identity{
		Id:      id,
		Name:    name,
		OwnerId: ownerID,
		Kind:    kind,
	}
}

// --- Put / Get ---

func TestPutAndGet(t *testing.T) {
	s := NewMemoryStore()
	ident := makeIdentity("id1", "alice", "", daov1.IdentityKind_IDENTITY_KIND_USER)
	s.Put(ident)

	got, ok := s.Get("id1")
	if !ok {
		t.Fatal("expected to find identity")
	}
	if got.Name != "alice" {
		t.Fatalf("expected alice, got %s", got.Name)
	}
}

func TestGetMissing(t *testing.T) {
	s := NewMemoryStore()
	_, ok := s.Get("nonexistent")
	if ok {
		t.Fatal("expected not found")
	}
}

func TestPutOverwrites(t *testing.T) {
	s := NewMemoryStore()
	s.Put(makeIdentity("id1", "alice", "", daov1.IdentityKind_IDENTITY_KIND_USER))
	s.Put(makeIdentity("id1", "bob", "", daov1.IdentityKind_IDENTITY_KIND_USER))

	got, _ := s.Get("id1")
	if got.Name != "bob" {
		t.Fatalf("expected overwrite to bob, got %s", got.Name)
	}
}

// --- ListByOwner ---

func TestListByOwnerFiltersCorrectly(t *testing.T) {
	s := NewMemoryStore()
	s.Put(makeIdentity("a1", "agent1", "user1", daov1.IdentityKind_IDENTITY_KIND_USER))
	s.Put(makeIdentity("a2", "agent2", "user1", daov1.IdentityKind_IDENTITY_KIND_USER))
	s.Put(makeIdentity("o1", "org1", "user1", daov1.IdentityKind_IDENTITY_KIND_ORG))
	s.Put(makeIdentity("a3", "agent3", "user2", daov1.IdentityKind_IDENTITY_KIND_USER))

	// All owned by user1
	all := s.ListByOwner("user1", daov1.IdentityKind_IDENTITY_KIND_UNSPECIFIED)
	if len(all) != 3 {
		t.Fatalf("expected 3 owned by user1, got %d", len(all))
	}

	// Only agents owned by user1
	agents := s.ListByOwner("user1", daov1.IdentityKind_IDENTITY_KIND_USER)
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents owned by user1, got %d", len(agents))
	}

	// Only orgs owned by user1
	orgs := s.ListByOwner("user1", daov1.IdentityKind_IDENTITY_KIND_ORG)
	if len(orgs) != 1 {
		t.Fatalf("expected 1 org owned by user1, got %d", len(orgs))
	}
}

func TestListByOwnerReturnsEmptyForUnknownOwner(t *testing.T) {
	s := NewMemoryStore()
	s.Put(makeIdentity("a1", "agent1", "user1", daov1.IdentityKind_IDENTITY_KIND_USER))

	result := s.ListByOwner("nobody", daov1.IdentityKind_IDENTITY_KIND_UNSPECIFIED)
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}

// --- Concurrency ---

func TestConcurrentPutGet(t *testing.T) {
	s := NewMemoryStore()
	var wg sync.WaitGroup

	for i := range 100 {
		wg.Add(2)
		id := makeIdentity("id", "name", "", daov1.IdentityKind_IDENTITY_KIND_USER)
		id.Id = "id" + string(rune(i))
		go func() {
			defer wg.Done()
			s.Put(id)
		}()
		go func() {
			defer wg.Done()
			s.Get(id.Id)
		}()
	}
	wg.Wait()
}
