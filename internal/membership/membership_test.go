package membership

import (
	"sync"
	"testing"
)

// fakeLookup simulates an identity store for testing.
// Keys are identity IDs, values are owner IDs.
type fakeLookup map[string]string

func (f fakeLookup) fn() IdentityLookup {
	return func(id string) (string, bool) {
		owner, ok := f[id]
		return owner, ok
	}
}

// newTestRegistry creates a Registry with pre-configured identities.
// "user1" owns "org1", "user2" and "agent1" exist but own nothing.
func newTestRegistry() *Registry {
	ids := fakeLookup{
		"user1":  "",      // user (no owner)
		"user2":  "",      // user (no owner)
		"agent1": "user1", // agent owned by user1
		"org1":   "user1", // org owned by user1
	}
	return NewRegistry(ids.fn())
}

// --- Authorization ---

func TestOwnerCanManageTheirGroup(t *testing.T) {
	r := newTestRegistry()
	if err := r.CanManage("user1", "org1"); err != nil {
		t.Fatalf("owner should manage their org: %v", err)
	}
}

func TestNonOwnerCannotManageGroup(t *testing.T) {
	r := newTestRegistry()
	err := r.CanManage("user2", "org1")
	if err != ErrPermissionDenied {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

func TestAdminCanManageGroup(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")
	// user1 (owner) adds user2 as admin
	_, err := r.AddMember("user1", "user2", "org1", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	// user2 should now be able to manage
	if err := r.CanManage("user2", "org1"); err != nil {
		t.Fatalf("admin should manage group: %v", err)
	}
}

func TestMemberCannotManageGroup(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")
	_, err := r.AddMember("user1", "user2", "org1", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	err = r.CanManage("user2", "org1")
	if err != ErrPermissionDenied {
		t.Fatalf("member should not manage group, got %v", err)
	}
}

func TestOperatorCannotManageGroup(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")
	_, err := r.AddMember("user1", "user2", "org1", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	err = r.CanManage("user2", "org1")
	if err != ErrPermissionDenied {
		t.Fatalf("operator should not manage group, got %v", err)
	}
}

func TestCanManageNonexistentGroup(t *testing.T) {
	r := newTestRegistry()
	err := r.CanManage("user1", "nonexistent")
	if err != ErrGroupNotFound {
		t.Fatalf("expected ErrGroupNotFound, got %v", err)
	}
}

// --- AddMember ---

func TestAddMemberHappyPath(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")

	m, err := r.AddMember("user1", "user2", "org1", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if m.IdentityId != "user2" {
		t.Fatalf("expected user2, got %s", m.IdentityId)
	}
	if m.GroupId != "org1" {
		t.Fatalf("expected org1, got %s", m.GroupId)
	}
	if m.Role != string(RoleMember) {
		t.Fatalf("expected member role, got %s", m.Role)
	}
	if m.JoinedAt == 0 {
		t.Fatal("expected non-zero JoinedAt")
	}
}

func TestAddMemberRejectsDuplicate(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")

	if _, err := r.AddMember("user1", "user2", "org1", RoleMember); err != nil {
		t.Fatal(err)
	}
	_, err := r.AddMember("user1", "user2", "org1", RoleAdmin)
	if err != ErrDuplicate {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
}

func TestAddMemberRejectsUnknownRole(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")

	_, err := r.AddMember("user1", "user2", "org1", Role("banana"))
	if err != ErrUnknownRole {
		t.Fatalf("expected ErrUnknownRole, got %v", err)
	}
}

func TestAddMemberRejectsNonexistentIdentity(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")

	_, err := r.AddMember("user1", "ghost", "org1", RoleMember)
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAddMemberUnauthorizedCaller(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")

	_, err := r.AddMember("user2", "agent1", "org1", RoleMember)
	if err != ErrPermissionDenied {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

// --- RemoveMember ---

func TestRemoveMemberHappyPath(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")
	r.AddMember("user1", "user2", "org1", RoleMember)

	err := r.RemoveMember("user1", "user2", "org1")
	if err != nil {
		t.Fatal(err)
	}
	// Verify removal
	members := r.ListMembers("org1")
	for _, m := range members {
		if m.IdentityId == "user2" {
			t.Fatal("user2 should have been removed")
		}
	}
}

func TestRemoveMemberNotFound(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")

	err := r.RemoveMember("user1", "user2", "org1")
	if err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRemoveMemberUnauthorized(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")
	r.AddMember("user1", "user2", "org1", RoleMember)

	err := r.RemoveMember("user2", "user1", "org1")
	if err != ErrPermissionDenied {
		t.Fatalf("expected ErrPermissionDenied, got %v", err)
	}
}

// --- ListMembers ---

func TestListMembersEmpty(t *testing.T) {
	r := newTestRegistry()
	members := r.ListMembers("org1")
	if len(members) != 0 {
		t.Fatalf("expected 0 members, got %d", len(members))
	}
}

func TestListMembersReturnsAll(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")
	r.AddMember("user1", "user2", "org1", RoleMember)

	members := r.ListMembers("org1")
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
}

// --- BootstrapOwner ---

func TestBootstrapOwnerCreatesOwnerMembership(t *testing.T) {
	r := newTestRegistry()
	m := r.BootstrapOwner("user1", "org1")

	if m.Role != string(RoleOwner) {
		t.Fatalf("expected owner role, got %s", m.Role)
	}
	if m.IdentityId != "user1" {
		t.Fatalf("expected user1, got %s", m.IdentityId)
	}
}

// --- Concurrency ---

func TestConcurrentAddRemove(t *testing.T) {
	r := newTestRegistry()
	r.BootstrapOwner("user1", "org1")

	var wg sync.WaitGroup
	// Hammer add and remove concurrently — should not panic or corrupt.
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			r.AddMember("user1", "user2", "org1", RoleMember)
		}()
		go func() {
			defer wg.Done()
			r.RemoveMember("user1", "user2", "org1")
		}()
	}
	wg.Wait()

	// State should be consistent — user2 is either a member or not.
	members := r.ListMembers("org1")
	user2Count := 0
	for _, m := range members {
		if m.IdentityId == "user2" {
			user2Count++
		}
	}
	if user2Count > 1 {
		t.Fatalf("user2 appears %d times — duplicate detected", user2Count)
	}
}
