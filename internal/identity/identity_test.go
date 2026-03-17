package identity

import (
	"strings"
	"testing"

	daov1 "dao.pub/gen/dao/v1"
)

// --- NewHuman ---

func TestNewHumanFields(t *testing.T) {
	u, err := NewHuman("alice", "alice-gh")
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "alice" {
		t.Fatalf("expected alice, got %s", u.Name)
	}
	if u.Github != "alice-gh" {
		t.Fatalf("expected alice-gh, got %s", u.Github)
	}
	if u.Kind != daov1.IdentityKind_IDENTITY_KIND_USER {
		t.Fatalf("expected user kind, got %v", u.Kind)
	}
	if u.UserType != daov1.UserType_USER_TYPE_HUMAN {
		t.Fatalf("expected human user type, got %v", u.UserType)
	}
	if u.OwnerId != "" {
		t.Fatalf("human should have no owner, got %s", u.OwnerId)
	}
	if u.CreatedAt == 0 {
		t.Fatal("expected non-zero CreatedAt")
	}
}

func TestNewHumanGeneratesUniqueIDs(t *testing.T) {
	u1, _ := NewHuman("alice", "gh")
	u2, _ := NewHuman("alice", "gh")
	if u1.Id == u2.Id {
		t.Fatalf("expected unique IDs, both got %s", u1.Id)
	}
}

func TestNewHumanIDFormat(t *testing.T) {
	u, _ := NewHuman("alice", "gh")
	if !strings.HasPrefix(u.Id, "id_") {
		t.Fatalf("expected id_ prefix, got %s", u.Id)
	}
	if len(u.Id) != 35 {
		t.Fatalf("expected 35 char ID, got %d: %s", len(u.Id), u.Id)
	}
}

// --- NewAgent ---

func TestNewAgentFields(t *testing.T) {
	a, err := NewAgent("bot", "owner-123")
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != daov1.IdentityKind_IDENTITY_KIND_USER {
		t.Fatalf("expected user kind, got %v", a.Kind)
	}
	if a.UserType != daov1.UserType_USER_TYPE_AGENT {
		t.Fatalf("expected agent user type, got %v", a.UserType)
	}
	if a.OwnerId != "owner-123" {
		t.Fatalf("expected owner-123, got %s", a.OwnerId)
	}
}

func TestNewAgentWithOptions(t *testing.T) {
	a, err := NewAgent("bot", "owner-123",
		WithDescription("a bot"),
		WithMeta(map[string]string{"k": "v"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if a.Description != "a bot" {
		t.Fatalf("expected description 'a bot', got %s", a.Description)
	}
	if a.Meta["k"] != "v" {
		t.Fatalf("expected meta k=v, got %v", a.Meta)
	}
}

// --- NewOrg ---

func TestNewOrgFields(t *testing.T) {
	o, err := NewOrg("acme", "owner-456")
	if err != nil {
		t.Fatal(err)
	}
	if o.Kind != daov1.IdentityKind_IDENTITY_KIND_ORG {
		t.Fatalf("expected org kind, got %v", o.Kind)
	}
	if o.UserType != daov1.UserType_USER_TYPE_UNSPECIFIED {
		t.Fatalf("orgs should have unspecified user type, got %v", o.UserType)
	}
	if o.OwnerId != "owner-456" {
		t.Fatalf("expected owner-456, got %s", o.OwnerId)
	}
}

// --- ValidateEd25519Key ---

func TestValidateEd25519KeyRejectsShortKey(t *testing.T) {
	err := ValidateEd25519Key([]byte("too-short"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestValidateEd25519KeyRejectsLongKey(t *testing.T) {
	err := ValidateEd25519Key(make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for long key")
	}
}

func TestValidateEd25519KeyAccepts32Bytes(t *testing.T) {
	err := ValidateEd25519Key(make([]byte, 32))
	if err != nil {
		t.Fatalf("expected nil for valid key, got %v", err)
	}
}

func TestValidateEd25519KeyRejectsNil(t *testing.T) {
	err := ValidateEd25519Key(nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}
