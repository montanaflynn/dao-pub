package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"connectrpc.com/connect"
)

// --- KeyRegistry ---

func TestKeyRegistryAddAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := NewKeyRegistry()
	kr.Add("user1", "default", pub)

	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)

	id, err := kr.Verify(msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if id != "user1" {
		t.Fatalf("expected user1, got %s", id)
	}
}

func TestKeyRegistryVerifyRejectsWrongSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	kr := NewKeyRegistry()
	kr.Add("user1", "default", pub)

	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("hello")
	sig := ed25519.Sign(wrongPriv, msg)

	_, err := kr.Verify(msg, sig)
	if err == nil {
		t.Fatal("expected error for wrong signature")
	}
}

func TestKeyRegistryRevokedKeyCannotVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := NewKeyRegistry()
	pk := kr.Add("user1", "default", pub)

	kr.Revoke(pk.Id, "user1")

	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	_, err := kr.Verify(msg, sig)
	if err == nil {
		t.Fatal("expected error for revoked key")
	}
}

func TestKeyRegistryRevokeWrongOwnerFails(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	kr := NewKeyRegistry()
	pk := kr.Add("user1", "default", pub)

	err := kr.Revoke(pk.Id, "user2")
	if err == nil {
		t.Fatal("expected error revoking someone else's key")
	}
}

func TestKeyRegistryRevokeNonexistent(t *testing.T) {
	kr := NewKeyRegistry()
	err := kr.Revoke("nonexistent", "user1")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestKeyRegistryListByIdentity(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	pub3, _, _ := ed25519.GenerateKey(rand.Reader)
	kr := NewKeyRegistry()
	kr.Add("user1", "key1", pub1)
	kr.Add("user1", "key2", pub2)
	kr.Add("user2", "key3", pub3)

	keys := kr.ListByIdentity("user1")
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys for user1, got %d", len(keys))
	}
	keys2 := kr.ListByIdentity("user2")
	if len(keys2) != 1 {
		t.Fatalf("expected 1 key for user2, got %d", len(keys2))
	}
}

// --- Signer ---

func TestSignerSetsHeaders(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := NewSigner(priv)

	header := http.Header{}
	req := &fakeRequest{header: header}
	s.Sign(req, "/dao.v1.DaoService/WhoAmI")

	ts := header.Get("X-Dao-Timestamp")
	sig := header.Get("X-Dao-Signature")
	if ts == "" {
		t.Fatal("expected X-Dao-Timestamp header")
	}
	if sig == "" {
		t.Fatal("expected X-Dao-Signature header")
	}

	// Verify the signature is valid
	tsInt, _ := strconv.ParseInt(ts, 10, 64)
	diff := time.Now().Unix() - tsInt
	if diff < 0 {
		diff = -diff
	}
	if diff > 2 {
		t.Fatalf("timestamp too far from now: %d", diff)
	}
}

func TestSignerProducesVerifiableSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := NewKeyRegistry()
	kr.Add("user1", "default", pub)

	s := NewSigner(priv)
	header := http.Header{}
	req := &fakeRequest{header: header}
	procedure := "/dao.v1.DaoService/WhoAmI"
	s.Sign(req, procedure)

	ts := header.Get("X-Dao-Timestamp")
	sigHex := header.Get("X-Dao-Signature")
	sig, _ := hex.DecodeString(sigHex)

	msg := FormatSignMessage(ts, procedure)
	id, err := kr.Verify(msg, sig)
	if err != nil {
		t.Fatalf("signer output should verify: %v", err)
	}
	if id != "user1" {
		t.Fatalf("expected user1, got %s", id)
	}
}

// --- NewTestAuth ---

func TestNewTestAuthProducesWorkingPair(t *testing.T) {
	signer, keys, _ := NewTestAuth("test-id")

	header := http.Header{}
	req := &fakeRequest{header: header}
	procedure := "/dao.v1.DaoService/WhoAmI"
	signer.Sign(req, procedure)

	ts := header.Get("X-Dao-Timestamp")
	sigHex := header.Get("X-Dao-Signature")
	sig, _ := hex.DecodeString(sigHex)

	msg := FormatSignMessage(ts, procedure)
	id, err := keys.Verify(msg, sig)
	if err != nil {
		t.Fatalf("test auth pair should verify: %v", err)
	}
	if id != "test-id" {
		t.Fatalf("expected test-id, got %s", id)
	}
}

// --- Interceptor ---
// connect.AnyRequest has unexported methods, so we can't fake it.
// But *connect.Request[T] from connect.NewRequest() satisfies it.
// The Spec().Procedure is "" for manually-created requests, so we
// sign with "" as the procedure and the interceptor validates normally.

func TestInterceptorRejectsMissingHeaders(t *testing.T) {
	kr := NewKeyRegistry()
	interceptor := NewInterceptor(kr)

	inner := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("should not reach inner handler")
		return nil, nil
	}
	wrapped := interceptor(inner)

	// NewRequest creates a request with empty Spec().Procedure — not in publicProcedures
	req := connect.NewRequest[any](nil)
	_, err := wrapped(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing auth headers")
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", connect.CodeOf(err))
	}
}

func TestInterceptorRejectsExpiredTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := NewKeyRegistry()
	kr.Add("user1", "default", pub)
	interceptor := NewInterceptor(kr)

	inner := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("should not reach inner handler")
		return nil, nil
	}
	wrapped := interceptor(inner)

	// Sign with empty procedure (matches what Spec().Procedure returns)
	oldTs := strconv.FormatInt(time.Now().Unix()-60, 10)
	msg := FormatSignMessage(oldTs, "")
	sig := ed25519.Sign(priv, msg)

	req := connect.NewRequest[any](nil)
	req.Header().Set("X-Dao-Timestamp", oldTs)
	req.Header().Set("X-Dao-Signature", hex.EncodeToString(sig))

	_, err := wrapped(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for expired timestamp")
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", connect.CodeOf(err))
	}
}

func TestInterceptorRejectsInvalidTimestamp(t *testing.T) {
	kr := NewKeyRegistry()
	interceptor := NewInterceptor(kr)

	inner := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("should not reach inner handler")
		return nil, nil
	}
	wrapped := interceptor(inner)

	req := connect.NewRequest[any](nil)
	req.Header().Set("X-Dao-Timestamp", "not-a-number")
	req.Header().Set("X-Dao-Signature", "deadbeef")

	_, err := wrapped(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", connect.CodeOf(err))
	}
}

func TestInterceptorRejectsBadSignatureEncoding(t *testing.T) {
	kr := NewKeyRegistry()
	interceptor := NewInterceptor(kr)

	inner := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("should not reach inner handler")
		return nil, nil
	}
	wrapped := interceptor(inner)

	req := connect.NewRequest[any](nil)
	req.Header().Set("X-Dao-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header().Set("X-Dao-Signature", "not-hex!!!")

	_, err := wrapped(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", connect.CodeOf(err))
	}
}

func TestInterceptorRejectsWrongSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	kr := NewKeyRegistry()
	kr.Add("user1", "default", pub)
	interceptor := NewInterceptor(kr)

	inner := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("should not reach inner handler")
		return nil, nil
	}
	wrapped := interceptor(inner)

	// Sign with a different key
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	msg := FormatSignMessage(ts, "")
	sig := ed25519.Sign(wrongPriv, msg)

	req := connect.NewRequest[any](nil)
	req.Header().Set("X-Dao-Timestamp", ts)
	req.Header().Set("X-Dao-Signature", hex.EncodeToString(sig))

	_, err := wrapped(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", connect.CodeOf(err))
	}
}

func TestInterceptorSetsIdentityInContext(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kr := NewKeyRegistry()
	kr.Add("user1", "default", pub)
	interceptor := NewInterceptor(kr)

	var gotID string
	inner := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		id, ok := IdentityFromContext(ctx)
		if !ok {
			t.Fatal("expected identity in context")
		}
		gotID = id
		return nil, nil
	}
	wrapped := interceptor(inner)

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	msg := FormatSignMessage(ts, "")
	sig := ed25519.Sign(priv, msg)

	req := connect.NewRequest[any](nil)
	req.Header().Set("X-Dao-Timestamp", ts)
	req.Header().Set("X-Dao-Signature", hex.EncodeToString(sig))

	_, err := wrapped(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != "user1" {
		t.Fatalf("expected user1 in context, got %s", gotID)
	}
}

func TestIdentityFromContextRoundtrip(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextKey{}, "user-123")
	id, ok := IdentityFromContext(ctx)
	if !ok {
		t.Fatal("expected identity in context")
	}
	if id != "user-123" {
		t.Fatalf("expected user-123, got %s", id)
	}
}

func TestIdentityFromContextMissing(t *testing.T) {
	_, ok := IdentityFromContext(context.Background())
	if ok {
		t.Fatal("expected no identity in empty context")
	}
}

// --- FormatSignMessage ---

func TestFormatSignMessage(t *testing.T) {
	msg := FormatSignMessage("12345", "/dao.v1.DaoService/Ping")
	expected := "12345:/dao.v1.DaoService/Ping"
	if string(msg) != expected {
		t.Fatalf("expected %q, got %q", expected, string(msg))
	}
}

// helper
type fakeRequest struct {
	header http.Header
}

func (f *fakeRequest) Header() http.Header { return f.header }
