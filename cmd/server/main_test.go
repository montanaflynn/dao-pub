package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	daov1 "dao.pub/gen/dao/v1"
	"dao.pub/gen/dao/v1/daov1connect"
	"dao.pub/internal/auth"

	"connectrpc.com/connect"
)

// testEnv sets up a server and returns a signed client helper.
type testEnv struct {
	client  daov1connect.DaoServiceClient
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
	signer  *auth.Signer
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	keys := auth.NewKeyRegistry()
	server := NewDaoServer(keys)
	mux := http.NewServeMux()
	path, handler := daov1connect.NewDaoServiceHandler(
		server,
		connect.WithInterceptors(auth.NewInterceptor(keys)),
	)
	mux.Handle(path, handler)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	client := daov1connect.NewDaoServiceClient(http.DefaultClient, ts.URL)
	return &testEnv{client: client, pubKey: pub, privKey: priv, signer: auth.NewSigner(priv)}
}

func (e *testEnv) sign(req interface{ Header() http.Header }, procedure string) {
	e.signer.Sign(req, procedure)
}

func (e *testEnv) register(t *testing.T, name, github string) *daov1.RegisterResponse {
	t.Helper()
	res, err := e.client.Register(context.Background(), connect.NewRequest(&daov1.RegisterRequest{
		Name:      name,
		Github:    github,
		PublicKey: e.pubKey,
		KeyLabel:  "default",
	}))
	if err != nil {
		t.Fatal(err)
	}
	return res.Msg
}

func TestPing(t *testing.T) {
	env := newTestEnv(t)
	res, err := env.client.Ping(context.Background(), connect.NewRequest(&daov1.PingRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.Message != "pong" {
		t.Fatalf("expected pong, got %q", res.Msg.Message)
	}
	if res.Msg.Timestamp == 0 {
		t.Fatal("expected non-zero timestamp")
	}
}

func TestRegisterAndWhoAmI(t *testing.T) {
	env := newTestEnv(t)

	reg := env.register(t, "montana", "montanaflynn")

	if reg.Identity.Name != "montana" {
		t.Fatalf("expected name montana, got %q", reg.Identity.Name)
	}
	if reg.Identity.Kind != daov1.IdentityKind_IDENTITY_KIND_USER {
		t.Fatalf("expected user kind, got %v", reg.Identity.Kind)
	}
	if reg.Key == nil {
		t.Fatal("expected public key in response")
	}

	// WhoAmI should return the same identity.
	req := connect.NewRequest(&daov1.WhoAmIRequest{})
	env.sign(req, "/dao.v1.DaoService/WhoAmI")
	whoami, err := env.client.WhoAmI(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if whoami.Msg.Identity.Id != reg.Identity.Id {
		t.Fatalf("whoami returned %q, expected %q", whoami.Msg.Identity.Id, reg.Identity.Id)
	}
}

func TestUnauthenticatedRequestFails(t *testing.T) {
	env := newTestEnv(t)

	// WhoAmI without signing should fail.
	_, err := env.client.WhoAmI(context.Background(), connect.NewRequest(&daov1.WhoAmIRequest{}))
	if err == nil {
		t.Fatal("expected error for unauthenticated request")
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", connect.CodeOf(err))
	}
}

func TestCreateAgent(t *testing.T) {
	env := newTestEnv(t)
	reg := env.register(t, "montana", "montanaflynn")

	req := connect.NewRequest(&daov1.CreateIdentityRequest{
		Kind:        daov1.IdentityKind_IDENTITY_KIND_AGENT,
		Name:        "code-reviewer",
		Description: "reviews pull requests",
	})
	env.sign(req, "/dao.v1.DaoService/CreateIdentity")
	res, err := env.client.CreateIdentity(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	agent := res.Msg.Identity
	if agent.Kind != daov1.IdentityKind_IDENTITY_KIND_AGENT {
		t.Fatalf("expected agent kind, got %v", agent.Kind)
	}
	if agent.Name != "code-reviewer" {
		t.Fatalf("expected code-reviewer, got %q", agent.Name)
	}
	if agent.OwnerId != reg.Identity.Id {
		t.Fatalf("expected owner %q, got %q", reg.Identity.Id, agent.OwnerId)
	}
}

func TestCreateOrg(t *testing.T) {
	env := newTestEnv(t)
	reg := env.register(t, "montana", "montanaflynn")

	req := connect.NewRequest(&daov1.CreateIdentityRequest{
		Kind:        daov1.IdentityKind_IDENTITY_KIND_ORG,
		Name:        "acme-labs",
		Description: "building the future",
	})
	env.sign(req, "/dao.v1.DaoService/CreateIdentity")
	res, err := env.client.CreateIdentity(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	org := res.Msg.Identity
	if org.Kind != daov1.IdentityKind_IDENTITY_KIND_ORG {
		t.Fatalf("expected org kind, got %v", org.Kind)
	}
	if org.OwnerId != reg.Identity.Id {
		t.Fatalf("expected owner %q, got %q", reg.Identity.Id, org.OwnerId)
	}

	// Creator should be auto-added as owner member.
	mReq := connect.NewRequest(&daov1.ListMembersRequest{GroupId: org.Id})
	env.sign(mReq, "/dao.v1.DaoService/ListMembers")
	mRes, err := env.client.ListMembers(context.Background(), mReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(mRes.Msg.Members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(mRes.Msg.Members))
	}
	if mRes.Msg.Members[0].Role != "owner" {
		t.Fatalf("expected owner role, got %q", mRes.Msg.Members[0].Role)
	}
}

func TestCreateUserIdentityFails(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "montana", "montanaflynn")

	req := connect.NewRequest(&daov1.CreateIdentityRequest{
		Kind: daov1.IdentityKind_IDENTITY_KIND_USER,
		Name: "sneaky",
	})
	env.sign(req, "/dao.v1.DaoService/CreateIdentity")
	_, err := env.client.CreateIdentity(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when creating user via CreateIdentity")
	}
}

func TestListOwned(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "montana", "montanaflynn")

	// Create 2 agents and 1 org.
	for _, name := range []string{"agent-a", "agent-b"} {
		req := connect.NewRequest(&daov1.CreateIdentityRequest{
			Kind: daov1.IdentityKind_IDENTITY_KIND_AGENT,
			Name: name,
		})
		env.sign(req, "/dao.v1.DaoService/CreateIdentity")
		if _, err := env.client.CreateIdentity(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	orgReq := connect.NewRequest(&daov1.CreateIdentityRequest{
		Kind: daov1.IdentityKind_IDENTITY_KIND_ORG,
		Name: "my-org",
	})
	env.sign(orgReq, "/dao.v1.DaoService/CreateIdentity")
	if _, err := env.client.CreateIdentity(context.Background(), orgReq); err != nil {
		t.Fatal(err)
	}

	// List all owned.
	allReq := connect.NewRequest(&daov1.ListOwnedRequest{})
	env.sign(allReq, "/dao.v1.DaoService/ListOwned")
	allRes, err := env.client.ListOwned(context.Background(), allReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(allRes.Msg.Identities) != 3 {
		t.Fatalf("expected 3 owned, got %d", len(allRes.Msg.Identities))
	}

	// Filter agents only.
	agentReq := connect.NewRequest(&daov1.ListOwnedRequest{Kind: daov1.IdentityKind_IDENTITY_KIND_AGENT})
	env.sign(agentReq, "/dao.v1.DaoService/ListOwned")
	agentRes, err := env.client.ListOwned(context.Background(), agentReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(agentRes.Msg.Identities) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agentRes.Msg.Identities))
	}
}

func TestMembershipManagement(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "montana", "montanaflynn")

	// Create an org.
	orgReq := connect.NewRequest(&daov1.CreateIdentityRequest{
		Kind: daov1.IdentityKind_IDENTITY_KIND_ORG,
		Name: "team",
	})
	env.sign(orgReq, "/dao.v1.DaoService/CreateIdentity")
	orgRes, err := env.client.CreateIdentity(context.Background(), orgReq)
	if err != nil {
		t.Fatal(err)
	}
	orgID := orgRes.Msg.Identity.Id

	// Create an agent to add as member.
	agentReq := connect.NewRequest(&daov1.CreateIdentityRequest{
		Kind: daov1.IdentityKind_IDENTITY_KIND_AGENT,
		Name: "bot",
	})
	env.sign(agentReq, "/dao.v1.DaoService/CreateIdentity")
	agentRes, err := env.client.CreateIdentity(context.Background(), agentReq)
	if err != nil {
		t.Fatal(err)
	}
	agentID := agentRes.Msg.Identity.Id

	// Add agent as member of org.
	addReq := connect.NewRequest(&daov1.AddMemberRequest{
		GroupId:  orgID,
		MemberId: agentID,
		Role:     "operator",
	})
	env.sign(addReq, "/dao.v1.DaoService/AddMember")
	addRes, err := env.client.AddMember(context.Background(), addReq)
	if err != nil {
		t.Fatal(err)
	}
	if addRes.Msg.Membership.Role != "operator" {
		t.Fatalf("expected operator role, got %q", addRes.Msg.Membership.Role)
	}

	// List members — should be owner + operator.
	listReq := connect.NewRequest(&daov1.ListMembersRequest{GroupId: orgID})
	env.sign(listReq, "/dao.v1.DaoService/ListMembers")
	listRes, err := env.client.ListMembers(context.Background(), listReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(listRes.Msg.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(listRes.Msg.Members))
	}

	// Remove the agent.
	rmReq := connect.NewRequest(&daov1.RemoveMemberRequest{
		GroupId:  orgID,
		MemberId: agentID,
	})
	env.sign(rmReq, "/dao.v1.DaoService/RemoveMember")
	if _, err := env.client.RemoveMember(context.Background(), rmReq); err != nil {
		t.Fatal(err)
	}

	// List again — should be just the owner.
	listReq2 := connect.NewRequest(&daov1.ListMembersRequest{GroupId: orgID})
	env.sign(listReq2, "/dao.v1.DaoService/ListMembers")
	listRes2, err := env.client.ListMembers(context.Background(), listReq2)
	if err != nil {
		t.Fatal(err)
	}
	if len(listRes2.Msg.Members) != 1 {
		t.Fatalf("expected 1 member after removal, got %d", len(listRes2.Msg.Members))
	}
}

func TestPermissionDenied(t *testing.T) {
	// Second user shouldn't be able to add members to first user's org.
	keys := auth.NewKeyRegistry()
	server := NewDaoServer(keys)
	mux := http.NewServeMux()
	path, handler := daov1connect.NewDaoServiceHandler(
		server,
		connect.WithInterceptors(auth.NewInterceptor(keys)),
	)
	mux.Handle(path, handler)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	client := daov1connect.NewDaoServiceClient(http.DefaultClient, ts.URL)
	ctx := context.Background()

	// User 1 registers and creates an org.
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	signer1 := auth.NewSigner(priv1)

	regRes, err := client.Register(ctx, connect.NewRequest(&daov1.RegisterRequest{
		Name: "user1", Github: "user1", PublicKey: pub1, KeyLabel: "default",
	}))
	if err != nil {
		t.Fatal(err)
	}

	orgReq := connect.NewRequest(&daov1.CreateIdentityRequest{
		Kind: daov1.IdentityKind_IDENTITY_KIND_ORG,
		Name: "private-org",
	})
	signer1.Sign(orgReq, "/dao.v1.DaoService/CreateIdentity")
	orgRes, err := client.CreateIdentity(ctx, orgReq)
	if err != nil {
		t.Fatal(err)
	}
	orgID := orgRes.Msg.Identity.Id

	// User 2 registers.
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	signer2 := auth.NewSigner(priv2)

	_, err = client.Register(ctx, connect.NewRequest(&daov1.RegisterRequest{
		Name: "user2", Github: "user2", PublicKey: pub2, KeyLabel: "default",
	}))
	if err != nil {
		t.Fatal(err)
	}

	// User 2 tries to add themselves to user 1's org — should fail.
	addReq := connect.NewRequest(&daov1.AddMemberRequest{
		GroupId:  orgID,
		MemberId: regRes.Msg.Identity.Id,
		Role:     "admin",
	})
	signer2.Sign(addReq, "/dao.v1.DaoService/AddMember")
	_, err = client.AddMember(ctx, addReq)
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("expected permission_denied, got %v", connect.CodeOf(err))
	}
}

func TestGetIdentityAndReputation(t *testing.T) {
	env := newTestEnv(t)
	reg := env.register(t, "montana", "montanaflynn")

	// GetIdentity
	getReq := connect.NewRequest(&daov1.GetIdentityRequest{Id: reg.Identity.Id})
	env.sign(getReq, "/dao.v1.DaoService/GetIdentity")
	getRes, err := env.client.GetIdentity(context.Background(), getReq)
	if err != nil {
		t.Fatal(err)
	}
	if getRes.Msg.Identity.Name != "montana" {
		t.Fatalf("expected montana, got %q", getRes.Msg.Identity.Name)
	}

	// GetIdentity for non-existent ID.
	badReq := connect.NewRequest(&daov1.GetIdentityRequest{Id: "nope"})
	env.sign(badReq, "/dao.v1.DaoService/GetIdentity")
	_, err = env.client.GetIdentity(context.Background(), badReq)
	if err == nil {
		t.Fatal("expected not found")
	}
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("expected not_found, got %v", connect.CodeOf(err))
	}

	// GetReputation
	repReq := connect.NewRequest(&daov1.GetReputationRequest{IdentityId: reg.Identity.Id})
	env.sign(repReq, "/dao.v1.DaoService/GetReputation")
	repRes, err := env.client.GetReputation(context.Background(), repReq)
	if err != nil {
		t.Fatal(err)
	}
	if repRes.Msg.Reputation.Score != 100 {
		t.Fatalf("expected score 100, got %d", repRes.Msg.Reputation.Score)
	}
}

func TestKeyManagement(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "montana", "montanaflynn")

	// List keys — should have 1 from registration.
	listReq := connect.NewRequest(&daov1.ListKeysRequest{})
	env.sign(listReq, "/dao.v1.DaoService/ListKeys")
	listRes, err := env.client.ListKeys(context.Background(), listReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(listRes.Msg.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(listRes.Msg.Keys))
	}
	keyID := listRes.Msg.Keys[0].Id

	// Add a second key.
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	addReq := connect.NewRequest(&daov1.AddKeyRequest{
		PublicKey: pub2,
		Label:    "backup",
	})
	env.sign(addReq, "/dao.v1.DaoService/AddKey")
	_, err = env.client.AddKey(context.Background(), addReq)
	if err != nil {
		t.Fatal(err)
	}

	// List again — should have 2.
	listReq2 := connect.NewRequest(&daov1.ListKeysRequest{})
	env.sign(listReq2, "/dao.v1.DaoService/ListKeys")
	listRes2, err := env.client.ListKeys(context.Background(), listReq2)
	if err != nil {
		t.Fatal(err)
	}
	if len(listRes2.Msg.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(listRes2.Msg.Keys))
	}

	// Find the backup key ID.
	var backupKeyID string
	for _, k := range listRes2.Msg.Keys {
		if k.Id != keyID {
			backupKeyID = k.Id
		}
	}

	// Revoke the backup key (not the one we're signing with).
	revokeReq := connect.NewRequest(&daov1.RevokeKeyRequest{KeyId: backupKeyID})
	env.sign(revokeReq, "/dao.v1.DaoService/RevokeKey")
	_, err = env.client.RevokeKey(context.Background(), revokeReq)
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's revoked.
	listReq3 := connect.NewRequest(&daov1.ListKeysRequest{})
	env.sign(listReq3, "/dao.v1.DaoService/ListKeys")
	listRes3, err := env.client.ListKeys(context.Background(), listReq3)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range listRes3.Msg.Keys {
		if k.Id == backupKeyID && !k.Revoked {
			t.Fatal("expected backup key to be revoked")
		}
	}
}

func TestExpiredSignatureFails(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "montana", "montanaflynn")

	// Sign with a timestamp 60 seconds in the past.
	req := connect.NewRequest(&daov1.WhoAmIRequest{})
	procedure := "/dao.v1.DaoService/WhoAmI"
	oldTs := strconv.FormatInt(time.Now().Unix()-60, 10)
	msg := auth.FormatSignMessage(oldTs, procedure)
	sig := ed25519.Sign(env.privKey, msg)
	req.Header().Set("X-Dao-Timestamp", oldTs)
	req.Header().Set("X-Dao-Signature", hex.EncodeToString(sig))

	_, err := env.client.WhoAmI(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for expired signature")
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", connect.CodeOf(err))
	}
}

func TestWrongKeyFails(t *testing.T) {
	env := newTestEnv(t)
	env.register(t, "montana", "montanaflynn")

	// Sign with a completely different key.
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	req := connect.NewRequest(&daov1.WhoAmIRequest{})
	procedure := "/dao.v1.DaoService/WhoAmI"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	msg := auth.FormatSignMessage(ts, procedure)
	sig := ed25519.Sign(wrongPriv, msg)
	req.Header().Set("X-Dao-Timestamp", ts)
	req.Header().Set("X-Dao-Signature", hex.EncodeToString(sig))

	_, err := env.client.WhoAmI(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("expected unauthenticated, got %v", connect.CodeOf(err))
	}
}

func TestAgentOwnsAgent(t *testing.T) {
	// Demonstrate the "agents own agents" model.
	// We need a separate setup since the agent needs its own keypair to auth.
	keys := auth.NewKeyRegistry()
	server := NewDaoServer(keys)
	mux := http.NewServeMux()
	path, handler := daov1connect.NewDaoServiceHandler(
		server,
		connect.WithInterceptors(auth.NewInterceptor(keys)),
	)
	mux.Handle(path, handler)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	client := daov1connect.NewDaoServiceClient(http.DefaultClient, ts.URL)
	ctx := context.Background()

	// Register a user.
	userPub, userPriv, _ := ed25519.GenerateKey(rand.Reader)
	userSigner := auth.NewSigner(userPriv)
	_, err := client.Register(ctx, connect.NewRequest(&daov1.RegisterRequest{
		Name: "human", Github: "human", PublicKey: userPub, KeyLabel: "default",
	}))
	if err != nil {
		t.Fatal(err)
	}

	// User creates an agent with its own keypair.
	agentPub, agentPriv, _ := ed25519.GenerateKey(rand.Reader)
	agentSigner := auth.NewSigner(agentPriv)
	createReq := connect.NewRequest(&daov1.CreateIdentityRequest{
		Kind:      daov1.IdentityKind_IDENTITY_KIND_AGENT,
		Name:      "orchestrator",
		PublicKey: agentPub,
	})
	userSigner.Sign(createReq, "/dao.v1.DaoService/CreateIdentity")
	agentRes, err := client.CreateIdentity(ctx, createReq)
	if err != nil {
		t.Fatal(err)
	}
	orchestratorID := agentRes.Msg.Identity.Id

	// The agent (orchestrator) authenticates with its own key and creates a sub-agent.
	subAgentReq := connect.NewRequest(&daov1.CreateIdentityRequest{
		Kind:        daov1.IdentityKind_IDENTITY_KIND_AGENT,
		Name:        "sub-worker",
		Description: "spawned by orchestrator",
	})
	agentSigner.Sign(subAgentReq, "/dao.v1.DaoService/CreateIdentity")
	subRes, err := client.CreateIdentity(ctx, subAgentReq)
	if err != nil {
		t.Fatal(err)
	}

	if subRes.Msg.Identity.OwnerId != orchestratorID {
		t.Fatalf("expected sub-agent owned by orchestrator %q, got %q", orchestratorID, subRes.Msg.Identity.OwnerId)
	}
	if subRes.Msg.Identity.Name != "sub-worker" {
		t.Fatalf("expected sub-worker, got %q", subRes.Msg.Identity.Name)
	}

	// Verify the ownership chain: user -> orchestrator -> sub-worker.
	fmt.Printf("ownership: human -> %s -> %s\n", orchestratorID, subRes.Msg.Identity.Id)
}
