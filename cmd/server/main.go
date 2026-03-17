package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	daov1 "dao.pub/gen/dao/v1"
	"dao.pub/gen/dao/v1/daov1connect"
	"dao.pub/internal/auth"

	"connectrpc.com/connect"
)

type DaoServer struct {
	identities  map[string]*daov1.Identity
	memberships []*daov1.Membership
	keys        *auth.KeyRegistry
}

func NewDaoServer(keys *auth.KeyRegistry) *DaoServer {
	return &DaoServer{
		identities: make(map[string]*daov1.Identity),
		keys:       keys,
	}
}

func (s *DaoServer) Ping(
	_ context.Context,
	_ *connect.Request[daov1.PingRequest],
) (*connect.Response[daov1.PingResponse], error) {
	return connect.NewResponse(&daov1.PingResponse{
		Message:   "pong",
		Timestamp: time.Now().Unix(),
	}), nil
}

func (s *DaoServer) Register(
	_ context.Context,
	req *connect.Request[daov1.RegisterRequest],
) (*connect.Response[daov1.RegisterResponse], error) {
	if len(req.Msg.PublicKey) != ed25519.PublicKeySize {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid ed25519 public key"))
	}

	id := fmt.Sprintf("id_%s_%d", req.Msg.Name, time.Now().UnixNano())
	identity := &daov1.Identity{
		Id:        id,
		Kind:      daov1.IdentityKind_IDENTITY_KIND_USER,
		Name:      req.Msg.Name,
		Github:    req.Msg.Github,
		CreatedAt: time.Now().Unix(),
	}
	s.identities[id] = identity

	label := req.Msg.KeyLabel
	if label == "" {
		label = "default"
	}
	pk := s.keys.Add(id, label, req.Msg.PublicKey)

	log.Printf("registered user: %s (%s)", identity.Name, identity.Id)
	return connect.NewResponse(&daov1.RegisterResponse{
		Identity: identity,
		Key:      pk,
	}), nil
}

func (s *DaoServer) WhoAmI(
	ctx context.Context,
	_ *connect.Request[daov1.WhoAmIRequest],
) (*connect.Response[daov1.WhoAmIResponse], error) {
	identity, err := s.callerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&daov1.WhoAmIResponse{
		Identity: identity,
	}), nil
}

func (s *DaoServer) CreateIdentity(
	ctx context.Context,
	req *connect.Request[daov1.CreateIdentityRequest],
) (*connect.Response[daov1.CreateIdentityResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)

	if req.Msg.Kind == daov1.IdentityKind_IDENTITY_KIND_USER {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("use Register to create user identities"))
	}
	if req.Msg.Kind == daov1.IdentityKind_IDENTITY_KIND_UNSPECIFIED {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("kind is required"))
	}

	id := fmt.Sprintf("id_%s_%d", req.Msg.Name, time.Now().UnixNano())
	identity := &daov1.Identity{
		Id:          id,
		Kind:        req.Msg.Kind,
		Name:        req.Msg.Name,
		Description: req.Msg.Description,
		OwnerId:     callerID,
		CreatedAt:   time.Now().Unix(),
		Meta:        req.Msg.Meta,
	}
	s.identities[id] = identity

	// Register the public key if provided.
	var pk *daov1.PublicKey
	if len(req.Msg.PublicKey) == ed25519.PublicKeySize {
		pk = s.keys.Add(id, "default", req.Msg.PublicKey)
	}

	kindName := "agent"
	if req.Msg.Kind == daov1.IdentityKind_IDENTITY_KIND_ORG {
		kindName = "org"
		// Auto-add creator as owner member.
		s.memberships = append(s.memberships, &daov1.Membership{
			IdentityId: callerID,
			GroupId:    id,
			Role:       "owner",
			JoinedAt:   time.Now().Unix(),
		})
	}

	log.Printf("created %s: %s (%s) owned by %s", kindName, identity.Name, identity.Id, callerID)
	return connect.NewResponse(&daov1.CreateIdentityResponse{
		Identity: identity,
		Key:      pk,
	}), nil
}

func (s *DaoServer) ListOwned(
	ctx context.Context,
	req *connect.Request[daov1.ListOwnedRequest],
) (*connect.Response[daov1.ListOwnedResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)

	var result []*daov1.Identity
	for _, id := range s.identities {
		if id.OwnerId != callerID {
			continue
		}
		if req.Msg.Kind != daov1.IdentityKind_IDENTITY_KIND_UNSPECIFIED && id.Kind != req.Msg.Kind {
			continue
		}
		result = append(result, id)
	}
	return connect.NewResponse(&daov1.ListOwnedResponse{
		Identities: result,
	}), nil
}

func (s *DaoServer) GetIdentity(
	_ context.Context,
	req *connect.Request[daov1.GetIdentityRequest],
) (*connect.Response[daov1.GetIdentityResponse], error) {
	identity, ok := s.identities[req.Msg.Id]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("identity %q not found", req.Msg.Id))
	}
	return connect.NewResponse(&daov1.GetIdentityResponse{
		Identity: identity,
	}), nil
}

func (s *DaoServer) AddMember(
	ctx context.Context,
	req *connect.Request[daov1.AddMemberRequest],
) (*connect.Response[daov1.AddMemberResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)

	// Verify caller owns or is admin of the group.
	if err := s.requireGroupAccess(callerID, req.Msg.GroupId); err != nil {
		return nil, err
	}

	// Verify the member identity exists.
	if _, ok := s.identities[req.Msg.MemberId]; !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("member identity %q not found", req.Msg.MemberId))
	}

	role := req.Msg.Role
	if role == "" {
		role = "member"
	}

	m := &daov1.Membership{
		IdentityId: req.Msg.MemberId,
		GroupId:    req.Msg.GroupId,
		Role:       role,
		JoinedAt:   time.Now().Unix(),
	}
	s.memberships = append(s.memberships, m)

	log.Printf("added member %s to %s as %s", req.Msg.MemberId, req.Msg.GroupId, role)
	return connect.NewResponse(&daov1.AddMemberResponse{
		Membership: m,
	}), nil
}

func (s *DaoServer) ListMembers(
	_ context.Context,
	req *connect.Request[daov1.ListMembersRequest],
) (*connect.Response[daov1.ListMembersResponse], error) {
	var result []*daov1.Membership
	for _, m := range s.memberships {
		if m.GroupId == req.Msg.GroupId {
			result = append(result, m)
		}
	}
	return connect.NewResponse(&daov1.ListMembersResponse{
		Members: result,
	}), nil
}

func (s *DaoServer) RemoveMember(
	ctx context.Context,
	req *connect.Request[daov1.RemoveMemberRequest],
) (*connect.Response[daov1.RemoveMemberResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)

	if err := s.requireGroupAccess(callerID, req.Msg.GroupId); err != nil {
		return nil, err
	}

	for i, m := range s.memberships {
		if m.GroupId == req.Msg.GroupId && m.IdentityId == req.Msg.MemberId {
			s.memberships = append(s.memberships[:i], s.memberships[i+1:]...)
			log.Printf("removed member %s from %s", req.Msg.MemberId, req.Msg.GroupId)
			return connect.NewResponse(&daov1.RemoveMemberResponse{}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("membership not found"))
}

func (s *DaoServer) AddKey(
	ctx context.Context,
	req *connect.Request[daov1.AddKeyRequest],
) (*connect.Response[daov1.AddKeyResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)
	if len(req.Msg.PublicKey) != ed25519.PublicKeySize {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid ed25519 public key"))
	}
	pk := s.keys.Add(callerID, req.Msg.Label, req.Msg.PublicKey)
	return connect.NewResponse(&daov1.AddKeyResponse{Key: pk}), nil
}

func (s *DaoServer) ListKeys(
	ctx context.Context,
	_ *connect.Request[daov1.ListKeysRequest],
) (*connect.Response[daov1.ListKeysResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)
	return connect.NewResponse(&daov1.ListKeysResponse{
		Keys: s.keys.ListByIdentity(callerID),
	}), nil
}

func (s *DaoServer) RevokeKey(
	ctx context.Context,
	req *connect.Request[daov1.RevokeKeyRequest],
) (*connect.Response[daov1.RevokeKeyResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)
	if err := s.keys.Revoke(req.Msg.KeyId, callerID); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&daov1.RevokeKeyResponse{}), nil
}

func (s *DaoServer) GetReputation(
	_ context.Context,
	req *connect.Request[daov1.GetReputationRequest],
) (*connect.Response[daov1.GetReputationResponse], error) {
	if _, ok := s.identities[req.Msg.IdentityId]; !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("identity %q not found", req.Msg.IdentityId))
	}
	return connect.NewResponse(&daov1.GetReputationResponse{
		Reputation: &daov1.ReputationScore{
			IdentityId:      req.Msg.IdentityId,
			Score:           100,
			TotalCalls:      0,
			SuccessfulCalls: 0,
		},
	}), nil
}

// --- helpers ---

func (s *DaoServer) callerIdentity(ctx context.Context) (*daov1.Identity, error) {
	callerID, _ := auth.IdentityFromContext(ctx)
	identity, ok := s.identities[callerID]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("identity not found"))
	}
	return identity, nil
}

func (s *DaoServer) requireGroupAccess(callerID, groupID string) error {
	// Owner of the group identity has access.
	group, ok := s.identities[groupID]
	if !ok {
		return connect.NewError(connect.CodeNotFound, fmt.Errorf("group %q not found", groupID))
	}
	if group.OwnerId == callerID {
		return nil
	}
	// Check membership with owner/admin role.
	for _, m := range s.memberships {
		if m.GroupId == groupID && m.IdentityId == callerID {
			if m.Role == "owner" || m.Role == "admin" {
				return nil
			}
		}
	}
	return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("not authorized"))
}

func main() {
	keys := auth.NewKeyRegistry()
	server := NewDaoServer(keys)
	mux := http.NewServeMux()

	path, handler := daov1connect.NewDaoServiceHandler(
		server,
		connect.WithInterceptors(auth.NewInterceptor(keys)),
	)
	mux.Handle(path, handler)

	addr := "localhost:8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = "localhost:" + port
	}

	log.Printf("dao.pub server listening on %s", addr)

	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)

	s := &http.Server{
		Addr:      addr,
		Handler:   mux,
		Protocols: p,
	}

	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
