package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	daov1 "dao.pub/gen/dao/v1"
	"dao.pub/gen/dao/v1/daov1connect"
	"dao.pub/internal/auth"
	"dao.pub/internal/identity"
	"dao.pub/internal/membership"

	"connectrpc.com/connect"
)

type DaoServer struct {
	identities map[string]*daov1.Identity
	members    *membership.Registry
	keys       *auth.KeyRegistry
}

func NewDaoServer(keys *auth.KeyRegistry) *DaoServer {
	s := &DaoServer{
		identities: make(map[string]*daov1.Identity),
		keys:       keys,
	}
	s.members = membership.NewRegistry(func(id string) (string, bool) {
		ident, ok := s.identities[id]
		if !ok {
			return "", false
		}
		return ident.OwnerId, true
	})
	return s
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
	if err := identity.ValidateEd25519Key(req.Msg.PublicKey); err != nil {
		return nil, err
	}

	id, err := identity.NewUser(req.Msg.Name, req.Msg.Github)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.identities[id.Id] = id

	label := req.Msg.KeyLabel
	if label == "" {
		label = "default"
	}
	pk := s.keys.Add(id.Id, label, req.Msg.PublicKey)

	log.Printf("registered user: %s (%s)", id.Name, id.Id)
	return connect.NewResponse(&daov1.RegisterResponse{
		Identity: id,
		Key:      pk,
	}), nil
}

func (s *DaoServer) WhoAmI(
	ctx context.Context,
	_ *connect.Request[daov1.WhoAmIRequest],
) (*connect.Response[daov1.WhoAmIResponse], error) {
	ident, err := s.callerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&daov1.WhoAmIResponse{
		Identity: ident,
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

	opts := []identity.Option{
		identity.WithDescription(req.Msg.Description),
		identity.WithMeta(req.Msg.Meta),
	}

	var (
		id  *daov1.Identity
		err error
	)
	switch req.Msg.Kind {
	case daov1.IdentityKind_IDENTITY_KIND_AGENT:
		id, err = identity.NewAgent(req.Msg.Name, callerID, opts...)
	case daov1.IdentityKind_IDENTITY_KIND_ORG:
		id, err = identity.NewOrg(req.Msg.Name, callerID, opts...)
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("unsupported kind: %v", req.Msg.Kind))
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	s.identities[id.Id] = id

	// Register the public key if provided.
	var pk *daov1.PublicKey
	if err := identity.ValidateEd25519Key(req.Msg.PublicKey); err == nil {
		pk = s.keys.Add(id.Id, "default", req.Msg.PublicKey)
	}

	kindName := "agent"
	if req.Msg.Kind == daov1.IdentityKind_IDENTITY_KIND_ORG {
		kindName = "org"
		s.members.BootstrapOwner(callerID, id.Id)
	}

	log.Printf("created %s: %s (%s) owned by %s", kindName, id.Name, id.Id, callerID)
	return connect.NewResponse(&daov1.CreateIdentityResponse{
		Identity: id,
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
	ident, ok := s.identities[req.Msg.Id]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("identity %q not found", req.Msg.Id))
	}
	return connect.NewResponse(&daov1.GetIdentityResponse{
		Identity: ident,
	}), nil
}

func (s *DaoServer) AddMember(
	ctx context.Context,
	req *connect.Request[daov1.AddMemberRequest],
) (*connect.Response[daov1.AddMemberResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)

	role := membership.Role(req.Msg.Role)
	if role == "" {
		role = membership.RoleMember
	}

	m, err := s.members.AddMember(callerID, req.Msg.MemberId, req.Msg.GroupId, role)
	if err != nil {
		return nil, membershipError(err)
	}

	log.Printf("added member %s to %s as %s", req.Msg.MemberId, req.Msg.GroupId, role)
	return connect.NewResponse(&daov1.AddMemberResponse{
		Membership: m,
	}), nil
}

func (s *DaoServer) ListMembers(
	_ context.Context,
	req *connect.Request[daov1.ListMembersRequest],
) (*connect.Response[daov1.ListMembersResponse], error) {
	return connect.NewResponse(&daov1.ListMembersResponse{
		Members: s.members.ListMembers(req.Msg.GroupId),
	}), nil
}

func (s *DaoServer) RemoveMember(
	ctx context.Context,
	req *connect.Request[daov1.RemoveMemberRequest],
) (*connect.Response[daov1.RemoveMemberResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)

	if err := s.members.RemoveMember(callerID, req.Msg.MemberId, req.Msg.GroupId); err != nil {
		return nil, membershipError(err)
	}

	log.Printf("removed member %s from %s", req.Msg.MemberId, req.Msg.GroupId)
	return connect.NewResponse(&daov1.RemoveMemberResponse{}), nil
}

func (s *DaoServer) AddKey(
	ctx context.Context,
	req *connect.Request[daov1.AddKeyRequest],
) (*connect.Response[daov1.AddKeyResponse], error) {
	callerID, _ := auth.IdentityFromContext(ctx)
	if err := identity.ValidateEd25519Key(req.Msg.PublicKey); err != nil {
		return nil, err
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
	ident, ok := s.identities[callerID]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("identity not found"))
	}
	return ident, nil
}

// membershipError maps membership sentinel errors to connect errors.
func membershipError(err error) error {
	switch {
	case errors.Is(err, membership.ErrPermissionDenied):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, membership.ErrNotFound), errors.Is(err, membership.ErrGroupNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, membership.ErrDuplicate):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, membership.ErrUnknownRole):
		return connect.NewError(connect.CodeInvalidArgument, err)
	default:
		return connect.NewError(connect.CodeInternal, err)
	}
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
