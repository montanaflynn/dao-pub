package membership

import (
	"errors"
	"sync"
	"time"

	daov1 "dao.pub/gen/dao/v1"
)

// Role constants — only these are accepted by AddMember.
type Role string

const (
	RoleOwner    Role = "owner"
	RoleAdmin    Role = "admin"
	RoleMember   Role = "member"
	RoleOperator Role = "operator"
)

var validRoles = map[Role]bool{
	RoleOwner: true, RoleAdmin: true, RoleMember: true, RoleOperator: true,
}

var (
	ErrNotFound         = errors.New("membership not found")
	ErrPermissionDenied = errors.New("not authorized")
	ErrDuplicate        = errors.New("already a member")
	ErrUnknownRole      = errors.New("unknown role")
	ErrGroupNotFound    = errors.New("group not found")
)

// Members is the interface for group membership management.
type Members interface {
	AddMember(callerID, identityID, groupID string, role Role) (*daov1.Membership, error)
	RemoveMember(callerID, identityID, groupID string) error
	ListMembers(groupID string) []*daov1.Membership
	BootstrapOwner(identityID, groupID string) *daov1.Membership
	CanManage(callerID, groupID string) error
}

// IdentityLookup checks whether an identity exists and returns its owner ID.
type IdentityLookup func(id string) (ownerID string, exists bool)

// Registry is the in-memory Members implementation.
type Registry struct {
	mu      sync.RWMutex
	members map[string]map[string]*daov1.Membership // groupID -> identityID -> Membership
	lookup  IdentityLookup
}

// Compile-time check that Registry implements Members.
var _ Members = (*Registry)(nil)

// NewRegistry creates a Registry. The lookup function is used to check
// identity existence and ownership for authorization.
func NewRegistry(lookup IdentityLookup) *Registry {
	return &Registry{
		members: make(map[string]map[string]*daov1.Membership),
		lookup:  lookup,
	}
}

// AddMember adds identityID to groupID with role, authorized as callerID.
// Authorization and mutation are atomic under a single lock.
func (r *Registry) AddMember(callerID, identityID, groupID string, role Role) (*daov1.Membership, error) {
	if !validRoles[role] {
		return nil, ErrUnknownRole
	}
	if _, exists := r.lookup(identityID); !exists {
		return nil, ErrNotFound
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.checkAccess(callerID, groupID); err != nil {
		return nil, err
	}

	group := r.members[groupID]
	if group == nil {
		group = make(map[string]*daov1.Membership)
		r.members[groupID] = group
	}
	if _, exists := group[identityID]; exists {
		return nil, ErrDuplicate
	}

	m := &daov1.Membership{
		IdentityId: identityID,
		GroupId:    groupID,
		Role:       string(role),
		JoinedAt:   time.Now().Unix(),
	}
	group[identityID] = m
	return m, nil
}

// RemoveMember removes identityID from groupID, authorized as callerID.
// Authorization and mutation are atomic under a single lock.
func (r *Registry) RemoveMember(callerID, identityID, groupID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.checkAccess(callerID, groupID); err != nil {
		return err
	}

	group := r.members[groupID]
	if group == nil {
		return ErrNotFound
	}
	if _, exists := group[identityID]; !exists {
		return ErrNotFound
	}
	delete(group, identityID)
	return nil
}

// ListMembers returns all memberships for a group.
func (r *Registry) ListMembers(groupID string) []*daov1.Membership {
	r.mu.RLock()
	defer r.mu.RUnlock()

	group := r.members[groupID]
	result := make([]*daov1.Membership, 0, len(group))
	for _, m := range group {
		result = append(result, m)
	}
	return result
}

// BootstrapOwner adds identityID as owner of groupID with no authorization check.
// Use only for org creation when the creator is auto-added.
func (r *Registry) BootstrapOwner(identityID, groupID string) *daov1.Membership {
	r.mu.Lock()
	defer r.mu.Unlock()

	group := r.members[groupID]
	if group == nil {
		group = make(map[string]*daov1.Membership)
		r.members[groupID] = group
	}
	m := &daov1.Membership{
		IdentityId: identityID,
		GroupId:    groupID,
		Role:       string(RoleOwner),
		JoinedAt:   time.Now().Unix(),
	}
	group[identityID] = m
	return m
}

// CanManage reports whether callerID may add/remove members in groupID.
func (r *Registry) CanManage(callerID, groupID string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.checkAccess(callerID, groupID)
}

// checkAccess checks authorization. Caller must hold r.mu (read or write).
func (r *Registry) checkAccess(callerID, groupID string) error {
	ownerID, exists := r.lookup(groupID)
	if !exists {
		return ErrGroupNotFound
	}
	if ownerID == callerID {
		return nil
	}

	group := r.members[groupID]
	if group == nil {
		return ErrPermissionDenied
	}
	m, exists := group[callerID]
	if !exists {
		return ErrPermissionDenied
	}
	if m.Role == string(RoleOwner) || m.Role == string(RoleAdmin) {
		return nil
	}
	return ErrPermissionDenied
}
