package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	daov1 "dao.pub/gen/dao/v1"
	"connectrpc.com/connect"
)

// Option configures optional identity fields.
type Option func(*buildOpts)

type buildOpts struct {
	Description string
	Meta        map[string]string
}

func WithDescription(d string) Option { return func(o *buildOpts) { o.Description = d } }
func WithMeta(m map[string]string) Option  { return func(o *buildOpts) { o.Meta = m } }

// NewHuman creates a human user identity. Humans have no owner.
func NewHuman(name, github string) (*daov1.Identity, error) {
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	return &daov1.Identity{
		Id:        id,
		Kind:      daov1.IdentityKind_IDENTITY_KIND_USER,
		UserType:  daov1.UserType_USER_TYPE_HUMAN,
		Name:      name,
		Github:    github,
		CreatedAt: time.Now().Unix(),
	}, nil
}

// NewAgent creates an agent user identity owned by ownerID.
func NewAgent(name, ownerID string, opts ...Option) (*daov1.Identity, error) {
	var o buildOpts
	for _, fn := range opts {
		fn(&o)
	}
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	return &daov1.Identity{
		Id:          id,
		Kind:        daov1.IdentityKind_IDENTITY_KIND_USER,
		UserType:    daov1.UserType_USER_TYPE_AGENT,
		Name:        name,
		Description: o.Description,
		OwnerId:     ownerID,
		CreatedAt:   time.Now().Unix(),
		Meta:        o.Meta,
	}, nil
}

// NewOrg creates an org identity owned by ownerID.
func NewOrg(name, ownerID string, opts ...Option) (*daov1.Identity, error) {
	var o buildOpts
	for _, fn := range opts {
		fn(&o)
	}
	id, err := generateID()
	if err != nil {
		return nil, err
	}
	return &daov1.Identity{
		Id:          id,
		Kind:        daov1.IdentityKind_IDENTITY_KIND_ORG,
		Name:        name,
		Description: o.Description,
		OwnerId:     ownerID,
		CreatedAt:   time.Now().Unix(),
		Meta:        o.Meta,
	}, nil
}

// ValidateEd25519Key returns a connect-compatible error if key is not a valid ed25519 public key.
func ValidateEd25519Key(key []byte) error {
	if len(key) != ed25519.PublicKeySize {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid ed25519 public key"))
	}
	return nil
}

func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("id_%x", b), nil
}
