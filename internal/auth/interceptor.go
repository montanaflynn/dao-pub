package auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"connectrpc.com/connect"
)

type contextKey struct{}

// Verifier resolves a signature to an identity ID.
type Verifier interface {
	Verify(message, signature []byte) (identityID string, err error)
}

// IdentityFromContext returns the authenticated identity ID from the context.
func IdentityFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(contextKey{}).(string)
	return id, ok
}

// publicProcedures that don't require authentication.
var publicProcedures = map[string]bool{
	"/dao.v1.DaoService/Ping":     true,
	"/dao.v1.DaoService/Register": true,
}

// NewInterceptor returns a Connect interceptor that validates Ed25519 signatures.
func NewInterceptor(v Verifier) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if publicProcedures[req.Spec().Procedure] {
				return next(ctx, req)
			}

			tsHeader := req.Header().Get("X-Dao-Timestamp")
			sigHeader := req.Header().Get("X-Dao-Signature")

			if tsHeader == "" || sigHeader == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing auth headers"))
			}

			ts, err := strconv.ParseInt(tsHeader, 10, 64)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid timestamp"))
			}
			diff := time.Now().Unix() - ts
			if diff < 0 {
				diff = -diff
			}
			if diff > 30 {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("timestamp too old"))
			}

			sig, err := hex.DecodeString(sigHeader)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid signature encoding"))
			}

			message := FormatSignMessage(tsHeader, req.Spec().Procedure)
			identityID, err := v.Verify(message, sig)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}

			ctx = context.WithValue(ctx, contextKey{}, identityID)
			return next(ctx, req)
		}
	}
}

// FormatSignMessage builds the message that must be signed.
func FormatSignMessage(timestamp, procedure string) []byte {
	return []byte(fmt.Sprintf("%s:%s", timestamp, procedure))
}
