package auth

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// Signer holds a private key and signs Connect requests.
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner creates a Signer from a private key.
func NewSigner(priv ed25519.PrivateKey) *Signer {
	return &Signer{priv: priv}
}

// Sign attaches auth headers (X-Dao-Timestamp, X-Dao-Signature) to a request.
func (s *Signer) Sign(req interface{ Header() http.Header }, procedure string) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	message := FormatSignMessage(ts, procedure)
	sig := ed25519.Sign(s.priv, message)
	req.Header().Set("X-Dao-Timestamp", ts)
	req.Header().Set("X-Dao-Signature", hex.EncodeToString(sig))
}
