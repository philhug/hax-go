package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	hax "github.com/philhug/hax-go"
)

// readRandom fills b with random bytes.
func readRandom(b []byte) (int, error) {
	return rand.Read(b)
}

// authInfo holds the authenticated identity for a request.
type authInfo struct {
	Method string // "apikey" or "did"
	DID    string // set when Method == "did"
}

// verifyAuth checks the Authorization header (API key) or X-HAX-DID /
// X-HAX-Signature headers (DID JWS). At least one must be valid.
func (s *Server) verifyAuth(r *http.Request) (*authInfo, []byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read request body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// 1. API key auth.
	if auth := r.Header.Get("Authorization"); auth != "" {
		const prefix = "Bearer "
		if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
			token := auth[len(prefix):]
			if s.config.APIKey != "" && token == s.config.APIKey {
				return &authInfo{Method: "apikey"}, body, nil
			}
		}
	}

	// 2. DID JWS auth.
	did := r.Header.Get("X-HAX-DID")
	sig := r.Header.Get("X-HAX-Signature")
	if did != "" && sig != "" {
		if err := hax.VerifyKnockJWS(sig, did); err != nil {
			return nil, body, fmt.Errorf("invalid JWS signature: %w", err)
		}
		payload, err := hax.DecodeJWSPayload(sig)
		if err != nil {
			return nil, body, fmt.Errorf("failed to decode JWS payload: %w", err)
		}
		if err := verifyJWSPayload(payload, r.Method, r.URL.Path, body); err != nil {
			return nil, body, err
		}
		return &authInfo{Method: "did", DID: did}, body, nil
	}

	// No valid auth.
	if s.config.APIKey != "" {
		return nil, body, fmt.Errorf("authentication required: provide a valid API key or DID signature")
	}
	return nil, body, fmt.Errorf("authentication required: provide a DID signature")
}

// verifyJWSPayload checks that the JWS claims match the actual request.
func verifyJWSPayload(payload map[string]any, method, path string, body []byte) error {
	if htm, ok := payload["htm"].(string); ok && htm != method {
		return fmt.Errorf("JWS htm mismatch: expected %s, got %s", method, htm)
	}
	if htu, ok := payload["htu"].(string); ok && htu != path {
		return fmt.Errorf("JWS htu mismatch: expected %s, got %s", path, htu)
	}
	if bh, ok := payload["bh"].(string); ok {
		computed := bodyHash(body)
		if bh != computed {
			return fmt.Errorf("JWS body hash mismatch")
		}
	}
	return nil
}

// bodyHash mirrors the SDK's bodyHash function: "sha256:<base64url(sha256(body))>".
func bodyHash(rawBody []byte) string {
	digest := sha256.Sum256(rawBody)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:])
}
