package hax

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func sha256Sum(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

func TestSignerOmitsAuthorizationWithoutAPIKey(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	var capturedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"did":          identity.DID,
			"status":       "unknown",
			"heldAskCount": 0,
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		BaseURL: server.URL + "/api/v1",
		DID:     identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.GetKnockStatus("acme", "")
	if err != nil {
		t.Fatal(err)
	}

	if capturedHeaders.Get("Authorization") != "" {
		t.Fatal("Authorization header should not be present without API key")
	}
	if capturedHeaders.Get("X-HAX-DID") != identity.DID {
		t.Fatalf("expected X-HAX-DID %s, got %s", identity.DID, capturedHeaders.Get("X-HAX-DID"))
	}
	sig := capturedHeaders.Get("X-HAX-Signature")
	if strings.Count(sig, ".") != 2 {
		t.Fatalf("expected JWS with 2 dots, got %s", sig)
	}
}

func TestSignerIncludesBothWhenAPIKeyPresent(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	var capturedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "active"})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:       "hax_live_abc",
		BaseURL:      server.URL + "/api/v1",
		DID:          identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.GetKnockStatus("acme", "")
	if err != nil {
		t.Fatal(err)
	}

	if capturedHeaders.Get("Authorization") != "Bearer hax_live_abc" {
		t.Fatalf("expected Authorization Bearer hax_live_abc, got %s", capturedHeaders.Get("Authorization"))
	}
	if capturedHeaders.Get("X-HAX-DID") != identity.DID {
		t.Fatalf("expected X-HAX-DID, got %s", capturedHeaders.Get("X-HAX-DID"))
	}
}

func TestPostSendsExactSignedBytes(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	var capturedHeaders http.Header
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":        "req_1",
			"url":       "https://hax.example.com/hub/r/req_1",
			"type":      "text-approval-v1",
			"payload":   map[string]any{"text": "Approve?"},
			"status":    "pending",
			"createdAt": "2026-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		BaseURL: server.URL + "/api/v1",
		DID:     identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.CreateRequest(CreateRequestParams{
		Type:     "text-approval-v1",
		Payload:  map[string]any{"text": "Approve?"},
		Workspace: StringPtr("acme"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The body the JWS hashed must equal the bytes on the wire.
	jws := capturedHeaders.Get("X-HAX-Signature")
	parts := strings.Split(jws, ".")
	payload, err := decodeJWSPart(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256Sum(capturedBody)
	expectedBH := "sha256:" + b64url(digest)
	if payload["bh"] != expectedBH {
		t.Fatalf("bh mismatch: got %v, want %s", payload["bh"], expectedBH)
	}

	// htu carries the /api/v1 prefix; htm is the method.
	if payload["htu"] != "/api/v1/requests" {
		t.Fatalf("expected htu /api/v1/requests, got %v", payload["htu"])
	}
	if payload["htm"] != "POST" {
		t.Fatalf("expected htm POST, got %v", payload["htm"])
	}

	// And the signature itself verifies over header.payload.
	pub, err := DidKeyToPublicJWK(identity.DID)
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := b64urlDecode(pub["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	pubKey := ed25519.PublicKey(rawPub)
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
		t.Fatal("signature verification failed")
	}

	// The body actually contains the workspace addressing.
	var bodyMap map[string]any
	if err := json.Unmarshal(capturedBody, &bodyMap); err != nil {
		t.Fatal(err)
	}
	if bodyMap["workspace"] != "acme" {
		t.Fatalf("expected workspace acme in body, got %v", bodyMap["workspace"])
	}
}

func TestGetSignsOverEmptyBody(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	var capturedHeaders http.Header
	var capturedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		BaseURL: server.URL + "/api/v1",
		DID:     identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.GetKnockStatus("", "code123")
	if err != nil {
		t.Fatal(err)
	}

	if len(capturedBody) != 0 {
		t.Fatalf("expected empty body for GET, got %d bytes", len(capturedBody))
	}

	jws := capturedHeaders.Get("X-HAX-Signature")
	parts := strings.Split(jws, ".")
	payload, err := decodeJWSPart(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256Sum([]byte{})
	expectedBH := "sha256:" + b64url(digest)
	if payload["bh"] != expectedBH {
		t.Fatalf("empty body bh mismatch: got %v, want %s", payload["bh"], expectedBH)
	}
	if payload["htu"] != "/api/v1/knock/status" {
		t.Fatalf("expected htu /api/v1/knock/status, got %v", payload["htu"])
	}
	if payload["htm"] != "GET" {
		t.Fatalf("expected htm GET, got %v", payload["htm"])
	}
}

func TestGetIdentityReturnsDID(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(ClientOptions{
		BaseURL: "https://hax.example.com/api/v1",
		DID:     identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	id := client.GetIdentity()
	if id["did"] != identity.DID {
		t.Fatalf("expected did %s, got %v", identity.DID, id["did"])
	}
}

func TestClientMintsWithoutAuth(t *testing.T) {
	t.Setenv(identityFileEnv, "")
	defaultPath := filepath.Join(t.TempDir(), "minted.json")
	oldDefault := DefaultIdentityFile
	DefaultIdentityFile = defaultPath
	defer func() { DefaultIdentityFile = oldDefault }()

	client, err := NewClient(ClientOptions{
		BaseURL: "https://hax.example.com/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	id := client.GetIdentity()
	if id == nil {
		t.Fatal("expected minted identity")
	}
	if !strings.HasPrefix(id["did"].(string), "did:key:") {
		t.Fatalf("expected did:key, got %v", id["did"])
	}
}

func TestErrorStatusCodeMapping(t *testing.T) {
	tests := []struct {
		statusCode int
		check      func(error) bool
		name       string
	}{
		{401, func(e error) bool { _, ok := e.(*AuthenticationError); return ok }, "401->AuthenticationError"},
		{403, func(e error) bool { _, ok := e.(*ForbiddenError); return ok }, "403->ForbiddenError"},
		{404, func(e error) bool { _, ok := e.(*NotFoundError); return ok }, "404->NotFoundError"},
		{422, func(e error) bool { _, ok := e.(*ValidationError); return ok }, "422->ValidationError"},
		{429, func(e error) bool { _, ok := e.(*RateLimitError); return ok }, "429->RateLimitError"},
		{500, func(e error) bool { _, ok := e.(*ServerError); return ok }, "500->ServerError"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(map[string]any{"error": "nope"})
			}))
			defer server.Close()

			client, err := NewClient(ClientOptions{
				APIKey:  "test_key",
				BaseURL: server.URL + "/api/v1",
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			_, err = client.GetRequest("req_123")
			if err == nil {
				t.Fatal("expected error")
			}
			if !tt.check(err) {
				t.Fatalf("expected specific error type for %d, got %T: %v", tt.statusCode, err, err)
			}

			// Check status code is carried.
			haxErr, ok := err.(*HaxError)
			if !ok {
				// Try embedded HaxError
				switch e := err.(type) {
				case *AuthenticationError:
					haxErr = &e.HaxError
				case *ForbiddenError:
					haxErr = &e.HaxError
				case *NotFoundError:
					haxErr = &e.HaxError
				case *ValidationError:
					haxErr = &e.HaxError
				case *RateLimitError:
					haxErr = &e.HaxError
				case *ServerError:
					haxErr = &e.HaxError
				}
			}
			if haxErr == nil {
				t.Fatalf("could not extract HaxError from %T", err)
			}
			if haxErr.StatusCode != tt.statusCode {
				t.Fatalf("expected status code %d, got %d", tt.statusCode, haxErr.StatusCode)
			}
		})
	}
}

func TestForbiddenErrorCarriesCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "Sender is blocked",
			"details": map[string]any{"code": "sender_blocked"},
		})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.CreateRequest(CreateRequestParams{
		Type:    "text-approval-v1",
		Payload: map[string]any{"text": "hi"},
	})
	if err == nil {
		t.Fatal("expected error")
	}

	fe, ok := err.(*ForbiddenError)
	if !ok {
		t.Fatalf("expected *ForbiddenError, got %T", err)
	}
	if fe.Code != "sender_blocked" {
		t.Fatalf("expected code sender_blocked, got %s", fe.Code)
	}
	if fe.Message != "Sender is blocked" {
		t.Fatalf("expected message 'Sender is blocked', got %s", fe.Message)
	}
}

func TestUnmappedStatusFallsBackToHaxError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(418)
		json.NewEncoder(w).Encode(map[string]any{"error": "teapot"})
	}))
	defer server.Close()

	client, err := NewClient(ClientOptions{
		APIKey:  "test_key",
		BaseURL: server.URL + "/api/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.GetRequest("req_123")
	if err == nil {
		t.Fatal("expected error")
	}

	haxErr, ok := err.(*HaxError)
	if !ok {
		t.Fatalf("expected *HaxError, got %T", err)
	}
	if haxErr.StatusCode != 418 {
		t.Fatalf("expected status code 418, got %d", haxErr.StatusCode)
	}
}
