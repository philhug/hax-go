package hax

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func TestB64urlRoundtripNoPadding(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 'h', 'e', 'l', 'l', 'o', '-', 'w', 'o', 'r', 'l', 'd', 0xff, 0xfe}
	encoded := b64url(data)
	if strings.Contains(encoded, "=") {
		t.Fatalf("encoded should not contain padding: %s", encoded)
	}
	decoded, err := b64urlDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(data) {
		t.Fatalf("roundtrip mismatch: got %v, want %v", decoded, data)
	}
}

func TestBase58Roundtrip(t *testing.T) {
	data := make([]byte, 40)
	for i := range data {
		data[i] = byte(i)
	}
	encoded := base58btcEncode(data)
	decoded, err := base58btcDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(data) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestBase58LeadingZerosMapToOnes(t *testing.T) {
	data := []byte{0x00, 0x00, 0x01, 0x02}
	encoded := base58btcEncode(data)
	if !strings.HasPrefix(encoded, "11") {
		t.Fatalf("expected leading '11' for leading zeros, got %s", encoded)
	}
	decoded, err := base58btcDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(data) {
		t.Fatalf("roundtrip mismatch for leading zeros")
	}
}

func TestBase58KnownVector(t *testing.T) {
	encoded := base58btcEncode([]byte("Hello World!"))
	if encoded != "2NEpo7TZRRrLZSi2U" {
		t.Fatalf("known vector mismatch: got %s, want 2NEpo7TZRRrLZSi2U", encoded)
	}
}

func TestDidKeyRoundtrip(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(identity.DID, "did:key:z6Mk") {
		t.Fatalf("DID should start with did:key:z6Mk, got %s", identity.DID)
	}

	pubJWK, err := DidKeyToPublicJWK(identity.DID)
	if err != nil {
		t.Fatal(err)
	}

	// The recovered public JWK must re-encode to the same DID.
	reencoded, err := DidKeyFromPublicJWK(pubJWK)
	if err != nil {
		t.Fatal(err)
	}
	if reencoded != identity.DID {
		t.Fatalf("DID roundtrip mismatch: got %s, want %s", reencoded, identity.DID)
	}

	// And it must match the public half of the generated private JWK.
	if pubJWK["x"] != identity.PrivateKeyJWK["x"] {
		t.Fatalf("public key mismatch")
	}
}

func TestFingerprintFormat(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := DidFingerprint(identity.PrivateKeyJWK)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(fp, ":")
	if len(parts) != 8 {
		t.Fatalf("expected 8 parts, got %d", len(parts))
	}
	for _, p := range parts {
		if len(p) != 2 {
			t.Fatalf("each part should be 2 chars, got %s", p)
		}
	}
}

func TestFingerprintMatchesSHA256(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := b64urlDecode(identity.PrivateKeyJWK["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(rawPub)
	expected := make([]string, 8)
	for i, b := range digest[:8] {
		expected[i] = strings.ToLower(formatHex(b))
	}
	expectedStr := strings.Join(expected, ":")

	fp, err := DidFingerprint(identity.PrivateKeyJWK)
	if err != nil {
		t.Fatal(err)
	}
	if fp != expectedStr {
		t.Fatalf("fingerprint mismatch: got %s, want %s", fp, expectedStr)
	}
}

func formatHex(b byte) string {
	const hexDigits = "0123456789abcdef"
	return string([]byte{hexDigits[b>>4], hexDigits[b&0xf]})
}

func decodeJWSPart(part string) (map[string]any, error) {
	raw, err := b64urlDecode(part)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func TestJWSStructureAndClaims(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"workspace":"acme"}`)
	jws, err := SignKnockJWS(SignKnockJWSOptions{
		DID:           identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
		HTM:           "POST",
		HTU:           "/api/v1/requests",
		RawBody:       body,
		IAT:           1700000000,
		JTI:           "fixed-jti",
	})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	for _, p := range parts {
		if p == "" {
			t.Fatalf("all parts should be non-empty")
		}
	}

	header, err := decodeJWSPart(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	payload, err := decodeJWSPart(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	// Header: kid suffix for did:key is the part after "did:key:".
	expectedKID := identity.DID + "#" + identity.DID[len(didKeyPrefix):]
	if header["alg"] != "EdDSA" {
		t.Fatalf("expected alg EdDSA, got %v", header["alg"])
	}
	if header["kid"] != expectedKID {
		t.Fatalf("expected kid %s, got %v", expectedKID, header["kid"])
	}

	// Payload claims.
	if payload["iat"] != float64(1700000000) {
		t.Fatalf("expected iat 1700000000, got %v", payload["iat"])
	}
	if payload["jti"] != "fixed-jti" {
		t.Fatalf("expected jti fixed-jti, got %v", payload["jti"])
	}
	if payload["htm"] != "POST" {
		t.Fatalf("expected htm POST, got %v", payload["htm"])
	}
	if payload["htu"] != "/api/v1/requests" {
		t.Fatalf("expected htu /api/v1/requests, got %v", payload["htu"])
	}
}

func TestJWSBhIsSHA256OfBody(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"hello":"world"}`)
	jws, err := SignKnockJWS(SignKnockJWSOptions{
		DID:           identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
		HTM:           "POST",
		HTU:           "/api/v1/requests",
		RawBody:       body,
	})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jws, ".")
	payload, err := decodeJWSPart(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(body)
	expected := "sha256:" + b64url(digest[:])
	if payload["bh"] != expected {
		t.Fatalf("bh mismatch: got %v, want %s", payload["bh"], expected)
	}
}

func TestJWSEmptyBodyHash(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	jws, err := SignKnockJWS(SignKnockJWSOptions{
		DID:           identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
		HTM:           "GET",
		HTU:           "/api/v1/knock/status",
		RawBody:       []byte{},
	})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jws, ".")
	payload, err := decodeJWSPart(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte{})
	expected := "sha256:" + b64url(digest[:])
	if payload["bh"] != expected {
		t.Fatalf("empty body bh mismatch: got %v, want %s", payload["bh"], expected)
	}
}

func TestJWSSignatureVerifies(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"workspace":"acme"}`)
	jws, err := SignKnockJWS(SignKnockJWSOptions{
		DID:           identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
		HTM:           "POST",
		HTU:           "/api/v1/requests",
		RawBody:       body,
	})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jws, ".")
	signingInput := parts[0] + "." + parts[1]

	pubJWK, err := DidKeyToPublicJWK(identity.DID)
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := b64urlDecode(pubJWK["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	pubKey := ed25519.PublicKey(rawPub)

	sig, err := b64urlDecode(parts[2])
	if err != nil {
		t.Fatal(err)
	}

	if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
		t.Fatal("signature verification failed")
	}
}

func TestJWSSignatureFailsOnTamperedBody(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	jws, err := SignKnockJWS(SignKnockJWSOptions{
		DID:           identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
		HTM:           "POST",
		HTU:           "/api/v1/requests",
		RawBody:       []byte(`{"workspace":"acme"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jws, ".")
	tampered := parts[0] + "." + parts[1] + "X"

	pubJWK, err := DidKeyToPublicJWK(identity.DID)
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := b64urlDecode(pubJWK["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	pubKey := ed25519.PublicKey(rawPub)

	sig, err := b64urlDecode(parts[2])
	if err != nil {
		t.Fatal(err)
	}

	if ed25519.Verify(pubKey, []byte(tampered), sig) {
		t.Fatal("signature should not verify on tampered input")
	}
}
