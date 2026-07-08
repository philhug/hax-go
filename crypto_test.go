package hax

import (
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

func TestGenerateKeyPairStructure(t *testing.T) {
	pub, priv, err := GenerateKeyPair("test-passphrase")
	if err != nil {
		t.Fatal(err)
	}

	// Check public key structure.
	if pub["kty"] != "RSA" {
		t.Fatalf("expected kty RSA, got %v", pub["kty"])
	}
	if pub["alg"] != "RSA-OAEP-256" {
		t.Fatalf("expected alg RSA-OAEP-256, got %v", pub["alg"])
	}
	if pub["use"] != "enc" {
		t.Fatalf("expected use enc, got %v", pub["use"])
	}
	if pub["n"] == nil || pub["n"] == "" {
		t.Fatal("expected non-empty n")
	}
	if pub["e"] == nil || pub["e"] == "" {
		t.Fatal("expected non-empty e")
	}

	// Check private key structure.
	if priv["kty"] != "RSA" {
		t.Fatalf("expected kty RSA, got %v", priv["kty"])
	}
	for _, key := range []string{"n", "e", "d", "p", "q", "dp", "dq", "qi"} {
		if priv[key] == nil || priv[key] == "" {
			t.Fatalf("expected non-empty %s in private key", key)
		}
	}
}

func TestDeterministicKeyGeneration(t *testing.T) {
	pub1, priv1, err := GenerateKeyPair("same-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := GenerateKeyPair("same-passphrase")
	if err != nil {
		t.Fatal(err)
	}

	if pub1["n"] != pub2["n"] {
		t.Fatal("same passphrase should produce same modulus")
	}
	if pub1["e"] != pub2["e"] {
		t.Fatal("same passphrase should produce same exponent")
	}
	if priv1["d"] != priv2["d"] {
		t.Fatal("same passphrase should produce same private exponent")
	}
}

func TestDifferentPassphrasesDifferentKeys(t *testing.T) {
	pub1, _, err := GenerateKeyPair("passphrase-1")
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateKeyPair("passphrase-2")
	if err != nil {
		t.Fatal(err)
	}

	if pub1["n"] == pub2["n"] {
		t.Fatal("different passphrases should produce different keys")
	}
}

func TestEmptyPassphrase(t *testing.T) {
	pub, priv, err := GenerateKeyPair("")
	if err != nil {
		t.Fatal(err)
	}
	if pub["kty"] != "RSA" || priv["kty"] != "RSA" {
		t.Fatal("empty passphrase should still produce valid keypair")
	}
}

func TestUnicodePassphrase(t *testing.T) {
	pub, priv, err := GenerateKeyPair("日本語パスフレーズ🔐")
	if err != nil {
		t.Fatal(err)
	}
	if pub["kty"] != "RSA" || priv["kty"] != "RSA" {
		t.Fatal("unicode passphrase should produce valid keypair")
	}
}

func TestPublicExponentIs65537(t *testing.T) {
	pub, _, err := GenerateKeyPair("test")
	if err != nil {
		t.Fatal(err)
	}
	// 65537 = AQAB in base64url
	if pub["e"] != "AQAB" {
		t.Fatalf("expected exponent AQAB, got %v", pub["e"])
	}
}

func TestModulusIs2048Bits(t *testing.T) {
	pub, _, err := GenerateKeyPair("test")
	if err != nil {
		t.Fatal(err)
	}
	n, err := base64urlToBigint(pub["n"].(string))
	if err != nil {
		t.Fatal(err)
	}
	bitLen := n.BitLen()
	if bitLen < 2040 || bitLen > 2048 {
		t.Fatalf("expected 2040-2048 bit modulus, got %d", bitLen)
	}
}

func TestDecryptDictData(t *testing.T) {
	pub, priv, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	original := map[string]any{"message": "Hello, World!", "count": float64(42)}

	encrypted, err := EncryptWithPublicKey(original, pub)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptResponse(encrypted, priv)
	if err != nil {
		t.Fatal(err)
	}

	dm, ok := decrypted.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", decrypted)
	}
	if dm["message"] != "Hello, World!" {
		t.Fatalf("message mismatch: got %v", dm["message"])
	}
	if dm["count"] != float64(42) {
		t.Fatalf("count mismatch: got %v", dm["count"])
	}
}

func TestDecryptStringData(t *testing.T) {
	pub, priv, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptWithPublicKey("Just a string", pub)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptResponse(encrypted, priv)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != "Just a string" {
		t.Fatalf("expected 'Just a string', got %v", decrypted)
	}
}

func TestDecryptListData(t *testing.T) {
	pub, priv, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	original := []any{float64(1), float64(2), float64(3), map[string]any{"nested": true}}
	encrypted, err := EncryptWithPublicKey(original, pub)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptResponse(encrypted, priv)
	if err != nil {
		t.Fatal(err)
	}
	dl, ok := decrypted.([]any)
	if !ok {
		t.Fatalf("expected []any, got %T", decrypted)
	}
	if len(dl) != 4 {
		t.Fatalf("expected 4 elements, got %d", len(dl))
	}
}

func TestDecryptNull(t *testing.T) {
	pub, priv, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptWithPublicKey(nil, pub)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptResponse(encrypted, priv)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != nil {
		t.Fatalf("expected nil, got %v", decrypted)
	}
}

func TestDecryptBoolean(t *testing.T) {
	pub, priv, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}

	encTrue, err := EncryptWithPublicKey(true, pub)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecryptResponse(encTrue, priv)
	if err != nil {
		t.Fatal(err)
	}
	if d != true {
		t.Fatalf("expected true, got %v", d)
	}

	encFalse, err := EncryptWithPublicKey(false, pub)
	if err != nil {
		t.Fatal(err)
	}
	d, err = DecryptResponse(encFalse, priv)
	if err != nil {
		t.Fatal(err)
	}
	if d != false {
		t.Fatalf("expected false, got %v", d)
	}
}

func TestDecryptNumber(t *testing.T) {
	pub, priv, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptWithPublicKey(float64(42), pub)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptResponse(encrypted, priv)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted != float64(42) {
		t.Fatalf("expected 42, got %v", decrypted)
	}
}

func TestDecryptUnicodeData(t *testing.T) {
	pub, priv, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	original := map[string]any{"emoji": "🔐", "japanese": "暗号化", "arabic": "تشفير"}
	encrypted, err := EncryptWithPublicKey(original, pub)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptResponse(encrypted, priv)
	if err != nil {
		t.Fatal(err)
	}
	dm := decrypted.(map[string]any)
	if dm["emoji"] != "🔐" {
		t.Fatalf("emoji mismatch: got %v", dm["emoji"])
	}
}

func TestWrongKeyFails(t *testing.T) {
	pub, _, err := GenerateKeyPair("key-1")
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPriv, err := GenerateKeyPair("key-2")
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := EncryptWithPublicKey(map[string]any{"secret": true}, pub)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptResponse(encrypted, wrongPriv)
	if err == nil {
		t.Fatal("expected decryption error with wrong key")
	}
	if !strings.Contains(err.Error(), "wrong key or corrupted") {
		t.Fatalf("expected 'wrong key' error, got: %v", err)
	}
}

func TestInvalidBase64Fails(t *testing.T) {
	_, priv, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptResponse("not-valid-base64!!!", priv)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestCorruptedCiphertextFails(t *testing.T) {
	pub, priv, err := GenerateKeyPair("test-key")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptWithPublicKey(map[string]any{"test": true}, pub)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the ciphertext (replace last 4 chars).
	corrupted := encrypted[:len(encrypted)-4] + "XXXX"
	_, err = DecryptResponse(corrupted, priv)
	if err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
}

func TestIsEncryptedResponseEncryptedWrapper(t *testing.T) {
	pub, _, err := GenerateKeyPair("key")
	if err != nil {
		t.Fatal(err)
	}
	wrapper, err := EncryptWithPublicKey(map[string]any{"test": true}, pub)
	if err != nil {
		t.Fatal(err)
	}
	wrapperMap := map[string]any{"_encrypted": wrapper}
	if !IsEncryptedResponse(wrapperMap) {
		t.Fatal("expected encrypted wrapper to be detected")
	}
}

func TestIsEncryptedResponsePlainDict(t *testing.T) {
	if IsEncryptedResponse(map[string]any{"test": true}) {
		t.Fatal("plain dict should not be detected as encrypted")
	}
	if IsEncryptedResponse(map[string]any{"name": "Alice"}) {
		t.Fatal("plain dict should not be detected as encrypted")
	}
}

func TestIsEncryptedResponseWithoutKey(t *testing.T) {
	if IsEncryptedResponse(map[string]any{"other_key": "value"}) {
		t.Fatal("dict without _encrypted key should not be detected")
	}
}

func TestIsEncryptedResponseWrongType(t *testing.T) {
	if IsEncryptedResponse(map[string]any{"_encrypted": 123}) {
		t.Fatal("integer _encrypted should not be detected")
	}
	if IsEncryptedResponse(map[string]any{"_encrypted": nil}) {
		t.Fatal("nil _encrypted should not be detected")
	}
	if IsEncryptedResponse(map[string]any{"_encrypted": []any{"list"}}) {
		t.Fatal("list _encrypted should not be detected")
	}
}

func TestIsEncryptedResponseNonDict(t *testing.T) {
	if IsEncryptedResponse(nil) {
		t.Fatal("nil should not be detected")
	}
	if IsEncryptedResponse("string") {
		t.Fatal("string should not be detected")
	}
	if IsEncryptedResponse(123) {
		t.Fatal("int should not be detected")
	}
	if IsEncryptedResponse([]any{1, 2, 3}) {
		t.Fatal("list should not be detected")
	}
}

func TestIsEncryptedResponseInvalidBase64(t *testing.T) {
	if IsEncryptedResponse(map[string]any{"_encrypted": "not-valid-base64!!!"}) {
		t.Fatal("invalid base64 should not be detected")
	}
}

func TestIsEncryptedResponseTooShort(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	if IsEncryptedResponse(map[string]any{"_encrypted": short}) {
		t.Fatal("too short base64 should not be detected")
	}
}

func TestRoundtripEncryptionDecryption(t *testing.T) {
	pub, priv, err := GenerateKeyPair("my-secret-passphrase")
	if err != nil {
		t.Fatal(err)
	}

	original := map[string]any{"action": "approve", "details": map[string]any{"amount": float64(1000)}}
	encrypted, err := EncryptWithPublicKey(original, pub)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptResponse(encrypted, priv)
	if err != nil {
		t.Fatal(err)
	}

	dm := decrypted.(map[string]any)
	if dm["action"] != "approve" {
		t.Fatalf("action mismatch: got %v", dm["action"])
	}
}

func TestJWKToRSAPrivateKey(t *testing.T) {
	_, priv, err := GenerateKeyPair("test")
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := jwkToRSAPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if rsaKey.N.BitLen() < 2040 {
		t.Fatalf("expected 2048-bit key, got %d", rsaKey.N.BitLen())
	}
}

func TestBase64urlToBigintRoundtrip(t *testing.T) {
	n := big.NewInt(65537)
	encoded := bigintToBase64url(n)
	decoded, err := base64urlToBigint(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Cmp(n) != 0 {
		t.Fatalf("roundtrip mismatch: got %d, want %d", decoded, n)
	}
}
