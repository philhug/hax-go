package hax

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeIdentityFile(t *testing.T, path string, did string, jwk map[string]any) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{
		"did":           did,
		"privateKeyJwk": jwk,
		"createdAt":      "2026-01-01T00:00:00.000Z",
	})
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSaveIdentityWritesCamelCase(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "nested", "identity.json")

	if err := SaveIdentity(identity, target); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}

	if payload["did"] != identity.DID {
		t.Fatalf("expected did %s, got %v", identity.DID, payload["did"])
	}
	if payload["privateKeyJwk"] == nil {
		t.Fatal("expected privateKeyJwk")
	}
	if payload["createdAt"] == nil {
		t.Fatal("expected createdAt")
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %v", info.Mode().Perm())
	}
}

func TestLoadIdentityExplicitDIDAndJWK(t *testing.T) {
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := LoadIdentity(LoadIdentityOptions{
		DID:           identity.DID,
		PrivateKeyJWK: identity.PrivateKeyJWK,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil {
		t.Fatal("expected non-nil identity")
	}
	if resolved.DID != identity.DID {
		t.Fatalf("DID mismatch")
	}
}

func TestLoadIdentityExplicitFileOverEnv(t *testing.T) {
	fileID, _ := GenerateIdentity()
	envID, _ := GenerateIdentity()
	filePath := filepath.Join(t.TempDir(), "file.json")
	envPath := filepath.Join(t.TempDir(), "env.json")
	writeIdentityFile(t, filePath, fileID.DID, fileID.PrivateKeyJWK)
	writeIdentityFile(t, envPath, envID.DID, envID.PrivateKeyJWK)

	t.Setenv(identityFileEnv, envPath)

	resolved, err := LoadIdentity(LoadIdentityOptions{
		IdentityFile: filePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil || resolved.DID != fileID.DID {
		t.Fatalf("expected file identity to win, got %v", resolved)
	}
}

func TestLoadIdentityEnvFileUsedWhenNoExplicit(t *testing.T) {
	envID, _ := GenerateIdentity()
	envPath := filepath.Join(t.TempDir(), "env.json")
	writeIdentityFile(t, envPath, envID.DID, envID.PrivateKeyJWK)

	t.Setenv(identityFileEnv, envPath)
	// Point default at non-existent path.
	oldDefault := DefaultIdentityFile
	DefaultIdentityFile = filepath.Join(t.TempDir(), "nope.json")
	defer func() { DefaultIdentityFile = oldDefault }()

	resolved, err := LoadIdentity(LoadIdentityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil || resolved.DID != envID.DID {
		t.Fatalf("expected env identity, got %v", resolved)
	}
}

func TestLoadIdentityMintWhenNothingResolves(t *testing.T) {
	t.Setenv(identityFileEnv, "")
	defaultPath := filepath.Join(t.TempDir(), "minted.json")
	oldDefault := DefaultIdentityFile
	DefaultIdentityFile = defaultPath
	defer func() { DefaultIdentityFile = oldDefault }()

	// No mint -> nil
	resolved, err := LoadIdentity(LoadIdentityOptions{AllowMint: false})
	if err != nil {
		t.Fatal(err)
	}
	if resolved != nil {
		t.Fatal("expected nil when no source and no mint")
	}

	// Mint -> identity
	resolved, err = LoadIdentity(LoadIdentityOptions{AllowMint: true})
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil {
		t.Fatal("expected minted identity")
	}
	if len(resolved.DID) == 0 || resolved.DID[0] != 'd' {
		t.Fatalf("expected valid DID, got %s", resolved.DID)
	}

	// File should exist with 0600.
	info, err := os.Stat(defaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600, got %v", info.Mode().Perm())
	}
}

func TestLoadIdentityMintPersistsToEnvPath(t *testing.T) {
	envPath := filepath.Join(t.TempDir(), "custom", "id.json")
	t.Setenv(identityFileEnv, envPath)
	defaultPath := filepath.Join(t.TempDir(), "default.json")
	oldDefault := DefaultIdentityFile
	DefaultIdentityFile = defaultPath
	defer func() { DefaultIdentityFile = oldDefault }()

	resolved, err := LoadIdentity(LoadIdentityOptions{AllowMint: true})
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil {
		t.Fatal("expected minted identity")
	}

	if _, err := os.Stat(envPath); err != nil {
		t.Fatal("minted identity should be at env path")
	}
	if _, err := os.Stat(defaultPath); err == nil {
		t.Fatal("minted identity should NOT be at default path")
	}

	// Re-resolving (no mint) finds the same identity via the env path.
	resolved2, err := LoadIdentity(LoadIdentityOptions{AllowMint: false})
	if err != nil {
		t.Fatal(err)
	}
	if resolved2 == nil || resolved2.DID != resolved.DID {
		t.Fatalf("re-resolved identity should match")
	}
}

func TestLoadIdentityDefaultFileUsedWhenPresent(t *testing.T) {
	t.Setenv(identityFileEnv, "")
	ident, _ := GenerateIdentity()
	defaultPath := filepath.Join(t.TempDir(), "identity.json")
	writeIdentityFile(t, defaultPath, ident.DID, ident.PrivateKeyJWK)

	oldDefault := DefaultIdentityFile
	DefaultIdentityFile = defaultPath
	defer func() { DefaultIdentityFile = oldDefault }()

	resolved, err := LoadIdentity(LoadIdentityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if resolved == nil || resolved.DID != ident.DID {
		t.Fatalf("expected default file identity, got %v", resolved)
	}
}
