package hax

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const identityFileEnv = "HAX_IDENTITY_FILE"

// DefaultIdentityFile is the default path for the identity file.
var DefaultIdentityFile = defaultIdentityFilePath()

func defaultIdentityFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".hax", "identity.json")
}

// LoadIdentityOptions configures identity resolution.
type LoadIdentityOptions struct {
	DID           string
	PrivateKeyJWK map[string]any
	IdentityFile  string
	AllowMint     bool
}

// LoadIdentity resolves a DID identity from the first available source.
//
// Resolution order:
//  1. Explicit DID + PrivateKeyJWK arguments.
//  2. Explicit IdentityFile path.
//  3. HAX_IDENTITY_FILE environment variable.
//  4. Default ~/.hax/identity.json if present.
//  5. If AllowMint — mint a fresh identity, persist it (0600).
func LoadIdentity(opts LoadIdentityOptions) (*Identity, error) {
	// 1. Explicit did + jwk.
	if opts.DID != "" && opts.PrivateKeyJWK != nil {
		return &Identity{DID: opts.DID, PrivateKeyJWK: opts.PrivateKeyJWK}, nil
	}

	// 2. Explicit identity file.
	if opts.IdentityFile != "" {
		if id, err := loadIdentityFromFile(opts.IdentityFile); err == nil && id != nil {
			return id, nil
		}
	}

	// 3. HAX_IDENTITY_FILE env var.
	envFile := os.Getenv(identityFileEnv)
	if envFile != "" {
		if id, err := loadIdentityFromFile(envFile); err == nil && id != nil {
			return id, nil
		}
	}

	// 4. Default ~/.hax/identity.json.
	if id, err := loadIdentityFromFile(DefaultIdentityFile); err == nil && id != nil {
		return id, nil
	}

	// 5. Mint as a last resort.
	if opts.AllowMint {
		identity, err := GenerateIdentity()
		if err != nil {
			return nil, err
		}
		mintPath := opts.IdentityFile
		if mintPath == "" {
			mintPath = envFile
		}
		if mintPath == "" {
			mintPath = DefaultIdentityFile
		}
		if err := SaveIdentity(identity, mintPath); err != nil {
			return nil, fmt.Errorf("failed to persist minted identity: %w", err)
		}
		log.Printf("hax: minted DID %s (%s)", identity.DID, mintPath)
		return identity, nil
	}

	return nil, nil
}

// SaveIdentity persists an identity to path (default ~/.hax/identity.json), 0600.
func SaveIdentity(identity *Identity, path string) error {
	if path == "" {
		path = DefaultIdentityFile
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create identity directory: %w", err)
	}

	payload := identityFilePayload{
		DID:           identity.DID,
		PrivateKeyJwk: identity.PrivateKeyJWK,
		CreatedAt:     time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identity: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	return nil
}

type identityFilePayload struct {
	DID           string         `json:"did"`
	PrivateKeyJwk map[string]any `json:"privateKeyJwk"`
	CreatedAt     string         `json:"createdAt"`
}

func loadIdentityFromFile(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var payload identityFilePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	if payload.DID == "" || payload.PrivateKeyJwk == nil {
		return nil, nil
	}

	return &Identity{
		DID:           payload.DID,
		PrivateKeyJWK: payload.PrivateKeyJwk,
	}, nil
}
