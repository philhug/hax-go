package hax

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"crypto/rand"
)

const didKeyPrefix = "did:key:"

// Multicodec prefix for ed25519-pub (0xed as an unsigned varint).
var ed25519Multicodec = []byte{0xED, 0x01}

const ed25519KeyLength = 32

// base58btc (Bitcoin) alphabet.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var base58Index [128]int

func init() {
	for i := range base58Index {
		base58Index[i] = -1
	}
	for i, c := range base58Alphabet {
		base58Index[c] = i
	}
}

// Identity represents a DID identity: a did:key and its Ed25519 private key JWK.
type Identity struct {
	DID           string         `json:"did"`
	PrivateKeyJWK map[string]any `json:"privateKeyJwk"`
}

// --- base64url (no padding) ---

// b64url encodes bytes to base64url WITHOUT padding.
func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// b64urlDecode decodes an unpadded base64url string to bytes.
func b64urlDecode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

// --- base58btc ---

// base58btcEncode encodes bytes to base58btc (Bitcoin alphabet).
func base58btcEncode(data []byte) string {
	leadingZeros := 0
	for leadingZeros < len(data) && data[leadingZeros] == 0 {
		leadingZeros++
	}

	// Big-endian base58 conversion.
	digits := []int{}
	for _, b := range data {
		carry := int(b)
		for i := 0; i < len(digits); i++ {
			carry += digits[i] * 256
			digits[i] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, carry%58)
			carry /= 58
		}
	}

	var sb strings.Builder
	for i := 0; i < leadingZeros; i++ {
		sb.WriteByte('1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		sb.WriteByte(base58Alphabet[digits[i]])
	}
	return sb.String()
}

// base58btcDecode decodes a base58btc string to bytes.
func base58btcDecode(value string) ([]byte, error) {
	leadingOnes := 0
	for leadingOnes < len(value) && value[leadingOnes] == '1' {
		leadingOnes++
	}

	outBytes := []int{}
	for _, ch := range value {
		if int(ch) >= len(base58Index) || base58Index[ch] == -1 {
			return nil, fmt.Errorf("invalid base58btc character: %q", string(ch))
		}
		carry := base58Index[ch]
		for i := 0; i < len(outBytes); i++ {
			carry += outBytes[i] * 58
			outBytes[i] = carry % 256
			carry /= 256
		}
		for carry > 0 {
			outBytes = append(outBytes, carry%256)
			carry /= 256
		}
	}

	// Reverse outBytes and prepend leading zeros.
	result := make([]byte, 0, leadingOnes+len(outBytes))
	for i := 0; i < leadingOnes; i++ {
		result = append(result, 0)
	}
	for i := len(outBytes) - 1; i >= 0; i-- {
		result = append(result, byte(outBytes[i]))
	}
	return result, nil
}

// --- did:key <-> JWK ---

func rawPublicKeyFromJWK(jwk map[string]any) ([]byte, error) {
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
		return nil, fmt.Errorf("JWK is not an Ed25519 OKP key")
	}
	x, ok := jwk["x"].(string)
	if !ok || x == "" {
		return nil, fmt.Errorf("JWK is not an Ed25519 OKP key")
	}
	raw, err := b64urlDecode(x)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	if len(raw) != ed25519KeyLength {
		return nil, fmt.Errorf("Ed25519 public key must be 32 bytes")
	}
	return raw, nil
}

// DidKeyFromPublicJWK encodes an Ed25519 public JWK as a did:key:z6Mk… identifier.
func DidKeyFromPublicJWK(jwk map[string]any) (string, error) {
	raw, err := rawPublicKeyFromJWK(jwk)
	if err != nil {
		return "", err
	}
	prefixed := append(ed25519Multicodec, raw...)
	return didKeyPrefix + "z" + base58btcEncode(prefixed), nil
}

// DidKeyToPublicJWK decodes a did:key:z6Mk… identifier into its Ed25519 public JWK.
func DidKeyToPublicJWK(did string) (map[string]any, error) {
	if !strings.HasPrefix(did, didKeyPrefix) {
		return nil, fmt.Errorf("not a did:key: %s", did)
	}
	multibase := did[len(didKeyPrefix):]
	if len(multibase) == 0 || multibase[0] != 'z' {
		return nil, fmt.Errorf("did:key must use base58btc multibase (z-prefix)")
	}

	decoded, err := base58btcDecode(multibase[1:])
	if err != nil {
		return nil, fmt.Errorf("invalid did:key encoding: %w", err)
	}
	if len(decoded) != len(ed25519Multicodec)+ed25519KeyLength ||
		decoded[0] != ed25519Multicodec[0] ||
		decoded[1] != ed25519Multicodec[1] {
		return nil, fmt.Errorf("did:key is not an ed25519-pub multicodec key")
	}

	raw := decoded[len(ed25519Multicodec):]
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   b64url(raw),
	}, nil
}

// DidFingerprint returns a short display fingerprint: first 8 bytes of
// sha256(raw pubkey), hex, colon-separated.
func DidFingerprint(jwk map[string]any) (string, error) {
	raw, err := rawPublicKeyFromJWK(jwk)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	parts := make([]string, 8)
	for i, b := range digest[:8] {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":"), nil
}

// --- Identity generation ---

// GenerateIdentity generates a fresh Ed25519 keypair and its did:key identity.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	rawPriv := priv.Seed()
	rawPub := pub

	jwk := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   b64url(rawPub),
		"d":   b64url(rawPriv),
	}

	did, err := DidKeyFromPublicJWK(jwk)
	if err != nil {
		return nil, err
	}

	return &Identity{DID: did, PrivateKeyJWK: jwk}, nil
}

// --- JWS signing ---

func defaultKID(did string) string {
	if strings.HasPrefix(did, didKeyPrefix) {
		suffix := did[len(didKeyPrefix):]
		return did + "#" + suffix
	}
	return did + "#key-1"
}

func bodyHash(rawBody []byte) string {
	digest := sha256.Sum256(rawBody)
	return "sha256:" + b64url(digest[:])
}

// b64urlJSON serializes a value to compact JSON and base64url-encodes it.
func b64urlJSON(value any) (string, error) {
	b, err := compactJSON(value)
	if err != nil {
		return "", err
	}
	return b64url(b), nil
}

// SignKnockJWSOptions configures the JWS signing.
type SignKnockJWSOptions struct {
	DID           string
	PrivateKeyJWK map[string]any
	HTM           string
	HTU           string
	RawBody       []byte
	IAT           int64
	JTI           string
	KID           string
}

// SignKnockJWS produces a compact JWS the server's verifyKnockJws accepts.
//
// The signed envelope is a DPoP-shaped compact JWS:
//
//	header  = {"alg": "EdDSA", "kid": "<did>#<suffix>"}
//	payload = {"iat": <unix int>, "jti": <uuid4>, "htm": "<METHOD>",
//	           "htu": "<path>", "bh": "sha256:<base64url(sha256(body))>"}
//
// The signature is Ed25519 over the ASCII "b64url(header).b64url(payload)".
func SignKnockJWS(opts SignKnockJWSOptions) (string, error) {
	kid := opts.KID
	if kid == "" {
		kid = defaultKID(opts.DID)
	}

	iat := opts.IAT
	if iat == 0 {
		iat = time.Now().Unix()
	}
	jti := opts.JTI
	if jti == "" {
		jti = uuidV4()
	}

	header := map[string]any{
		"alg": "EdDSA",
		"kid": kid,
	}
	payload := map[string]any{
		"iat": iat,
		"jti": jti,
		"htm": opts.HTM,
		"htu": opts.HTU,
		"bh":  bodyHash(opts.RawBody),
	}

	headerB64, err := b64urlJSON(header)
	if err != nil {
		return "", err
	}
	payloadB64, err := b64urlJSON(payload)
	if err != nil {
		return "", err
	}

	signingInput := headerB64 + "." + payloadB64

	key, err := privateKeyFromJWK(opts.PrivateKeyJWK)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(key, []byte(signingInput))

	return signingInput + "." + b64url(signature), nil
}

func privateKeyFromJWK(jwk map[string]any) (ed25519.PrivateKey, error) {
	if jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" {
		return nil, fmt.Errorf("JWK is not an Ed25519 OKP private key")
	}
	d, ok := jwk["d"].(string)
	if !ok || d == "" {
		return nil, fmt.Errorf("JWK is not an Ed25519 OKP private key")
	}
	seed, err := b64urlDecode(d)
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 private seed: %w", err)
	}
	if len(seed) != ed25519KeyLength {
		return nil, fmt.Errorf("Ed25519 private seed must be 32 bytes")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// VerifyKnockJWS verifies a compact JWS against the public key recovered
// from the did:key. Returns nil if valid.
func VerifyKnockJWS(jws, did string) error {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWS: expected 3 parts")
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	pubJWK, err := DidKeyToPublicJWK(did)
	if err != nil {
		return err
	}
	rawPub, err := b64urlDecode(pubJWK["x"].(string))
	if err != nil {
		return err
	}
	pubKey := ed25519.PublicKey(rawPub)

	if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// DecodeJWSPayload decodes the payload of a compact JWS.
func DecodeJWSPayload(jws string) (map[string]any, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWS: expected 3 parts")
	}
	raw, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}
