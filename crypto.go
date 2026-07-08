package hax

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

const (
	rsaKeyBits        = 2048
	rsaPublicExponent = 65537
)

// smallPrimes used for quick divisibility checks before Miller-Rabin.
var smallPrimes = []int64{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
	59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
}

// GenerateKeyPair generates a deterministic RSA keypair from a passphrase.
// The same passphrase always produces the same keypair.
// Returns (publicKeyJWK, privateKeyJWK).
func GenerateKeyPair(passphrase string) (map[string]any, map[string]any, error) {
	seed := sha256.Sum256([]byte(passphrase))
	prng := newSeededPRNG(seed[:])

	bitSize := rsaKeyBits / 2 // 1024

	p, err := generatePrime(bitSize, prng)
	if err != nil {
		return nil, nil, err
	}
	q, err := generatePrime(bitSize, prng)
	if err != nil {
		return nil, nil, err
	}

	// Ensure p > q for standard RSA.
	if p.Cmp(q) < 0 {
		p, q = q, p
	}

	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)
	e := big.NewInt(rsaPublicExponent)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, nil, fmt.Errorf("modular inverse does not exist")
	}

	dp := new(big.Int).Mod(d, new(big.Int).Sub(p, big.NewInt(1)))
	dq := new(big.Int).Mod(d, new(big.Int).Sub(q, big.NewInt(1)))
	qi := new(big.Int).ModInverse(q, p)
	if qi == nil {
		return nil, nil, fmt.Errorf("modular inverse of q mod p does not exist")
	}

	publicKey := map[string]any{
		"kty": "RSA",
		"alg": "RSA-OAEP-256",
		"use": "enc",
		"n":   bigintToBase64url(n),
		"e":   bigintToBase64url(e),
	}

	privateKey := map[string]any{
		"kty": "RSA",
		"alg": "RSA-OAEP-256",
		"use": "enc",
		"n":   bigintToBase64url(n),
		"e":   bigintToBase64url(e),
		"d":   bigintToBase64url(d),
		"p":   bigintToBase64url(p),
		"q":   bigintToBase64url(q),
		"dp":  bigintToBase64url(dp),
		"dq":  bigintToBase64url(dq),
		"qi":  bigintToBase64url(qi),
	}

	return publicKey, privateKey, nil
}

// DecryptResponse decrypts a response that was encrypted by the server using RSA-OAEP.
func DecryptResponse(encrypted string, privateKeyJWK map[string]any) (any, error) {
	rsaKey, err := jwkToRSAPrivateKey(privateKeyJWK)
	if err != nil {
		return nil, decryptionError(err.Error())
	}

	ciphertext, err := base64Decode(encrypted)
	if err != nil {
		return nil, decryptionError(fmt.Sprintf("Invalid base64 encoding: %s", err))
	}

	plaintext, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaKey,
		ciphertext,
		nil, // label
	)
	if err != nil {
		return nil, decryptionError(fmt.Sprintf("Decryption failed (wrong key or corrupted data): %s", err))
	}

	var result any
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil, decryptionError(fmt.Sprintf("Invalid JSON in decrypted data: %s", err))
	}
	return result, nil
}

// IsEncryptedResponse checks if data looks like it was encrypted by the server.
func IsEncryptedResponse(data any) bool {
	m, ok := data.(map[string]any)
	if !ok {
		return false
	}
	encValue, ok := m["_encrypted"].(string)
	if !ok {
		return false
	}
	raw, err := base64Decode(encValue)
	if err != nil {
		return false
	}
	// RSA-2048 produces 256 bytes of ciphertext.
	return len(raw) >= 128 && len(raw) <= 512
}

// --- Internal utilities ---

// seededPRNG is a deterministic PRNG that produces the same byte sequence
// as the Python SDK's _create_seeded_prng.
type seededPRNG struct {
	state   []byte
	counter int
}

func newSeededPRNG(seed []byte) *seededPRNG {
	state := make([]byte, len(seed))
	copy(state, seed)
	return &seededPRNG{state: state}
}

func (p *seededPRNG) getBytes(length int) []byte {
	chunks := make([][]byte, 0, (length+31)/32)
	remaining := length

	for remaining > 0 {
		var counterBytes [4]byte
		binary.LittleEndian.PutUint32(counterBytes[:], uint32(p.counter))

		// hash = sha256(state + counter_bytes)
		input := make([]byte, 0, len(p.state)+4)
		input = append(input, p.state...)
		input = append(input, counterBytes[:]...)
		hash := sha256.Sum256(input)

		take := remaining
		if take > 32 {
			take = 32
		}
		chunks = append(chunks, hash[:take])
		remaining -= take
		p.counter++

		if p.counter%256 == 0 {
			input2 := make([]byte, 0, len(p.state)+32)
			input2 = append(input2, p.state...)
			input2 = append(input2, hash[:]...)
			newState := sha256.Sum256(input2)
			p.state = newState[:]
		}
	}

	result := make([]byte, 0, length)
	for _, chunk := range chunks {
		result = append(result, chunk...)
	}
	return result
}

// generatePrime generates a random prime of the specified bit size using Miller-Rabin.
func generatePrime(bits int, prng *seededPRNG) (*big.Int, error) {
	byteLength := (bits + 7) / 8

	for {
		randomBytes := prng.getBytes(byteLength)
		// Set MSB to ensure correct bit length.
		randomBytes[0] |= 0x80
		// Set LSB to ensure odd number.
		randomBytes[len(randomBytes)-1] |= 0x01

		candidate := new(big.Int).SetBytes(randomBytes)

		if !passesSmallPrimeCheck(candidate) {
			continue
		}

		if millerRabin(candidate, 40, prng) {
			return candidate, nil
		}
	}
}

func passesSmallPrimeCheck(n *big.Int) bool {
	for _, p := range smallPrimes {
		bp := big.NewInt(p)
		if n.Cmp(bp) == 0 {
			return true
		}
		// n % p == 0
		rem := new(big.Int).Mod(n, bp)
		if rem.Sign() == 0 {
			return false
		}
	}
	return true
}

// millerRabin performs the Miller-Rabin primality test with the given number
// of rounds, using the provided PRNG for witness generation.
func millerRabin(n *big.Int, rounds int, prng *seededPRNG) bool {
	if n.Cmp(big.NewInt(2)) < 0 {
		return false
	}
	if n.Cmp(big.NewInt(2)) == 0 {
		return true
	}
	// n is even?
	if new(big.Int).Mod(n, big.NewInt(2)).Sign() == 0 {
		return false
	}

	// Write n-1 = 2^r * d
	r := 0
	d := new(big.Int).Sub(n, big.NewInt(1))
	for d.Bit(0) == 0 {
		r++
		d.Rsh(d, 1)
	}

	byteLength := (n.BitLen() + 7) / 8
	nMinus3 := new(big.Int).Sub(n, big.NewInt(3))
	nMinus1 := new(big.Int).Sub(n, big.NewInt(1))

	for i := 0; i < rounds; i++ {
		var a *big.Int
		for {
			randomBytes := prng.getBytes(byteLength)
			a = new(big.Int).SetBytes(randomBytes)
			a.Mod(a, nMinus3)
			a.Add(a, big.NewInt(2))
			if a.Cmp(big.NewInt(2)) >= 0 && a.Cmp(nMinus1) < 0 {
				break
			}
		}

		x := new(big.Int).Exp(a, d, n)

		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(nMinus1) == 0 {
			continue
		}

		composite := true
		for j := 0; j < r-1; j++ {
			x.Exp(x, big.NewInt(2), n)
			if x.Cmp(nMinus1) == 0 {
				composite = false
				break
			}
		}

		if composite {
			return false
		}
	}

	return true
}

func bigintToBase64url(n *big.Int) string {
	if n.Sign() == 0 {
		return "AA"
	}
	data := n.Bytes()
	return base64.RawURLEncoding.EncodeToString(data)
}

func base64urlToBigint(s string) (*big.Int, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(data), nil
}

// base64Decode decodes base64 (handles both standard and URL-safe, with or without padding).
func base64Decode(data string) ([]byte, error) {
	// Convert base64url to standard base64.
	data = replaceChars(data)
	// Add padding if needed.
	pad := (4 - len(data)%4) % 4
	for i := 0; i < pad; i++ {
		data += "="
	}
	return base64.StdEncoding.DecodeString(data)
}

func replaceChars(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch c {
		case '-':
			b[i] = '+'
		case '_':
			b[i] = '/'
		}
	}
	return string(b)
}

func jwkToRSAPrivateKey(jwk map[string]any) (*rsa.PrivateKey, error) {
	n, err := base64urlToBigint(getString(jwk, "n"))
	if err != nil {
		return nil, fmt.Errorf("invalid n: %w", err)
	}
	e, err := base64urlToBigint(getString(jwk, "e"))
	if err != nil {
		return nil, fmt.Errorf("invalid e: %w", err)
	}
	d, err := base64urlToBigint(getString(jwk, "d"))
	if err != nil {
		return nil, fmt.Errorf("invalid d: %w", err)
	}
	p, err := base64urlToBigint(getString(jwk, "p"))
	if err != nil {
		return nil, fmt.Errorf("invalid p: %w", err)
	}
	q, err := base64urlToBigint(getString(jwk, "q"))
	if err != nil {
		return nil, fmt.Errorf("invalid q: %w", err)
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	key.Precompute()
	return key, nil
}

func getString(m map[string]any, key string) string {
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return v
}

// EncryptWithPublicKey encrypts data with a public key JWK (for testing).
func EncryptWithPublicKey(data any, publicKeyJWK map[string]any) (string, error) {
	n, err := base64urlToBigint(getString(publicKeyJWK, "n"))
	if err != nil {
		return "", err
	}
	e, err := base64urlToBigint(getString(publicKeyJWK, "e"))
	if err != nil {
		return "", err
	}

	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pubKey,
		plaintext,
		nil,
	)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
