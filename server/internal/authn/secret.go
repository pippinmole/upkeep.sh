// Package authn handles agent credential generation and verification.
// Agent secrets are high-entropy random tokens, not user passwords, so a
// fast salted hash (SHA-256) is sufficient — the threat model is
// "database leaked, secrets must not be trivially reusable in plaintext,"
// not offline dictionary attack resistance.
package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateSecret returns a URL-safe random secret and its stored hash.
func GenerateSecret() (secret, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate secret: %w", err)
	}
	secret = base64.RawURLEncoding.EncodeToString(buf)
	return secret, HashSecret(secret), nil
}

func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// VerifySecret compares in constant time.
func VerifySecret(secret, storedHash string) bool {
	got := HashSecret(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}
