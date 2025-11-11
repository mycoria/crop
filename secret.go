package crop

import "crypto/rand"

const minSecretLength = 32 // 256 bits

// NewSecret returns a new random secret with the given length (minimum 32 bytes).
func NewSecret(length int) []byte {
	// Enforce minimum of 32 bytes.
	if length < minSecretLength {
		length = minSecretLength
	}

	// Read random data into secret.
	secret := make([]byte, length)
	rand.Read(secret) // Cannot fail.
	return secret
}
