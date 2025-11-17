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
	if _, err := rand.Read(secret); err != nil {
		// This should never happen with crypto/rand, but handle it defensively.
		panic("failed to generate random secret: " + err.Error())
	}
	return secret
}
