package crop

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/mr-tron/base58"
)

// StoredKey is an intermediary format used for exporting and importing keys.
type StoredKey struct {
	Type      string `cbor:"t,omitzero" json:"t,omitzero"`
	IsPrivate bool   `cbor:"p,omitzero" json:"p,omitzero"`
	Key       []byte `cbor:"k,omitzero" json:"k,omitzero"`
}

// IsType checks whether the stored key is of the expected type, using case
// insensitive matching.
func (sk *StoredKey) IsType(expected string) bool {
	return strings.EqualFold(sk.Type, expected)
}

// FindStoredKeyType finds the type of the given stored key using the given
// acceptable types, using case insensitive matching
func FindStoredKeyType[T ~string](sk *StoredKey, acceptable []T) (found T, ok bool) {
	for _, entry := range acceptable {
		if strings.EqualFold(sk.Type, string(entry)) {
			return T(sk.Type), true
		}
	}
	var zero T
	return zero, false
}

// Text returns the stored key formatted in text format.
func (sk *StoredKey) Text() string {
	pubPriv := "public"
	if sk.IsPrivate {
		pubPriv = "private"
	}

	return fmt.Sprintf(
		"%s:%s:%s",
		sk.Type,
		pubPriv,
		base58.Encode(sk.Key),
	)
}

// LoadKeyFromText loads a stored key from the text format.
func LoadKeyFromText(text string) (*StoredKey, error) {
	key := &StoredKey{}

	// Split into chunks.
	chunks := strings.Split(text, ":")
	if len(chunks) != 3 {
		return nil, ErrInvalidFormat
	}

	// Check key type very basic.
	// Actual type is checked later with IsType().
	if chunks[0] == "" {
		return nil, ErrInvalidKeyPairType
	}
	key.Type = chunks[0]

	// Check if private.
	switch chunks[1] {
	case "public":
		key.IsPrivate = false
	case "private":
		key.IsPrivate = true
	default:
		return nil, ErrInvalidFormat
	}

	// Parse key data.
	keyData, err := base58.Decode(chunks[2])
	if err != nil {
		return nil, ErrInvalidFormat
	}
	key.Key = keyData

	return key, nil
}

// Bytes returns the stored key formatted in binary format.
func (sk *StoredKey) Bytes() ([]byte, error) {
	return cbor.Marshal(sk)
}

// LoadKeyFromBytes loads a stored key from the binary format.
func LoadKeyFromBytes(data []byte) (*StoredKey, error) {
	key := &StoredKey{}
	err := cbor.Unmarshal(data, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFormat, err)
	}
	if len(key.Type) == 0 || len(key.Key) == 0 {
		return nil, ErrInvalidFormat
	}
	return key, nil
}

// JSON returns the stored key as json.
func (sk *StoredKey) JSON() ([]byte, error) {
	return json.Marshal(sk)
}

// LoadKeyFromJSON loads a stored key from json.
func LoadKeyFromJSON(data []byte) (*StoredKey, error) {
	key := &StoredKey{}
	err := json.Unmarshal(data, key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidFormat, err)
	}
	if len(key.Type) == 0 || len(key.Key) == 0 {
		return nil, ErrInvalidFormat
	}
	return key, nil
}
