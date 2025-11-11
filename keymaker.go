package crop

import (
	"fmt"

	"github.com/zeebo/blake3"
)

// KeyMakerType identifies a key derivation algorithm.
type KeyMakerType string

const (
	// KeyMakerTypeBlake3 derives keys using BLAKE3.
	KeyMakerTypeBlake3 KeyMakerType = "BLAKE3"

	keyMakerBaseContext = "nexufend key mkr"

	keyMakerMinKeySize = 16
)

// IsValid returns whether this key maker type is supported.
func (kmt KeyMakerType) IsValid() bool {
	switch kmt {
	case KeyMakerTypeBlake3:
		return true
	}
	return false
}

// NewKeyMaker creates a new key derivation instance from key material.
func NewKeyMaker(kmt KeyMakerType, key []byte) (KeyMaker, error) {
	return kmt.New(key)
}

func (kmt KeyMakerType) New(keyMaterial []byte) (KeyMaker, error) {
	if !kmt.IsValid() {
		return nil, fmt.Errorf("invalid key maker type: %q", kmt)
	}

	switch kmt {
	case KeyMakerTypeBlake3:
		return &Blake3Keymaker{
			material: keyMaterial,
		}, nil

	default:
		return nil, fmt.Errorf("key maker type %s not yet implemented", kmt)
	}
}

func (kmt KeyMakerType) String() string {
	return string(kmt)
}

// KeyMaker derives multiple keys from shared key material.
type KeyMaker interface {
	// Type returns the key maker algorithm type.
	Type() KeyMakerType
	// DeriveKey creates a new key with domain separation.
	DeriveKey(keyContext, keyParty string, keyLength int) ([]byte, error)
	// DeriveKeyInto writes a derived key directly into dst.
	DeriveKeyInto(keyContext, keyParty string, dst []byte) error
	// Burn securely erases key material from memory.
	Burn()
}

// Blake3Keymaker implements KeyMaker using BLAKE3 key derivation.
type Blake3Keymaker struct {
	material []byte
}

func (b3km *Blake3Keymaker) Type() KeyMakerType {
	return KeyMakerTypeBlake3
}

func (b3km *Blake3Keymaker) DeriveKey(keyContext, keyParty string, keyLength int) ([]byte, error) {
	dst := make([]byte, keyLength)
	return dst, b3km.DeriveKeyInto(keyContext, keyParty, dst)
}

func (b3km *Blake3Keymaker) DeriveKeyInto(keyContext, keyParty string, dst []byte) error {
	if len(dst) < keyMakerMinKeySize {
		return ErrRequestedKeyLengthTooSmall
	}

	blake3.DeriveKey(keyMakerBaseContext+keyContext+keyParty, b3km.material, dst)
	return nil
}

func (b3km *Blake3Keymaker) Burn() {
	clear(b3km.material)
}
