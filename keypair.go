package crop

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// KeyPairType identifies a signing/verification key pair algorithm.
type KeyPairType string

const (
	// KeyPairTypeEd25519 is the Ed25519 signature scheme.
	KeyPairTypeEd25519 KeyPairType = "Ed25519"
)

// AllKeyPairTypes returns all supported key pair types.
func AllKeyPairTypes() []KeyPairType {
	return []KeyPairType{
		KeyPairTypeEd25519,
	}
}

// IsValid returns whether this key pair type is supported.
func (kpt KeyPairType) IsValid() bool {
	switch kpt {
	case KeyPairTypeEd25519:
		return true
	}
	return false
}

// KeyPair represents a public/private key pair for signing and verification.
type KeyPair interface {
	// Type returns the key pair algorithm type.
	Type() KeyPairType
	// PublicKey returns the public key.
	PublicKey() crypto.PublicKey

	// HasPrivate returns true if this key pair includes a private key.
	HasPrivate() bool
	// ToPublic returns a copy containing only the public key.
	ToPublic() KeyPair

	// Sign creates a signature over the data using the private key.
	Sign(data []byte) (sig []byte, err error)
	// Verify checks that the signature is valid for the data.
	Verify(data, sig []byte) error

	// Export serializes the key pair to a StoredKey.
	Export() (*StoredKey, error)
	// Burn securely erases key material from memory.
	Burn()
}

// NewKeyPair generates a new key pair of the specified type.
func NewKeyPair(kpType KeyPairType) (KeyPair, error) {
	return kpType.New()
}

func (kpType KeyPairType) New() (KeyPair, error) {
	if !kpType.IsValid() {
		return nil, fmt.Errorf("invalid key pair type: %q", kpType)
	}

	switch kpType {
	case KeyPairTypeEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &Ed25519KeyPair{
			pubKey:  pub,
			privKey: priv,
		}, nil

	default:
		return nil, fmt.Errorf("key pair type %s not yet implemented", kpType)
	}
}

func (kpt KeyPairType) String() string {
	return string(kpt)
}

// LoadKeyPair loads a key pair from a StoredKey.
func LoadKeyPair(stored *StoredKey) (KeyPair, error) {
	// Get and check key type.
	kpType, ok := FindStoredKeyType(stored, []KeyPairType{
		KeyPairTypeEd25519,
	})
	if !ok {
		return nil, ErrInvalidKeyPairType
	}

	// Load key.
	switch kpType {
	case KeyPairTypeEd25519:
		key := &Ed25519KeyPair{}
		if stored.IsPrivate {
			key.privKey = stored.Key
			key.pubKey = key.privKey.Public().(ed25519.PublicKey)
		} else {
			key.pubKey = stored.Key
		}
		return key, nil

	default:
		return nil, fmt.Errorf("key pair type %s not yet implemented", kpType)
	}
}

// Ed25519KeyPair implements the KeyPair interface for Ed25519 signatures.
type Ed25519KeyPair struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
}

// MakeEd25519KeyPair creates an Ed25519KeyPair from existing key material.
func MakeEd25519KeyPair(privKey ed25519.PrivateKey, pubKey ed25519.PublicKey) *Ed25519KeyPair {
	if len(pubKey) == 0 && len(privKey) != 0 {
		pubKey = privKey.Public().(ed25519.PublicKey)
	}
	return &Ed25519KeyPair{
		pubKey:  pubKey,
		privKey: privKey,
	}
}

func (edkp *Ed25519KeyPair) Type() KeyPairType {
	return KeyPairTypeEd25519
}

func (edkp *Ed25519KeyPair) PublicKey() crypto.PublicKey {
	return edkp.pubKey
}

func (edkp *Ed25519KeyPair) HasPrivate() bool {
	return edkp.privKey != nil
}

func (edkp *Ed25519KeyPair) ToPublic() KeyPair {
	return &Ed25519KeyPair{
		pubKey: edkp.pubKey,
	}
}

func (edkp *Ed25519KeyPair) Sign(data []byte) (signature []byte, err error) {
	if edkp.privKey == nil {
		return nil, ErrNoPrivateKey
	}
	return edkp.privKey.Sign(rand.Reader, data, &ed25519.Options{})
}

func (edkp *Ed25519KeyPair) Verify(data, sig []byte) error {
	if edkp.pubKey == nil {
		return ErrNoPublicKey
	}
	return ed25519.VerifyWithOptions(edkp.pubKey, data, sig, &ed25519.Options{})
}

// PublicKeyData returns the raw public key bytes.
func (edkp *Ed25519KeyPair) PublicKeyData() []byte {
	return edkp.pubKey
}

// PrivateKeyData returns the raw private key bytes.
func (edkp *Ed25519KeyPair) PrivateKeyData() []byte {
	return edkp.privKey
}

func (edkp *Ed25519KeyPair) Export() (*StoredKey, error) {
	stored := &StoredKey{
		Type:      string(edkp.Type()),
		IsPrivate: edkp.HasPrivate(),
	}
	if stored.IsPrivate {
		if edkp.privKey == nil {
			return nil, ErrNoPrivateKey
		}
		stored.Key = edkp.privKey
	} else {
		if edkp.pubKey == nil {
			return nil, ErrNoPublicKey
		}
		stored.Key = edkp.pubKey
	}
	return stored, nil
}

func (edkp *Ed25519KeyPair) Burn() {
	// TODO: Use guaranteed memory wiping as soon as Go supports it.
	clear(edkp.privKey)
	clear(edkp.pubKey)
	edkp.privKey = nil
	edkp.pubKey = nil
}
