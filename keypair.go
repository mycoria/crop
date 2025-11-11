package crop

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

type KeyPairType string

const (
	KeyPairTypeEd25519 KeyPairType = "Ed25519"
)

func AllKeyPairTypes() []KeyPairType {
	return []KeyPairType{
		KeyPairTypeEd25519,
	}
}

func (kpt KeyPairType) IsValid() bool {
	switch kpt {
	case KeyPairTypeEd25519:
		return true
	}
	return false
}

type KeyPair interface {
	Type() KeyPairType
	PublicKey() crypto.PublicKey

	HasPrivate() bool
	ToPublic() KeyPair

	Sign(data []byte) (sig []byte, err error)
	Verify(data, sig []byte) error

	Export() (*StoredKey, error)
	Burn()
}

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

type Ed25519KeyPair struct {
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
}

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

func (edkp *Ed25519KeyPair) PublicKeyData() []byte {
	return edkp.pubKey
}

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
