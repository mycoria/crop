package crop

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// KeyExchangeType identifies a key exchange algorithm.
type KeyExchangeType string

const (
	// KeyExchangeTypeX25519 is the X25519 Diffie-Hellman key exchange.
	KeyExchangeTypeX25519 KeyExchangeType = "X25519"
)

// IsValid returns whether this key exchange type is supported.
func (kmt KeyExchangeType) IsValid() bool {
	switch kmt {
	case KeyExchangeTypeX25519:
		return true
	}
	return false
}

// NewKeyExchange creates a new key exchange instance of the specified type.
func NewKeyExchange(kmt KeyExchangeType) (KeyExchange, error) {
	return kmt.New()
}

func (kmt KeyExchangeType) New() (KeyExchange, error) {
	if !kmt.IsValid() {
		return nil, fmt.Errorf("invalid key exchange type: %q", kmt)
	}

	switch kmt {
	case KeyExchangeTypeX25519:
		privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &X25519KeyExchange{
			privKey: privKey,
		}, nil

	default:
		return nil, fmt.Errorf("key exchange type %s not yet implemented", kmt)
	}
}

func (kxt KeyExchangeType) String() string {
	return string(kxt)
}

// KeyExchange performs key agreement between two parties.
type KeyExchange interface {
	// Type returns the key exchange algorithm type.
	Type() KeyExchangeType
	// ExchangeMsg returns the public key to send to the peer.
	ExchangeMsg() ([]byte, error)
	// MakeKeys derives shared keys from the peer's public key.
	MakeKeys(exchMsg []byte, keyMakerType KeyMakerType) (KeyMaker, error)
	// Burn securely erases key material from memory.
	Burn()
}

// X25519KeyExchange implements KeyExchange using X25519.
type X25519KeyExchange struct {
	privKey *ecdh.PrivateKey
	used    bool // Prevents key reuse for security
}

func (xke *X25519KeyExchange) Type() KeyExchangeType {
	return KeyExchangeTypeX25519
}

func (xke *X25519KeyExchange) ExchangeMsg() ([]byte, error) {
	return xke.privKey.PublicKey().Bytes(), nil
}

func (xke *X25519KeyExchange) MakeKeys(exchMsg []byte, keyMakerType KeyMakerType) (KeyMaker, error) {
	if xke.used {
		return nil, ErrCannotReuse
	}

	remotePubKey, err := ecdh.X25519().NewPublicKey(exchMsg)
	if err != nil {
		return nil, err
	}
	keyMaterial, err := xke.privKey.ECDH(remotePubKey)
	if err != nil {
		return nil, err
	}
	keyMaker, err := keyMakerType.New(keyMaterial)
	if err != nil {
		return nil, err
	}

	xke.used = true
	return keyMaker, nil
}

func (xke *X25519KeyExchange) Burn() {
	// TODO: How can we destroy the ecdh private key?
}
