package crop

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

type KeyExchangeType string

const (
	KeyExchangeTypeX25519 KeyExchangeType = "X25519"
)

func (kmt KeyExchangeType) IsValid() bool {
	switch kmt {
	case KeyExchangeTypeX25519:
		return true
	}
	return false
}

func NewKeyExchange(kmt KeyExchangeType, key []byte) (KeyExchange, error) {
	return kmt.New(key)
}

func (kmt KeyExchangeType) New(keyMaterial []byte) (KeyExchange, error) {
	if !kmt.IsValid() {
		return nil, fmt.Errorf("invalid key maker type: %q", kmt)
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
		return nil, fmt.Errorf("key maker type %s not yet implemented", kmt)
	}
}

type KeyExchange interface {
	Type() KeyExchangeType
	ExchangeMsg() ([]byte, error)
	MakeKeys(exchMsg []byte, keyMakerType KeyMakerType) (KeyMaker, error)
	Burn()
}

type X25519KeyExchange struct {
	privKey *ecdh.PrivateKey
	used    bool
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
