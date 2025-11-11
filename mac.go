package crop

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"

	"github.com/zeebo/blake3"
)

type MsgAuthCodeType string

const (
	MsgAuthCodeTypeHMACBlake3 MsgAuthCodeType = "HMAC-BLAKE3"
	MsgAuthCodeTypeBlake3     MsgAuthCodeType = "BLAKE3"

	macMinSaltSize = 8
	macSaltSize    = 16
)

func (act MsgAuthCodeType) IsValid() bool {
	switch act {
	case MsgAuthCodeTypeHMACBlake3:
		return true
	}
	return false
}

func NewAuthCodeHandler(act MsgAuthCodeType, signKey, verifyKey []byte, seqChecker SequenceChecker) (MsgAuthCodeHandler, error) {
	return act.New(signKey, verifyKey, seqChecker)
}

func (act MsgAuthCodeType) New(signKey, verifyKey []byte, seqChecker SequenceChecker) (MsgAuthCodeHandler, error) {
	if !act.IsValid() {
		return nil, fmt.Errorf("invalid auth code type: %q", act)
	}

	// Create handler based on type.
	switch act {
	case MsgAuthCodeTypeHMACBlake3:
		return &HashBasedMAC{
			handlerType: MsgAuthCodeTypeHMACBlake3,
			seqChecker:  seqChecker,
			signer:      hmac.New(BLAKE3.New, signKey),
			verifier:    hmac.New(BLAKE3.New, verifyKey),
		}, nil

	case MsgAuthCodeTypeBlake3:
		signer, err := blake3.NewKeyed(signKey)
		if err != nil {
			return nil, err
		}
		verifier, err := blake3.NewKeyed(verifyKey)
		if err != nil {
			return nil, err
		}
		return &HashBasedMAC{
			handlerType: MsgAuthCodeTypeBlake3,
			seqChecker:  seqChecker,
			signer:      signer,
			verifier:    verifier,
		}, nil

	default:
		return nil, fmt.Errorf("auth code type %s not yet implemented", act)
	}
}

func (act MsgAuthCodeType) String() string {
	return string(act)
}

type MsgAuthCodeHandler interface {
	Type() MsgAuthCodeType
	Sign(data []byte) (mac []byte)
	Verify(data []byte, mac []byte) error
	Burn()
}

type HashBasedMAC struct {
	handlerType MsgAuthCodeType
	seqChecker  SequenceChecker

	signer   hash.Hash
	signLock sync.Mutex

	verifier   hash.Hash
	verifyLock sync.Mutex
}

func (hbm *HashBasedMAC) Type() MsgAuthCodeType {
	return MsgAuthCodeTypeBlake3
}

func (hbm *HashBasedMAC) Sign(data []byte) (mac []byte) {
	hbm.signLock.Lock()
	defer hbm.signLock.Unlock()
	defer hbm.signer.Reset()

	// Create slice for the new MAC.
	mac = make([]byte, 9+macSaltSize+hbm.signer.Size())

	// Increment and add serial.
	sequence := hbm.seqChecker.NextOutSequence()
	size := binary.PutUvarint(mac, sequence)

	// Get random salt.
	rand.Read(mac[size : size+macSaltSize])
	size += macSaltSize

	// Generate checksum.
	hbm.signer.Write(mac[:size])
	hbm.signer.Write(data)
	copy(mac[size:], hbm.signer.Sum(nil))
	size += hbm.signer.Size()

	// Return full MAC without extra bytes.
	return mac[:size]
}

func (hbm *HashBasedMAC) Verify(data []byte, mac []byte) error {
	hbm.verifyLock.Lock()
	defer hbm.verifyLock.Unlock()
	defer hbm.verifier.Reset()

	// Extract sequence. Note: Check _after_ signature!
	seqNum, seqSize := binary.Uvarint(mac)
	if seqSize <= 0 {
		return fmt.Errorf("%w: too short", ErrAuthCodeInvalid)
	}

	// Check salt size.
	saltSize := len(mac) - seqSize - hbm.verifier.Size()
	if saltSize < macMinSaltSize {
		return fmt.Errorf("%w: too short", ErrAuthCodeInvalid)
	}

	// Generate checksum.
	hbm.verifier.Write(mac[:seqSize+saltSize])
	hbm.verifier.Write(data)
	compareChecksum := hbm.verifier.Sum(nil)

	// Compare checksum.
	if subtle.ConstantTimeCompare(mac[seqSize+saltSize:], compareChecksum) != 1 {
		return ErrAuthCodeInvalid
	}

	// Check sequence number.
	if !hbm.seqChecker.CheckInSequence(seqNum) {
		return fmt.Errorf("%w: sequence violation", ErrAuthCodeInvalid)
	}

	return nil
}

func (hbm *HashBasedMAC) Burn() {
	// TODO: Any way we can burn the hash constructs?
}
