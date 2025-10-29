package crop

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"sync"
)

type MsgAuthCodeType string

const (
	MsgAuthCodeTypeHMACBlake3 MsgAuthCodeType = "HMAC-BLAKE3"

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

	// Get HMAC-based auth code.
	switch act {
	case MsgAuthCodeTypeHMACBlake3:
		return &HMAC{
			handlerType: MsgAuthCodeTypeHMACBlake3,
			seqChecker:  seqChecker,
			signer:      hmac.New(BLAKE3.New, signKey),
			verifier:    hmac.New(BLAKE3.New, verifyKey),
		}, nil

	default:
		return nil, fmt.Errorf("auth code type %s not yet implemented", act)
	}
}

type MsgAuthCodeHandler interface {
	Type() MsgAuthCodeType
	Sign(data []byte) (mac []byte)
	Verify(data []byte, mac []byte) error
	Burn()
}

type HMAC struct {
	handlerType MsgAuthCodeType
	seqChecker  SequenceChecker

	signer   hash.Hash
	signLock sync.Mutex

	verifier   hash.Hash
	verifyLock sync.Mutex
}

func (hmac *HMAC) Type() MsgAuthCodeType {
	return hmac.handlerType
}

func (hmac *HMAC) Sign(data []byte) (mac []byte) {
	hmac.signLock.Lock()
	defer hmac.signLock.Unlock()
	defer hmac.signer.Reset()

	// Create slice for the new MAC.
	mac = make([]byte, 9+macSaltSize+hmac.signer.Size())

	// Increment and add serial.
	sequence := hmac.seqChecker.NextOutSequence()
	size := binary.PutUvarint(mac, sequence)

	// Get random salt.
	rand.Read(mac[size : size+macSaltSize])
	size += macSaltSize

	// Generate checksum.
	hmac.signer.Write(mac[:size])
	hmac.signer.Write(data)
	copy(mac[size:], hmac.signer.Sum(nil))
	size += hmac.signer.Size()

	// Return full MAC without extra bytes.
	return mac[:size]
}

func (hmac *HMAC) Verify(data []byte, mac []byte) error {
	hmac.verifyLock.Lock()
	defer hmac.verifyLock.Unlock()
	defer hmac.verifier.Reset()

	// Extract sequence. Note: Check _after_ signature!
	seqNum, seqSize := binary.Uvarint(mac)
	if seqSize <= 0 {
		return fmt.Errorf("%w: too short", ErrAuthCodeInvalid)
	}

	// Check salt size.
	saltSize := len(mac) - seqSize - hmac.verifier.Size()
	if saltSize < macMinSaltSize {
		return fmt.Errorf("%w: too short", ErrAuthCodeInvalid)
	}

	// Generate checksum.
	hmac.verifier.Write(mac[:seqSize+saltSize])
	hmac.verifier.Write(data)
	compareChecksum := hmac.verifier.Sum(nil)

	// Compare checksum.
	if subtle.ConstantTimeCompare(mac[seqSize+saltSize:], compareChecksum) != 1 {
		return ErrAuthCodeInvalid
	}

	// Check sequence number.
	if !hmac.seqChecker.CheckInSequence(seqNum) {
		return fmt.Errorf("%w: sequence violation", ErrAuthCodeInvalid)
	}

	return nil
}

func (hmac *HMAC) Burn() {
	// TODO: Any way we can burn the HMAC constructs?
}
