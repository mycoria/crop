package crop

import "errors"

var (
	ErrAuthCodeInvalid            = errors.New("invalid message authentication code")
	ErrCannotReuse                = errors.New("cannot reuse")
	ErrChallengeFailed            = errors.New("challenge failed")
	ErrChecksumMismatch           = errors.New("checksum mismatch")
	ErrInvalidFormat              = errors.New("invalid format")
	ErrInvalidKeyPairType         = errors.New("invalid key pair type")
	ErrNoPrivateKey               = errors.New("no private key available")
	ErrNoPublicKey                = errors.New("no public key available")
	ErrRequestedKeyLengthTooSmall = errors.New("request key length too small")
)
