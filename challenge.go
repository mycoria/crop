package crop

import (
	"crypto/subtle"
	"fmt"
)

// ChallengeType identifies a challenge-response authentication algorithm.
type ChallengeType string

const (
	// ChallengeTypeContextHashBl3 uses context-bound hashing with BLAKE3.
	ChallengeTypeContextHashBl3 ChallengeType = "context-hash-bl3"
)

// IsValid returns whether this challenge type is supported.
func (ct ChallengeType) IsValid() bool {
	switch ct {
	case ChallengeTypeContextHashBl3:
		return true
	}
	return false
}

// NewChallenge creates a new challenge for authentication.
func NewChallenge(ct ChallengeType, purpose, requesterContext, responderContext string) (Challenge, error) {
	return ct.New(purpose, requesterContext, responderContext)
}

func (ct ChallengeType) New(purpose, requesterContext, responderContext string) (Challenge, error) {
	if !ct.IsValid() {
		return nil, fmt.Errorf("invalid challenge type: %q", ct)
	}

	// Get HMAC-based auth code.
	switch ct {
	case ChallengeTypeContextHashBl3:
		return &HashedContextChallenge{
			challengeType:    ChallengeTypeContextHashBl3,
			hash:             BLAKE3,
			challengeData:    NewSecret(32),
			purpose:          purpose,
			requesterContext: requesterContext,
			responderContext: responderContext,
		}, nil

	default:
		return nil, fmt.Errorf("challenge type %s not yet implemented", ct)
	}
}

func (ct ChallengeType) String() string {
	return string(ct)
}

// Challenge implements challenge-response authentication between peers.
type Challenge interface {
	// Type returns the challenge algorithm type.
	Type() ChallengeType
	// GetChallenge returns the challenge bytes to send.
	GetChallenge() []byte
	// CheckResponse verifies a response to the challenge.
	CheckResponse(data []byte) error
	// MakeResponse generates a response to a received challenge.
	MakeResponse(challenge []byte) (response []byte, err error)
}

// HashedContextChallenge implements Challenge using context-bound hashing.
type HashedContextChallenge struct {
	challengeType    ChallengeType
	hash             Hash
	challengeData    []byte
	purpose          string
	requesterContext string
	responderContext string
}

func (hcc *HashedContextChallenge) Type() ChallengeType {
	return hcc.challengeType
}

func (hcc *HashedContextChallenge) GetChallenge() []byte {
	return hcc.challengeData
}

func (hcc *HashedContextChallenge) CheckResponse(data []byte) error {
	comparison := hcc.makeHash(hcc.challengeData, false)
	if subtle.ConstantTimeCompare(data, comparison) != 1 {
		return ErrChallengeFailed
	}
	return nil
}

func (hcc *HashedContextChallenge) MakeResponse(challenge []byte) (response []byte, err error) {
	return hcc.makeHash(challenge, true), nil
}

func (hcc *HashedContextChallenge) makeHash(input []byte, reverse bool) []byte {
	vh := NewValueHasher(hcc.hash.New())

	vh.AddString("hashed context challenge") // Fixed internal value.
	vh.AddString(hcc.purpose)                // Add purpose.
	if !reverse {
		// Add request, then response context for checking response.
		vh.AddString(hcc.requesterContext)
		vh.AddString(hcc.responderContext)
	} else {
		// Add response, then request context for making response.
		vh.AddString(hcc.responderContext)
		vh.AddString(hcc.requesterContext)
	}
	vh.Add(input)

	return vh.Sum(nil)
}
