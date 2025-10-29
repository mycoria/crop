package crop

import (
	"crypto/subtle"
	"fmt"
)

type ChallengeType string

const (
	ChallengeTypeContextHashBl3 ChallengeType = "context-hash-bl3"
)

func (ct ChallengeType) IsValid() bool {
	switch ct {
	case ChallengeTypeContextHashBl3:
		return true
	}
	return false
}

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

type Challenge interface {
	GetChallenge() []byte
	CheckResponse(data []byte) error
	MakeResponse(challenge []byte) (response []byte, err error)
}

type HashedContextChallenge struct {
	hash             Hash
	challengeData    []byte
	purpose          string
	requesterContext string
	responderContext string
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
	vh := NewValueHasher(hcc.hash)

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

	return vh.Sum()
}
