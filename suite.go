package crop

// Default is the default cryptographic suite using X25519, BLAKE3, Ed25519, context hashing, and HMAC-BLAKE3.
var Default = Suite{
	keyExchange: KeyExchangeTypeX25519,
	keyMaker:    KeyMakerTypeBlake3,
	keyPair:     KeyPairTypeEd25519,
	challenge:   ChallengeTypeContextHashBl3,
	msgAuthCode: MsgAuthCodeTypeHMACBlake3,
}

// Suite defines a collection of cryptographic algorithms to be used together.
type Suite struct {
	keyExchange KeyExchangeType
	keyMaker    KeyMakerType
	keyPair     KeyPairType
	challenge   ChallengeType
	msgAuthCode MsgAuthCodeType
}

// KeyExchangeType returns the key exchange algorithm type for this suite.
func (s Suite) KeyExchangeType() KeyExchangeType {
	return s.keyExchange
}

// KeyMakerType returns the key derivation algorithm type for this suite.
func (s Suite) KeyMakerType() KeyMakerType {
	return s.keyMaker
}

// KeyPairType returns the key pair algorithm type for this suite.
func (s Suite) KeyPairType() KeyPairType {
	return s.keyPair
}
