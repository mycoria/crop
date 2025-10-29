package crop

var Default = Suite{
	keyExchange: KeyExchangeTypeX25519,
	keyMaker:    KeyMakerTypeBlake3,
	keyPair:     KeyPairTypeEd25519,
	challenge:   ChallengeTypeContextHashBl3,
	msgAuthCode: MsgAuthCodeTypeHMACBlake3,
}

type Suite struct {
	keyExchange KeyExchangeType
	keyMaker    KeyMakerType
	keyPair     KeyPairType
	challenge   ChallengeType
	msgAuthCode MsgAuthCodeType
}

func (s Suite) KeyExchangeType() KeyExchangeType {
	return s.keyExchange
}

func (s Suite) KeyMakerType() KeyMakerType {
	return s.keyMaker
}

func (s Suite) KeyPairType() KeyPairType {
	return s.keyPair
}
