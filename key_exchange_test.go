package crop

// Note: LLM-Generated.

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"testing"
)

func TestKeyExchangeType_IsValid(t *testing.T) {
	t.Parallel()

	if !KeyExchangeTypeX25519.IsValid() {
		t.Fatalf("expected X25519 to be valid")
	}
	if (KeyExchangeType("NOPE")).IsValid() {
		t.Fatalf("expected unknown type to be invalid")
	}
}

func TestNewKeyExchange_InvalidType(t *testing.T) {
	t.Parallel()

	ke, err := NewKeyExchange(KeyExchangeType("invalid"))
	if err == nil {
		t.Fatalf("expected error for invalid key exchange type")
	}
	if ke != nil {
		t.Fatalf("expected nil KeyExchange for invalid type")
	}
}

func TestNewKeyExchange_X25519_CreatesUsable(t *testing.T) {
	t.Parallel()

	ke, err := NewKeyExchange(KeyExchangeTypeX25519)
	if err != nil {
		t.Fatalf("NewKeyExchange(X25519) error: %v", err)
	}
	if ke == nil {
		t.Fatalf("NewKeyExchange(X25519) returned nil")
	}
	if ke.Type() != KeyExchangeTypeX25519 {
		t.Fatalf("Type() = %q, want %q", ke.Type(), KeyExchangeTypeX25519)
	}

	exMsg, err := ke.ExchangeMsg()
	if err != nil {
		t.Fatalf("ExchangeMsg() error: %v", err)
	}
	// X25519 public key bytes must be 32 bytes and parseable
	if len(exMsg) != 32 {
		t.Fatalf("ExchangeMsg length = %d, want 32", len(exMsg))
	}
	if _, err := ecdh.X25519().NewPublicKey(exMsg); err != nil {
		t.Fatalf("ExchangeMsg() did not produce a valid X25519 public key: %v", err)
	}
}

func TestX25519_ECDHSharedSecret_MatchBetweenPeers(t *testing.T) {
	t.Parallel()

	// Create two peers
	aliceKE, err := NewKeyExchange(KeyExchangeTypeX25519)
	if err != nil {
		t.Fatalf("alice NewKeyExchange error: %v", err)
	}
	bobKE, err := NewKeyExchange(KeyExchangeTypeX25519)
	if err != nil {
		t.Fatalf("bob NewKeyExchange error: %v", err)
	}

	// Assert concrete types to access private keys (package-internal)
	alice := aliceKE.(*X25519KeyExchange)
	bob := bobKE.(*X25519KeyExchange)

	// Exchange public messages
	aliceMsg, err := alice.ExchangeMsg()
	if err != nil {
		t.Fatalf("alice.ExchangeMsg error: %v", err)
	}
	bobMsg, err := bob.ExchangeMsg()
	if err != nil {
		t.Fatalf("bob.ExchangeMsg error: %v", err)
	}

	// Parse each other's public keys and compute the ECDH secrets directly.
	aliceRemote, err := ecdh.X25519().NewPublicKey(bobMsg)
	if err != nil {
		t.Fatalf("alice parse bob pubkey: %v", err)
	}
	bobRemote, err := ecdh.X25519().NewPublicKey(aliceMsg)
	if err != nil {
		t.Fatalf("bob parse alice pubkey: %v", err)
	}

	aliceSecret, err := alice.privKey.ECDH(aliceRemote)
	if err != nil {
		t.Fatalf("alice ECDH: %v", err)
	}
	bobSecret, err := bob.privKey.ECDH(bobRemote)
	if err != nil {
		t.Fatalf("bob ECDH: %v", err)
	}

	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Fatalf("ECDH secrets differ\nalice: %x\n  bob: %x", aliceSecret, bobSecret)
	}
}

func TestX25519_MakeKeys_ErrOnInvalidRemotePubKey(t *testing.T) {
	t.Parallel()

	ke, err := NewKeyExchange(KeyExchangeTypeX25519)
	if err != nil {
		t.Fatalf("NewKeyExchange error: %v", err)
	}

	var dummyKMT KeyMakerType // zero value; should not be reached for invalid exchMsg
	_, err = ke.MakeKeys([]byte("short"), dummyKMT)
	if err == nil {
		t.Fatalf("expected error when passing invalid remote public key bytes")
	}
}

func TestX25519_MakeKeys_ErrCannotReuse(t *testing.T) {
	t.Parallel()

	// Create an instance and force it into a "used" state.
	ke, err := NewKeyExchange(KeyExchangeTypeX25519)
	if err != nil {
		t.Fatalf("NewKeyExchange error: %v", err)
	}
	x := ke.(*X25519KeyExchange)
	x.used = true

	var dummyKMT KeyMakerType
	_, err = x.MakeKeys(make([]byte, 32), dummyKMT) // exchMsg won't be used due to early check
	if err == nil {
		t.Fatalf("expected ErrCannotReuse on second MakeKeys call")
	}
	if !errors.Is(err, ErrCannotReuse) {
		t.Fatalf("expected ErrCannotReuse, got %v", err)
	}
}

func TestX25519_TypeAndBurn_NoPanic(t *testing.T) {
	t.Parallel()

	ke, err := NewKeyExchange(KeyExchangeTypeX25519)
	if err != nil {
		t.Fatalf("NewKeyExchange error: %v", err)
	}

	if ke.Type() != KeyExchangeTypeX25519 {
		t.Fatalf("Type() = %q, want %q", ke.Type(), KeyExchangeTypeX25519)
	}

	// Burn is currently a no-op; ensure it doesn't panic.
	ke.Burn()
}
