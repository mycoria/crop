package crop

// Note: LLM-Generated.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/zeebo/blake3"
)

func TestKeyMakerType_IsValid(t *testing.T) {
	t.Parallel()

	if !KeyMakerTypeBlake3.IsValid() {
		t.Fatalf("expected KeyMakerTypeBlake3 to be valid")
	}
	if KeyMakerType("NOPE").IsValid() {
		t.Fatalf("expected unknown type to be invalid")
	}
}

func TestNewKeyMaker_InvalidType(t *testing.T) {
	t.Parallel()

	km, err := NewKeyMaker(KeyMakerType("invalid"), []byte("material"))
	if err == nil {
		t.Fatalf("expected error for invalid key maker type")
	}
	if km != nil {
		t.Fatalf("expected nil KeyMaker for invalid type")
	}
}

func TestNewKeyMaker_Blake3_CreatesUsableAndType(t *testing.T) {
	t.Parallel()

	material := []byte("some key material for blake3")
	km, err := NewKeyMaker(KeyMakerTypeBlake3, material)
	if err != nil {
		t.Fatalf("NewKeyMaker error: %v", err)
	}
	if km == nil {
		t.Fatalf("NewKeyMaker returned nil")
	}
	if km.Type() != KeyMakerTypeBlake3 {
		t.Fatalf("Type() = %q, want %q", km.Type(), KeyMakerTypeBlake3)
	}

	// Derive a minimal-length key
	dst := make([]byte, keyMakerMinKeySize)
	if err := km.DeriveKeyInto("ctx", "party", dst); err != nil {
		t.Fatalf("DeriveKeyInto error: %v", err)
	}
}

func TestBlake3Keymaker_DeriveKeyInto_MinLength(t *testing.T) {
	t.Parallel()

	km, err := NewKeyMaker(KeyMakerTypeBlake3, []byte("material"))
	if err != nil {
		t.Fatalf("NewKeyMaker error: %v", err)
	}

	// Too short: 0 and 15 should error
	shorts := [][]byte{
		make([]byte, 0),
		make([]byte, keyMakerMinKeySize-1),
	}
	for _, dst := range shorts {
		if err := km.DeriveKeyInto("", "", dst); err == nil {
			t.Fatalf("expected error for len(dst)=%d < %d", len(dst), keyMakerMinKeySize)
		} else if !errors.Is(err, ErrRequestedKeyLengthTooSmall) {
			t.Fatalf("expected ErrRequestedKeyLengthTooSmall, got %v", err)
		}
	}

	// Exactly min should succeed
	min := make([]byte, keyMakerMinKeySize)
	if err := km.DeriveKeyInto("", "", min); err != nil {
		t.Fatalf("DeriveKeyInto(min) error: %v", err)
	}
}

func TestBlake3Keymaker_DeriveKeyInto_DeterministicAndDomainSeparated(t *testing.T) {
	t.Parallel()

	material := []byte("fixed key material")
	ctx := "encryption"
	party := "client"

	km1, err := NewKeyMaker(KeyMakerTypeBlake3, append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("NewKeyMaker km1 error: %v", err)
	}
	km2, err := NewKeyMaker(KeyMakerTypeBlake3, append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("NewKeyMaker km2 error: %v", err)
	}

	// Deterministic: same material, context, party, length
	dst1 := make([]byte, 32)
	dst2 := make([]byte, 32)
	if err := km1.DeriveKeyInto(ctx, party, dst1); err != nil {
		t.Fatalf("km1.DeriveKeyInto error: %v", err)
	}
	if err := km2.DeriveKeyInto(ctx, party, dst2); err != nil {
		t.Fatalf("km2.DeriveKeyInto error: %v", err)
	}
	if !bytes.Equal(dst1, dst2) {
		t.Fatalf("determinism failed: km1 != km2\nkm1: %x\nkm2: %x", dst1, dst2)
	}

	// Domain separation: changing ctx changes output
	dstCtx := make([]byte, 32)
	if err := km1.DeriveKeyInto(ctx+"-2", party, dstCtx); err != nil {
		t.Fatalf("DeriveKeyInto(ctx2) error: %v", err)
	}
	if bytes.Equal(dst1, dstCtx) {
		t.Fatalf("expected different keys when context changes")
	}

	// Domain separation: changing party changes output
	dstParty := make([]byte, 32)
	if err := km1.DeriveKeyInto(ctx, party+"-2", dstParty); err != nil {
		t.Fatalf("DeriveKeyInto(party2) error: %v", err)
	}
	if bytes.Equal(dst1, dstParty) {
		t.Fatalf("expected different keys when party changes")
	}
}

func TestBlake3Keymaker_DeriveKeyInto_MatchesReference(t *testing.T) {
	t.Parallel()

	material := []byte("ref material")
	ctx := "ctx"
	party := "server"
	fullCtx := keyMakerBaseContext + ctx + party

	km, err := NewKeyMaker(KeyMakerTypeBlake3, append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("NewKeyMaker error: %v", err)
	}

	dst := make([]byte, 64)
	if err := km.DeriveKeyInto(ctx, party, dst); err != nil {
		t.Fatalf("DeriveKeyInto error: %v", err)
	}

	// Reference using the blake3 package directly
	ref := make([]byte, 64)
	blake3.DeriveKey(fullCtx, material, ref)

	if !bytes.Equal(dst, ref) {
		t.Fatalf("derived key mismatch with reference\n got: %x\nwant: %x", dst, ref)
	}
}

func TestBlake3Keymaker_DeriveKeyInto_VariousLengths(t *testing.T) {
	t.Parallel()

	km, err := NewKeyMaker(KeyMakerTypeBlake3, []byte("material X"))
	if err != nil {
		t.Fatalf("NewKeyMaker error: %v", err)
	}

	lengths := []int{keyMakerMinKeySize, 24, 32, 48, 64, 128}
	prev := make([][]byte, len(lengths))
	for i, n := range lengths {
		dst := make([]byte, n)
		if err := km.DeriveKeyInto("kdf", "party", dst); err != nil {
			t.Fatalf("DeriveKeyInto len=%d error: %v", n, err)
		}
		// Save a copy for uniqueness checks
		prev[i] = append([]byte(nil), dst...)
		// Sanity: output is not all-zeros
		if allZero(dst) {
			t.Fatalf("derived key of length %d is all zeros", n)
		}
	}

	// Keys of different lengths should differ (prefix property not guaranteed, but full slices must differ)
	for i := range prev {
		for j := i + 1; j < len(prev); j++ {
			if bytes.Equal(prev[i], prev[j]) {
				t.Fatalf("keys of different lengths should not be identical: len(%d)==len(%d)", len(prev[i]), len(prev[j]))
			}
		}
	}
}

func TestBlake3Keymaker_Burn_ZeroizesMaterialAndCallerSlice(t *testing.T) {
	t.Parallel()

	src := []byte("super secret material")
	km, err := NewKeyMaker(KeyMakerTypeBlake3, src)
	if err != nil {
		t.Fatalf("NewKeyMaker error: %v", err)
	}
	b3 := km.(*Blake3Keymaker)

	// Ensure initially non-zero
	if allZero(b3.material) || allZero(src) {
		t.Fatalf("test setup: material should be non-zero")
	}

	km.Burn()

	// Internal material zeroized
	if !allZero(b3.material) {
		t.Fatalf("internal material not zeroized after Burn")
	}
	// Since New stores the same slice, the caller's buffer is also zeroized
	if !allZero(src) {
		t.Fatalf("caller-provided material not zeroized after Burn")
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
