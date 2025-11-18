package crop

// Note: LLM-Generated.

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
)

func TestHash_New_IsValid_AndDigestAgainstReference(t *testing.T) {
	type algoCase struct {
		name    string
		algo    Hash
		refFunc func([]byte) []byte
	}

	algos := []algoCase{
		// SHA2
		{"SHA2_224", SHA2_224, func(b []byte) []byte { sum := sha256.Sum224(b); return sum[:] }},
		{"SHA2_256", SHA2_256, func(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }},
		{"SHA2_384", SHA2_384, func(b []byte) []byte { sum := sha512.Sum384(b); return sum[:] }},
		{"SHA2_512", SHA2_512, func(b []byte) []byte { sum := sha512.Sum512(b); return sum[:] }},
		{"SHA2_512_224", SHA2_512_224, func(b []byte) []byte { sum := sha512.Sum512_224(b); return sum[:] }},
		{"SHA2_512_256", SHA2_512_256, func(b []byte) []byte { sum := sha512.Sum512_256(b); return sum[:] }},

		// SHA3
		{"SHA3_224", SHA3_224, func(b []byte) []byte { sum := sha3.Sum224(b); return sum[:] }},
		{"SHA3_256", SHA3_256, func(b []byte) []byte { sum := sha3.Sum256(b); return sum[:] }},
		{"SHA3_384", SHA3_384, func(b []byte) []byte { sum := sha3.Sum384(b); return sum[:] }},
		{"SHA3_512", SHA3_512, func(b []byte) []byte { sum := sha3.Sum512(b); return sum[:] }},

		// BLAKE2
		{"BLAKE2s_256", BLAKE2s_256, func(b []byte) []byte { sum := blake2s.Sum256(b); return sum[:] }},
		{"BLAKE2b_256", BLAKE2b_256, func(b []byte) []byte { sum := blake2b.Sum256(b); return sum[:] }},
		{"BLAKE2b_384", BLAKE2b_384, func(b []byte) []byte { sum := blake2b.Sum384(b); return sum[:] }},
		{"BLAKE2b_512", BLAKE2b_512, func(b []byte) []byte { sum := blake2b.Sum512(b); return sum[:] }},

		// BLAKE3
		{"BLAKE3", BLAKE3, func(b []byte) []byte { sum := blake3.Sum256(b); return sum[:] }},
	}

	inputs := [][]byte{
		nil,
		{},
		[]byte(""),
		[]byte("abc"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		make([]byte, 1024), // a block of zeros
	}

	for _, a := range algos {
		a := a
		t.Run(a.name, func(t *testing.T) {
			if !a.algo.IsValid() {
				t.Fatalf("expected IsValid() true for %s", a.name)
			}
			hasher := a.algo.New()
			if hasher == nil {
				t.Fatalf("New() returned nil for %s", a.name)
			}

			for _, in := range inputs {
				got := a.algo.Digest(in)
				want := a.refFunc(in)

				if !bytes.Equal(got, want) {
					t.Fatalf("%s digest mismatch for input %q\n got:  %x\n want: %x",
						a.name, preview(in), got, want)
				}

				// Check reported Size() matches digest length.
				if hasher.Size() != len(want) {
					t.Fatalf("%s hasher.Size()=%d does not match digest len=%d", a.name, hasher.Size(), len(want))
				}
			}
		})
	}
}

func TestHash_IsValid_FalseForUnknown(t *testing.T) {
	var unknown Hash = "UNKNOWN_ALGO"
	if unknown.IsValid() {
		t.Fatalf("expected IsValid() false for unknown algo")
	}
}

func TestHash_Digest_PanicsOnInvalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on invalid hash.Digest, got none")
		}
	}()
	var unknown Hash = "NOT_A_HASH"
	_ = unknown.Digest([]byte("data"))
}

func TestHash_Verify(t *testing.T) {
	data := []byte("some payload to hash and verify")

	algos := []Hash{
		SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256,
		SHA3_224, SHA3_256, SHA3_384, SHA3_512,
		BLAKE2s_256, BLAKE2b_256, BLAKE2b_384, BLAKE2b_512,
		BLAKE3,
	}

	for _, algo := range algos {
		algo := algo
		t.Run(string(algo), func(t *testing.T) {
			sum := algo.Digest(data)

			if err := algo.Verify(data, sum); err != nil {
				t.Fatalf("Verify() returned error for matching checksum: %v", err)
			}

			// Corrupt checksum and expect ErrChecksumMismatch.
			if len(sum) > 0 {
				sum[0] ^= 0xFF
			} else {
				sum = []byte{0x00} // force mismatch
			}
			err := algo.Verify(data, sum)
			if err == nil {
				t.Fatalf("expected error for mismatched checksum, got nil")
			}
			if !errors.Is(err, ErrChecksumMismatch) {
				t.Fatalf("expected ErrChecksumMismatch, got %v", err)
			}
		})
	}
}

func TestValueHasher_Sum_FormatAndDeterminism(t *testing.T) {
	fields := [][]byte{
		[]byte("alpha"),
		nil,
		[]byte{},
		[]byte("beta"),
		[]byte("gamma"),
	}

	algos := []Hash{
		SHA2_256, SHA2_512, SHA3_256, SHA3_512,
		BLAKE2s_256, BLAKE2b_256, BLAKE2b_512,
		BLAKE3,
	}

	for _, algo := range algos {
		algo := algo
		t.Run(string(algo), func(t *testing.T) {
			vh := NewValueHasher(algo)
			for _, f := range fields {
				vh.Add(f)
			}
			sum := vh.Sum()

			hasher := algo.New()
			if hasher == nil {
				t.Fatalf("algo.New() is nil")
			}

			// Expect finisher prefix (16 bytes): [fieldCnt(8)][0xFF * 8]
			if len(sum) < 16+hasher.Size() {
				t.Fatalf("sum too short: got %d, need at least %d", len(sum), 16+hasher.Size())
			}
			prefix := sum[:16]
			tail := sum[16:]

			// Build expected finisher
			var finisher [16]byte
			binary.BigEndian.PutUint64(finisher[:8], uint64(len(fields)))
			for i := 8; i < 16; i++ {
				finisher[i] = 0xFF
			}
			if !bytes.Equal(prefix, finisher[:]) {
				t.Fatalf("finisher prefix mismatch\n got: %x\nwant: %x", prefix, finisher[:])
			}
			if len(tail) != hasher.Size() {
				t.Fatalf("digest tail size mismatch: got %d want %d", len(tail), hasher.Size())
			}

			// Reconstruct the exact stream written by ValueHasher.Add and verify the digest.
			stream := buildValueHasherStream(fields)
			_, _ = hasher.Write(stream)
			expectedDigest := hasher.Sum(nil)

			if !bytes.Equal(tail, expectedDigest) {
				t.Fatalf("tail digest mismatch\n got: %x\nwant: %x", tail, expectedDigest)
			}

			// Determinism: re-run and expect the same output.
			vh2 := NewValueHasher(algo)
			for _, f := range fields {
				vh2.Add(f)
			}
			sum2 := vh2.Sum()
			if !bytes.Equal(sum, sum2) {
				t.Fatalf("non-deterministic result for ValueHasher\n1: %x\n2: %x", sum, sum2)
			}
		})
	}
}

func TestValueHasher_AddString(t *testing.T) {
	algo := SHA2_256

	vh1 := NewValueHasher(algo)
	vh1.Add([]byte("hello"))
	vh1.Add([]byte("world"))

	vh2 := NewValueHasher(algo)
	vh2.AddString("hello")
	vh2.AddString("world")

	if got1, got2 := vh1.Sum(), vh2.Sum(); !bytes.Equal(got1, got2) {
		t.Fatalf("AddString mismatch with Add\nAdd:       %x\nAddString: %x", got1, got2)
	}
}

func TestValueHasher_OrderMatters(t *testing.T) {
	algo := BLAKE2b_256

	vh1 := NewValueHasher(algo)
	vh1.Add([]byte("first"))
	vh1.Add([]byte("second"))

	vh2 := NewValueHasher(algo)
	vh2.Add([]byte("second"))
	vh2.Add([]byte("first"))

	if bytes.Equal(vh1.Sum(), vh2.Sum()) {
		t.Fatalf("expected different sums when field order differs")
	}
}

func TestNewValueHasher_WithInvalidAlgo_PanicsOnUse(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when using ValueHasher with invalid algo")
		}
	}()
	var invalid Hash = "NOPE"
	vh := NewValueHasher(invalid)
	// Should panic on first write due to nil hasher
	vh.Add([]byte("data"))
}

// Helper to build the exact byte stream ValueHasher writes.
func buildValueHasherStream(fields [][]byte) []byte {
	var buf bytes.Buffer
	var id uint64
	var bebuf [8]byte

	for _, f := range fields {
		id++
		binary.BigEndian.PutUint64(bebuf[:], id)
		_, _ = buf.Write(bebuf[:])

		binary.BigEndian.PutUint64(bebuf[:], uint64(len(f)))
		_, _ = buf.Write(bebuf[:])

		if len(f) > 0 {
			_, _ = buf.Write(f)
		}
	}
	return buf.Bytes()
}

func preview(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const max = 32
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}
