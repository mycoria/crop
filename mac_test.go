package crop

// Note: Partly LLM-Generated.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	mathRand "math/rand"
	"strconv"
	"testing"
)

func TestAuthCode_SignVerify_Simple(t *testing.T) {
	acts := []MsgAuthCodeType{
		MsgAuthCodeTypeHMACBlake3,
	}

	for _, act := range acts {
		t.Run(string(act), func(t *testing.T) {
			// Generate random 32-byte key.
			aKey := make([]byte, 32)
			bKey := make([]byte, 32)
			rand.Read(aKey)
			rand.Read(bKey)

			// Two independent handlers to test both directions.
			a, err := NewAuthCodeHandler(act, aKey, bKey, NewStrictSequenceChecker())
			if err != nil {
				t.Fatalf("unexpected error creating handler A: %v", err)
			}
			b, err := NewAuthCodeHandler(act, bKey, aKey, NewLooseSequenceChecker())
			if err != nil {
				t.Fatalf("unexpected error creating handler B: %v", err)
			}

			// Sign with A, verify with B.
			msg1 := []byte("hello from A")
			mac1 := a.Sign(msg1)
			if err := b.Verify(msg1, mac1); err != nil {
				t.Fatalf("verify failed for A->B: %v (mac: %x)", err, mac1)
			}

			// Sign with B, verify with A.
			msg2 := []byte("hello from B")
			mac2 := b.Sign(msg2)
			if err := a.Verify(msg2, mac2); err != nil {
				t.Fatalf("verify failed for B->A: %v (mac: %x)", err, mac2)
			}

			// Cross-check that wrong message fails.
			if err := a.Verify([]byte("tampered"), mac2); err == nil {
				t.Fatalf("expected verify to fail for tampered message but it succeeded")
			}
		})
	}
}

func TestAuthCode_SignVerify_Randomized_BothDirections(t *testing.T) {
	acts := []MsgAuthCodeType{
		MsgAuthCodeTypeHMACBlake3,
	}

	type entry struct {
		id   string
		data []byte
		mac  []byte
	}

	const messages = 64

	for _, act := range acts {
		t.Run(string(act), func(t *testing.T) {
			// Generate random 32-byte key.
			aKey := make([]byte, 32)
			bKey := make([]byte, 32)
			rand.Read(aKey)
			rand.Read(bKey)

			// Handlers:
			// A signs and B verifies for A->B direction.
			// B signs and A verifies for B->A direction.
			handlerA, err := NewAuthCodeHandler(act, aKey, bKey, NewLooseSequenceChecker())
			if err != nil {
				t.Fatalf("create handlerA: %v", err)
			}
			handlerB, err := NewAuthCodeHandler(act, bKey, aKey, NewLooseSequenceChecker())
			if err != nil {
				t.Fatalf("create handlerB: %v", err)
			}

			AtoB := make([]*entry, 0, messages) // Max supported view of loose seq checker.
			BtoA := make([]*entry, 0, messages) // Max supported view of loose seq checker.

			// Sign for A->B.
			for i := 0; i < messages; i++ {
				data := []byte("A-msg-" + strconv.Itoa(i))
				mac := handlerA.Sign(data)
				AtoB = append(AtoB, &entry{id: string(data), data: data, mac: mac})
			}

			// Sign for B->A.
			for i := 0; i < messages; i++ {
				data := []byte("B-msg-" + strconv.Itoa(i))
				mac := handlerB.Sign(data)
				BtoA = append(BtoA, &entry{id: string(data), data: data, mac: mac})
			}

			// Mix!
			mathRand.Shuffle(len(AtoB), func(i, j int) { AtoB[i], AtoB[j] = AtoB[j], AtoB[i] })
			mathRand.Shuffle(len(BtoA), func(i, j int) { BtoA[i], BtoA[j] = BtoA[j], BtoA[i] })

			// Verify for A->B.
			for _, entry := range AtoB {
				if err := handlerB.Verify(entry.data, entry.mac); err != nil {
					t.Errorf("verify A->B failed at %s: %v", entry.id, err)
				}
				// fmt.Println(entry.id)
			}

			// Verify for B->A.
			for _, entry := range BtoA {
				if err := handlerA.Verify(entry.data, entry.mac); err != nil {
					t.Errorf("verify B->A failed at %s: %v", entry.id, err)
				}
				// fmt.Println(entry.id)
			}
		})
	}
}

func TestAuthCode_ErrorCases(t *testing.T) {
	acts := []MsgAuthCodeType{
		MsgAuthCodeTypeHMACBlake3,
	}

	for _, act := range acts {
		t.Run(string(act), func(t *testing.T) {
			// invalid auth code type
			if _, err := NewAuthCodeHandler(MsgAuthCodeType("INVALID"), []byte{1}, []byte{1}, NewStrictSequenceChecker()); err == nil {
				t.Fatalf("expected error creating handler with invalid auth code type")
			}

			// Generate random 32-byte key.
			aKey := make([]byte, 32)
			bKey := make([]byte, 32)
			rand.Read(aKey)
			rand.Read(bKey)

			signer, err := NewAuthCodeHandler(act, aKey, bKey, NewStrictSequenceChecker())
			if err != nil {
				t.Fatalf("create signer: %v", err)
			}
			verifier, err := NewAuthCodeHandler(act, bKey, aKey, NewStrictSequenceChecker())
			if err != nil {
				t.Fatalf("create verifier: %v", err)
			}

			// 1) too short (no uvarint)
			err = verifier.Verify([]byte("data"), []byte{})
			if err == nil {
				t.Fatalf("expected error for too short mac, got nil")
			}
			if !errors.Is(err, ErrAuthCodeInvalid) {
				t.Fatalf("expected ErrAuthCodeInvalid for too short mac, got: %v", err)
			}

			// 2) serial violation: sign two messages and verify the newer one first on the same verifier
			mac1 := signer.Sign([]byte("first"))
			mac2 := signer.Sign([]byte("second"))
			// verify second first -> ok
			if err := verifier.Verify([]byte("second"), mac2); err != nil {
				t.Fatalf("unexpected verify error for second: %v", err)
			}
			// verify first next -> serial violation
			err = verifier.Verify([]byte("first"), mac1)
			if err == nil {
				t.Fatalf("expected serial violation error but got nil")
			}
			if !errors.Is(err, ErrAuthCodeInvalid) {
				t.Fatalf("expected ErrAuthCodeInvalid for serial violation, got: %v", err)
			}

			// 3) salt too short: craft mac with too-small salt by truncating a valid mac
			orig := signer.Sign([]byte("x"))
			_, serialSize := binary.Uvarint(orig)
			if serialSize <= 0 {
				t.Fatalf("failed to decode uvarint from mac")
			}
			// Determine hasher size based on the original mac and known macSaltSize
			hasherSize := len(orig) - serialSize - macSaltSize
			if hasherSize <= 0 {
				t.Fatalf("unexpected hasher size computed: %d", hasherSize)
			}
			// Build truncated mac where saltSize = macMinSaltSize - 1 (too small)
			newSaltSize := macMinSaltSize - 1
			newLen := serialSize + newSaltSize + hasherSize
			if newLen >= len(orig) {
				// unexpected, but ensure we still create a too-short-salt mac by truncating to something smaller
				newLen = serialSize + (macMinSaltSize - 1) + hasherSize
			}
			if newLen <= 0 || newLen > len(orig) {
				t.Fatalf("unable to construct truncated mac for salt-too-short test")
			}
			trunc := make([]byte, newLen)
			copy(trunc, orig[:newLen])
			err = verifier.Verify([]byte("x"), trunc)
			if err == nil {
				t.Fatalf("expected error for salt-too-short but got nil")
			}
			if !errors.Is(err, ErrAuthCodeInvalid) {
				t.Fatalf("expected ErrAuthCodeInvalid for salt-too-short, got: %v", err)
			}

			// 4) checksum mismatch: tamper with the checksum bytes
			valid := signer.Sign([]byte("payload"))
			// flip a byte in the checksum area (the tail)
			tampered := make([]byte, len(valid))
			copy(tampered, valid)
			if len(tampered) == 0 {
				t.Fatalf("unexpected empty mac")
			}
			tampered[len(tampered)-1] ^= 0xFF
			err = verifier.Verify([]byte("payload"), tampered)
			if err == nil {
				t.Fatalf("expected checksum mismatch to cause error but got nil")
			}
			if !errors.Is(err, ErrAuthCodeInvalid) {
				t.Fatalf("expected ErrAuthCodeInvalid for checksum mismatch, got: %v", err)
			}

			// 5) wrong message (data mismatch)
			valid2 := signer.Sign([]byte("good"))
			if err := verifier.Verify([]byte("bad"), valid2); err == nil {
				t.Fatalf("expected verification failure for wrong data but got nil")
			}
		})
	}
}
