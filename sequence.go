package crop

import (
	"sync"
	"sync/atomic"
)

// SequenceChecker checks sequence numbers and mitigates replay attacks.
type SequenceChecker interface {
	// NextOutSequence returns the next sequence number for an outgoing message.
	NextOutSequence() uint64

	// CheckInSequence checks the sequence number of an incoming message.
	// It returns whether the sequence number is okay and the message may be accepted.
	CheckInSequence(n uint64) (ok bool)
}

// StrictSequenceChecker only allows sequence numbers higher than the highest
// previously received sequence number.
// Note: Using this on message without guaranteed delivery order will result in lost messages.
// Note: Does not roll over and will stop accepting sequence numbers after 2⁶⁴ messages.
type StrictSequenceChecker struct {
	inLock sync.Mutex
	inSeq  uint64

	outSeq atomic.Uint64
}

// NewStrictSequenceChecker returns a new StrictSequenceChecker.
func NewStrictSequenceChecker() *StrictSequenceChecker {
	return &StrictSequenceChecker{}
}

// NextOutSequence returns the next sequence number for an outgoing message.
func (ssc *StrictSequenceChecker) NextOutSequence() uint64 {
	return ssc.outSeq.Add(1)
}

// CheckInSequence checks the sequence number of an incoming message.
// It returns whether the sequence number is okay and the message may be accepted.
func (ssc *StrictSequenceChecker) CheckInSequence(n uint64) (ok bool) {
	ssc.inLock.Lock()
	defer ssc.inLock.Unlock()

	// Check if sequence is equal or smaller than the current sequence.
	if n <= ssc.inSeq {
		return false
	}

	// Save new sequence number.
	ssc.inSeq = n
	return true
}

// LooseSequenceChecker allows some reordering of sequence numbers, up to 64 messages.
// Note: Does not roll over and will stop accepting sequence numbers after 2⁶⁴ messages.
type LooseSequenceChecker struct {
	inLock    sync.Mutex
	inBitMap  uint64
	inHighest uint64

	outSeq atomic.Uint64
}

const fullBitMap = 0xFFFF_FFFF_FFFF_FFFF

// NewLooseSequenceChecker returns a new LooseSequenceChecker.
func NewLooseSequenceChecker() *LooseSequenceChecker {
	return &LooseSequenceChecker{
		inBitMap: fullBitMap, // Start with full bit map.
	}
}

// NextOutSequence returns the next sequence number for an outgoing message.
func (lsc *LooseSequenceChecker) NextOutSequence() uint64 {
	return lsc.outSeq.Add(1)
}

// CheckInSequence checks the sequence number of an incoming message.
// It returns whether the sequence number is okay and the message may be accepted.
func (lsc *LooseSequenceChecker) CheckInSequence(seqNum uint64) (ok bool) {
	lsc.inLock.Lock()
	defer lsc.inLock.Unlock()

	switch {
	case seqNum == lsc.inHighest:
		// This is the same as the highest sequence number we already received.
		// Must be a duplicate.
		return false

	case seqNum > lsc.inHighest:
		// The received sequence number is higher than the previous highest sequence number.
		// Update view bitmap and highest sequence number.
		diff := seqNum - lsc.inHighest
		// Shift bitmap by diff
		lsc.inBitMap <<= diff
		// Update highest value
		lsc.inHighest = seqNum
		return true

	case seqNum < lsc.inHighest:
		// The received sequence number is lower the previous highest sequence number.
		// This means this is either a duplicate or late message.
		// Check the view bitmap.
		diff := lsc.inHighest - seqNum
		// Return if the position would be out of view of the bitmap.
		if diff > 64 {
			return false
		}
		// Calculate position in view bitmap.
		var bitMapPosition uint64 = 1 << (diff - 1)
		// Check if received flag is set in view bitmap.
		if lsc.inBitMap&bitMapPosition > 0 {
			// Received flag is set, this must be a duplicate.
			return false
		}
		// Otherwise, set the received flag.
		lsc.inBitMap |= bitMapPosition
		return true
	}

	// In case something goes wrong, don't accept the message.
	return false
}
