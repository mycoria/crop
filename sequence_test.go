package crop

// Note: LLM-Generated.

import (
	"runtime"
	"sort"
	"sync"
	"testing"
)

func TestStrictSequenceChecker_CheckInSequence_Basic(t *testing.T) {
	t.Parallel()

	ssc := NewStrictSequenceChecker()

	// Initial highest is 0, equal (0) should be rejected.
	if ok := ssc.CheckInSequence(0); ok {
		t.Fatalf("expected seq=0 to be rejected initially")
	}

	// Strictly increasing is accepted.
	if ok := ssc.CheckInSequence(1); !ok {
		t.Fatalf("expected seq=1 to be accepted")
	}
	if ok := ssc.CheckInSequence(2); !ok {
		t.Fatalf("expected seq=2 to be accepted")
	}

	// Equal or lower are rejected.
	if ok := ssc.CheckInSequence(2); ok {
		t.Fatalf("expected duplicate seq=2 to be rejected")
	}
	if ok := ssc.CheckInSequence(1); ok {
		t.Fatalf("expected lower seq=1 to be rejected")
	}

	// Larger is accepted.
	if ok := ssc.CheckInSequence(10); !ok {
		t.Fatalf("expected seq=10 to be accepted")
	}
	if ok := ssc.CheckInSequence(9); ok {
		t.Fatalf("expected lower seq=9 to be rejected")
	}
}

func TestStrictSequenceChecker_NextOutSequence_SequentialAndConcurrent(t *testing.T) {
	t.Parallel()

	ssc := NewStrictSequenceChecker()

	// Sequential
	if got := ssc.NextOutSequence(); got != 1 {
		t.Fatalf("sequential NextOutSequence got=%d want=1", got)
	}
	if got := ssc.NextOutSequence(); got != 2 {
		t.Fatalf("sequential NextOutSequence got=%d want=2", got)
	}

	// Concurrent uniqueness and coverage 1..N
	const N = 2000
	ssc2 := NewStrictSequenceChecker()

	out := make([]uint64, 0, N)
	var mu sync.Mutex
	var wg sync.WaitGroup

	workers := runtime.GOMAXPROCS(0)
	per := N / workers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		count := per
		// last worker picks up remainder
		if w == workers-1 {
			count += N % workers
		}
		go func(n int) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				val := ssc2.NextOutSequence()
				mu.Lock()
				out = append(out, val)
				mu.Unlock()
			}
		}(count)
	}
	wg.Wait()

	if len(out) != N {
		t.Fatalf("collected %d sequence numbers, want %d", len(out), N)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	for i, v := range out {
		want := uint64(i + 1)
		if v != want {
			t.Fatalf("out[%d]=%d want=%d", i, v, want)
		}
	}
}

func TestLooseSequenceChecker_CheckInSequence_Basic(t *testing.T) {
	t.Parallel()

	lsc := NewLooseSequenceChecker()

	// Highest starts at 0; equal (0) is rejected.
	if ok := lsc.CheckInSequence(0); ok {
		t.Fatalf("expected initial seq=0 to be rejected")
	}

	// First higher value accepted.
	if ok := lsc.CheckInSequence(1); !ok {
		t.Fatalf("expected seq=1 to be accepted")
	}
	// Equal to highest rejected.
	if ok := lsc.CheckInSequence(1); ok {
		t.Fatalf("expected duplicate highest seq=1 to be rejected")
	}
	// Lower, within window, is accepted once.
	if ok := lsc.CheckInSequence(0); !ok {
		t.Fatalf("expected late seq=0 to be accepted within window")
	}
	// Same lower value again is duplicate.
	if ok := lsc.CheckInSequence(0); ok {
		t.Fatalf("expected duplicate late seq=0 to be rejected")
	}

	// New higher increases highest.
	if ok := lsc.CheckInSequence(2); !ok {
		t.Fatalf("expected seq=2 to be accepted")
	}
	// Same highest rejected.
	if ok := lsc.CheckInSequence(2); ok {
		t.Fatalf("expected duplicate highest seq=2 to be rejected")
	}
}

func TestLooseSequenceChecker_AcceptsLateWithinWindowAndRejectsBeyond(t *testing.T) {
	t.Parallel()

	lsc := NewLooseSequenceChecker()

	// Jump highest forward a lot; this also resets bitmap effectively via shift.
	if ok := lsc.CheckInSequence(100); !ok {
		t.Fatalf("expected seq=100 to be accepted")
	}

	// Within window (diff == 64) should be accepted.
	if ok := lsc.CheckInSequence(36); !ok { // 100 - 36 = 64
		t.Fatalf("expected seq=36 (diff=64) to be accepted")
	}
	// Duplicate of within-window value should be rejected.
	if ok := lsc.CheckInSequence(36); ok {
		t.Fatalf("expected duplicate seq=36 to be rejected")
	}

	// Just outside window (diff == 65) should be rejected.
	if ok := lsc.CheckInSequence(35); ok { // 100 - 35 = 65
		t.Fatalf("expected seq=35 (diff=65) to be rejected")
	}
}

func TestLooseSequenceChecker_OutOfOrderSeriesWithinWindow(t *testing.T) {
	t.Parallel()

	lsc := NewLooseSequenceChecker()

	// Set a baseline highest
	if ok := lsc.CheckInSequence(10); !ok {
		t.Fatalf("expected seq=10 to be accepted")
	}

	// Accept a series of out-of-order messages within the 64-element window.
	accepts := []uint64{9, 8, 7, 6, 5, 4, 3, 2, 1}
	for _, n := range accepts {
		if ok := lsc.CheckInSequence(n); !ok {
			t.Fatalf("expected late seq=%d to be accepted", n)
		}
		// Duplicate immediately after should be rejected
		if ok := lsc.CheckInSequence(n); ok {
			t.Fatalf("expected duplicate late seq=%d to be rejected", n)
		}
	}

	// New highest values keep being accepted.
	if ok := lsc.CheckInSequence(11); !ok {
		t.Fatalf("expected seq=11 to be accepted")
	}
	if ok := lsc.CheckInSequence(12); !ok {
		t.Fatalf("expected seq=12 to be accepted")
	}
	// Equal (12) rejected
	if ok := lsc.CheckInSequence(12); ok {
		t.Fatalf("expected duplicate highest seq=12 to be rejected")
	}
}

func TestLooseSequenceChecker_NextOutSequence_SequentialAndConcurrent(t *testing.T) {
	t.Parallel()

	lsc := NewLooseSequenceChecker()

	// Sequential
	if got := lsc.NextOutSequence(); got != 1 {
		t.Fatalf("sequential NextOutSequence got=%d want=1", got)
	}
	if got := lsc.NextOutSequence(); got != 2 {
		t.Fatalf("sequential NextOutSequence got=%d want=2", got)
	}

	// Concurrent uniqueness and coverage 1..N
	const N = 1500
	lsc2 := NewLooseSequenceChecker()

	out := make([]uint64, 0, N)
	var mu sync.Mutex
	var wg sync.WaitGroup

	workers := runtime.GOMAXPROCS(0)
	per := N / workers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		count := per
		if w == workers-1 {
			count += N % workers
		}
		go func(n int) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				v := lsc2.NextOutSequence()
				mu.Lock()
				out = append(out, v)
				mu.Unlock()
			}
		}(count)
	}
	wg.Wait()

	if len(out) != N {
		t.Fatalf("collected %d sequence numbers, want %d", len(out), N)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	for i, v := range out {
		want := uint64(i + 1)
		if v != want {
			t.Fatalf("out[%d]=%d want=%d", i, v, want)
		}
	}
}
