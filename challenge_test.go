package crop

// Note: LLM-Generated.

import (
	"bytes"
	"errors"
	"testing"
)

func TestChallengeType_IsValid(t *testing.T) {
	t.Parallel()

	if !ChallengeTypeContextHashBl3.IsValid() {
		t.Fatalf("expected ChallengeTypeContextHashBl3 to be valid")
	}
	if ChallengeType("nope").IsValid() {
		t.Fatalf("expected unknown challenge type to be invalid")
	}
}

func TestNewChallenge_InvalidType(t *testing.T) {
	t.Parallel()

	ch, err := NewChallenge(ChallengeType("invalid"), "p", "req", "res")
	if err == nil {
		t.Fatalf("expected error for invalid challenge type")
	}
	if ch != nil {
		t.Fatalf("expected nil Challenge on invalid type")
	}
}

func TestHashedContextChallenge_BasicFlow_Succeeds(t *testing.T) {
	t.Parallel()

	const (
		purpose = "auth"
		reqCtx  = "alice"
		resCtx  = "bob"
	)

	// Requester constructs challenge
	reqCh, err := NewChallenge(ChallengeTypeContextHashBl3, purpose, reqCtx, resCtx)
	if err != nil {
		t.Fatalf("NewChallenge requester: %v", err)
	}
	hReq, ok := reqCh.(*HashedContextChallenge)
	if !ok {
		t.Fatalf("challenge is not *HashedContextChallenge")
	}
	if hReq.hash != BLAKE3 {
		t.Fatalf("hash = %v, want BLAKE3", hReq.hash)
	}
	chal := hReq.GetChallenge()
	if len(chal) != 32 {
		t.Fatalf("GetChallenge len=%d, want 32", len(chal))
	}

	// Responder constructs with SWAPPED roles (this is required by the protocol)
	resCh, err := NewChallenge(ChallengeTypeContextHashBl3, purpose, resCtx, reqCtx)
	if err != nil {
		t.Fatalf("NewChallenge responder(swapped): %v", err)
	}
	hRes := resCh.(*HashedContextChallenge)

	// Responder makes response to requester's challenge
	resp, err := hRes.MakeResponse(chal)
	if err != nil {
		t.Fatalf("MakeResponse error: %v", err)
	}
	if len(resp) == 0 {
		t.Fatalf("expected non-empty response")
	}

	// Requester checks the response
	if err := hReq.CheckResponse(resp); err != nil {
		t.Fatalf("CheckResponse failed: %v", err)
	}
}

func TestHashedContextChallenge_BadResponse_Fails(t *testing.T) {
	t.Parallel()

	// Build proper requester/responder pair
	reqCh, _ := NewChallenge(ChallengeTypeContextHashBl3, "p", "req", "res")
	hReq := reqCh.(*HashedContextChallenge)
	resCh, _ := NewChallenge(ChallengeTypeContextHashBl3, "p", "res", "req")
	hRes := resCh.(*HashedContextChallenge)

	chal := hReq.GetChallenge()

	// Make a valid response, then corrupt it.
	resp, err := hRes.MakeResponse(chal)
	if err != nil {
		t.Fatalf("MakeResponse: %v", err)
	}
	respBad := append([]byte(nil), resp...)
	respBad[0] ^= 0xFF

	err = hReq.CheckResponse(respBad)
	if err == nil {
		t.Fatalf("expected error for corrupted response")
	}
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("expected ErrChallengeFailed, got %v", err)
	}
}

func TestHashedContextChallenge_WrongChallengeBytes_Fails(t *testing.T) {
	t.Parallel()

	const (
		purpose = "file-transfer"
		reqCtx  = "carol"
		resCtx  = "dave"
	)

	// Proper requester/responder pair (responder has swapped roles)
	reqCh, _ := NewChallenge(ChallengeTypeContextHashBl3, purpose, reqCtx, resCtx)
	hReq := reqCh.(*HashedContextChallenge)
	resCh, _ := NewChallenge(ChallengeTypeContextHashBl3, purpose, resCtx, reqCtx)
	hRes := resCh.(*HashedContextChallenge)

	chal := hReq.GetChallenge()

	// Use a wrong challenge (one bit flipped)
	wrong := append([]byte(nil), chal...)
	wrong[len(wrong)-1] ^= 0x80

	respWrong, err := hRes.MakeResponse(wrong)
	if err != nil {
		t.Fatalf("MakeResponse wrong: %v", err)
	}

	if err := hReq.CheckResponse(respWrong); err == nil {
		t.Fatalf("expected CheckResponse to fail with wrong challenge bytes")
	} else if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("expected ErrChallengeFailed, got %v", err)
	}
}

func TestHashedContextChallenge_RolesMustBeSwappedForSuccess(t *testing.T) {
	t.Parallel()

	const (
		purpose = "session"
		reqCtx  = "initiator"
		resCtx  = "responder"
	)

	// Requester's challenge object
	reqCh, _ := NewChallenge(ChallengeTypeContextHashBl3, purpose, reqCtx, resCtx)
	hReq := reqCh.(*HashedContextChallenge)

	// Responder mistakenly uses the SAME roles (not swapped) -> should FAIL
	resChBad, _ := NewChallenge(ChallengeTypeContextHashBl3, purpose, reqCtx, resCtx)
	hResBad := resChBad.(*HashedContextChallenge)

	respBad, _ := hResBad.MakeResponse(hReq.GetChallenge())
	if err := hReq.CheckResponse(respBad); err == nil {
		t.Fatalf("expected CheckResponse to fail when responder does not swap roles")
	}

	// Responder uses swapped roles -> should SUCCEED
	resChGood, _ := NewChallenge(ChallengeTypeContextHashBl3, purpose, resCtx, reqCtx)
	hResGood := resChGood.(*HashedContextChallenge)

	respGood, _ := hResGood.MakeResponse(hReq.GetChallenge())
	if err := hReq.CheckResponse(respGood); err != nil {
		t.Fatalf("expected CheckResponse to succeed when roles are swapped: %v", err)
	}
}

func TestHashedContextChallenge_ResponseVariesWithInputs(t *testing.T) {
	t.Parallel()

	basePurpose := "purpose"
	baseReq := "req"
	baseRes := "res"

	// Base pair
	reqBase, _ := NewChallenge(ChallengeTypeContextHashBl3, basePurpose, baseReq, baseRes)
	hReq := reqBase.(*HashedContextChallenge)
	resBase, _ := NewChallenge(ChallengeTypeContextHashBl3, basePurpose, baseRes, baseReq)
	hRes := resBase.(*HashedContextChallenge)

	baseChal := hReq.GetChallenge()
	baseResp, _ := hRes.MakeResponse(baseChal)

	// Change purpose
	resP, _ := NewChallenge(ChallengeTypeContextHashBl3, basePurpose+"-x", baseRes, baseReq)
	rP, _ := resP.(*HashedContextChallenge).MakeResponse(baseChal)

	// Change requester (and thus responder in the swapped pair)
	resR, _ := NewChallenge(ChallengeTypeContextHashBl3, basePurpose, baseRes, baseReq+"-x")
	rR, _ := resR.(*HashedContextChallenge).MakeResponse(baseChal)

	// Change responder (and thus requester in the swapped pair)
	resS, _ := NewChallenge(ChallengeTypeContextHashBl3, basePurpose, baseRes+"-x", baseReq)
	rS, _ := resS.(*HashedContextChallenge).MakeResponse(baseChal)

	// Change challenge input
	diffChal := append([]byte(nil), baseChal...)
	diffChal[0] ^= 1
	rC, _ := hRes.MakeResponse(diffChal)

	if bytes.Equal(baseResp, rP) {
		t.Fatalf("expected response to differ when purpose changes")
	}
	if bytes.Equal(baseResp, rR) {
		t.Fatalf("expected response to differ when requester context changes")
	}
	if bytes.Equal(baseResp, rS) {
		t.Fatalf("expected response to differ when responder context changes")
	}
	if bytes.Equal(baseResp, rC) {
		t.Fatalf("expected response to differ when challenge input changes")
	}
}

func TestHashedContextChallenge_ResponseMatchesIndependentComputation(t *testing.T) {
	t.Parallel()

	const (
		purpose = "independent-check"
		reqCtx  = "left"
		resCtx  = "right"
	)

	// Requester and swapped responder
	reqCh, _ := NewChallenge(ChallengeTypeContextHashBl3, purpose, reqCtx, resCtx)
	hReq := reqCh.(*HashedContextChallenge)
	resCh, _ := NewChallenge(ChallengeTypeContextHashBl3, purpose, resCtx, reqCtx)
	hRes := resCh.(*HashedContextChallenge)

	chal := hReq.GetChallenge()

	// Response produced by responder
	resp1, err := hRes.MakeResponse(chal)
	if err != nil {
		t.Fatalf("MakeResponse: %v", err)
	}

	// Independent recomputation matching the requester's expected order:
	// fixed string, purpose, requester, responder, challenge.
	vh := NewValueHasher(BLAKE3)
	vh.AddString("hashed context challenge")
	vh.AddString(purpose)
	vh.AddString(reqCtx)
	vh.AddString(resCtx)
	vh.Add(chal)
	resp2 := vh.Sum()

	if !bytes.Equal(resp1, resp2) {
		t.Fatalf("independent computation mismatch\n got: %x\nwant: %x", resp1, resp2)
	}

	// Ensure CheckResponse accepts the response.
	if err := hReq.CheckResponse(resp1); err != nil {
		t.Fatalf("CheckResponse failed for valid response: %v", err)
	}
}