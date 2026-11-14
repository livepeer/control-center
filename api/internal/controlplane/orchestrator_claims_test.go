package controlplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestOrchestratorClaimAndMultipleMachines(t *testing.T) {
	s := newTestServer(t)
	onchainSettings(t, s)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	address := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	checks := 0
	s.activeCheck = func(_ context.Context, got string) (bool, error) { checks++; return got == address, nil }
	challenge := request(t, s, "POST", "/api/orchestrators/challenge", "session-a", map[string]string{"address": address})
	requireStatus(t, challenge, 200)
	var issued struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(challenge.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(accounts.TextHash([]byte(issued.Challenge)), key)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27 // livepeer chain sign message emits Ethereum v=27/28.
	encoded := "0x" + hex.EncodeToString(sig)
	claim := map[string]string{"address": address, "challenge": issued.Challenge, "signature": encoded}
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-b", claim), 403)
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-a", claim), 201)
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-a", claim), 409)
	if checks != 3 {
		t.Fatal("activity was not rechecked", checks)
	}
	for _, fingerprint := range []string{strings.Repeat("c", 64), strings.Repeat("d", 64)} {
		grant, _, err := s.params.signEnrollment(ownerA, address, s.currentTime())
		if err != nil {
			t.Fatal(err)
		}
		w := request(t, s, "POST", "/v1/nodes/register", grant, registrationBody(ownerA, fingerprint, grant))
		requireStatus(t, w, 200)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machines WHERE orchestrator_address=$1 AND enrolled_by_user_id=$2`, address, ownerA) != 2 {
		t.Fatal("machines did not retain initiator")
	}
}

func TestOrchestratorClaimFailures(t *testing.T) {
	s := newTestServer(t)
	s.params.Mode = "onchain"
	address := "0x3333333333333333333333333333333333333333"
	s.activeCheck = func(context.Context, string) (bool, error) { return false, nil }
	requireStatus(t, request(t, s, "POST", "/api/orchestrators/challenge", "session-a", map[string]string{"address": address}), 403)
	s.activeCheck = func(context.Context, string) (bool, error) {
		return false, errors.New("wrong chain or RPC unavailable")
	}
	requireStatus(t, request(t, s, "POST", "/api/orchestrators/challenge", "session-a", map[string]string{"address": address}), 503)
	s.activeCheck = func(context.Context, string) (bool, error) { return true, nil }
	requireStatus(t, request(t, s, "POST", "/api/orchestrators/challenge", "session-a", map[string]string{"address": orchA}), 409)
	raw, _, err := s.signOrchestratorClaim(ownerA, address)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-a", map[string]string{"challenge": raw, "signature": "bad"}), 403)
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-a", map[string]string{"challenge": raw + "x", "signature": "bad"}), 403)
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-b", map[string]string{"challenge": raw, "signature": "bad"}), 403)
	s.params.PublicAPIURL = "https://other.example"
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-a", map[string]string{"challenge": raw, "signature": "bad"}), 403)
	s.params.PublicAPIURL = "https://api.example"
	old := s.currentTime().Add(-2 * time.Hour)
	s.now = func() time.Time { return old }
	expired, _, err := s.signOrchestratorClaim(ownerA, address)
	if err != nil {
		t.Fatal(err)
	}
	s.now = nil
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-a", map[string]string{"challenge": expired, "signature": "bad"}), 403)
}

func TestOffchainOrchestratorCreation(t *testing.T) {
	s := newTestServer(t)
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-a", map[string]string{}), 201)
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-b", map[string]string{}), 409)
	requireStatus(t, request(t, s, "POST", "/api/orchestrators", "session-b", map[string]string{"address": "0x4444444444444444444444444444444444444444"}), 201)
	if count(t, s, `SELECT count(*) FROM lpcc.orchestrators WHERE address=$1 AND claimed_by_user_id=$2`, "0x4444444444444444444444444444444444444444", ownerB) != 1 {
		t.Fatal("claimant not saved")
	}
}

func TestConcurrentOrchestratorClaims(t *testing.T) {
	s := newTestServer(t)
	s.params.Mode = "onchain"
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	address := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	s.activeCheck = func(context.Context, string) (bool, error) { return true, nil }
	users := []struct{ id, session string }{{ownerA, "session-a"}, {ownerB, "session-b"}}
	results := make(chan int, 2)
	var group sync.WaitGroup
	for _, user := range users {
		group.Go(func() {
			raw, _, err := s.signOrchestratorClaim(user.id, address)
			if err != nil {
				results <- 0
				return
			}
			sig, err := crypto.Sign(accounts.TextHash([]byte(raw)), key)
			if err != nil {
				results <- 0
				return
			}
			sig[64] += 27
			results <- request(t, s, "POST", "/api/orchestrators", user.session, map[string]string{"address": address, "challenge": raw, "signature": "0x" + hex.EncodeToString(sig)}).Code
		})
	}
	group.Wait()
	close(results)
	seen := map[int]int{}
	for status := range results {
		seen[status]++
	}
	if seen[201] != 1 || seen[409] != 1 {
		t.Fatal(seen)
	}
}

func TestBootstrapRequiresCurrentOnchainActivity(t *testing.T) {
	s := newTestServer(t)
	s.params.Mode = "onchain"
	input := map[string]string{"orchestrator_address": orchA}
	s.activeCheck = func(context.Context, string) (bool, error) { return false, nil }
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token", "session-a", input), 403)
	s.activeCheck = func(context.Context, string) (bool, error) { return false, errors.New("RPC unavailable") }
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token", "session-a", input), 503)
	s.activeCheck = func(context.Context, string) (bool, error) { return true, nil }
	requireStatus(t, request(t, s, "POST", "/api/bootstrap-token", "session-a", input), 200)
}

func TestOrchestratorChallengeSignatureAndBindings(t *testing.T) {
	s := &Server{params: testParams()}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	address := strings.ToLower(crypto.PubkeyToAddress(key.PublicKey).Hex())
	raw, _, err := s.signOrchestratorClaim(ownerA, address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.verifyOrchestratorClaim(raw, ownerA); err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.Sign(accounts.TextHash([]byte(raw)), key)
	if err != nil {
		t.Fatal(err)
	}
	sig[64] += 27
	if got, err := recoverOrchestrator(raw, "0x"+hex.EncodeToString(sig)); err != nil || got != address {
		t.Fatal(got, err)
	}
	if got, err := recoverOrchestrator(raw+"x", "0x"+hex.EncodeToString(sig)); err == nil && got == address {
		t.Fatal("altered challenge recovered signer")
	}
	other, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := crypto.Sign(accounts.TextHash([]byte(raw)), other)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := recoverOrchestrator(raw, "0x"+hex.EncodeToString(wrong)); err == nil && got == address {
		t.Fatal("wrong key accepted")
	}
	if _, err := recoverOrchestrator(raw, "invalid"); err == nil {
		t.Fatal("malformed signature accepted")
	}
	if _, err := s.verifyOrchestratorClaim(raw+"x", ownerA); err == nil {
		t.Fatal("altered token accepted")
	}
	if _, err := s.verifyOrchestratorClaim(raw, ownerB); err == nil {
		t.Fatal("wrong user accepted")
	}
	s.params.PublicAPIURL = "https://other.example"
	if _, err := s.verifyOrchestratorClaim(raw, ownerA); err == nil {
		t.Fatal("wrong service accepted")
	}
	s.params.PublicAPIURL = "https://api.example"
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := s.verifyOrchestratorClaim(raw, ownerA); err == nil {
		t.Fatal("expired challenge accepted")
	}
}
