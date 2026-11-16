package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
	protocol "github.com/livepeer/control-center/secrets"
	"github.com/livepeer/node/eth"
)

const orchestratorClaimAudience = "livepeer-orchestrator-claim"

type orchestratorClaim struct {
	jwt.RegisteredClaims
	Scope               string `json:"scope"`
	ControlCenter       string `json:"control_center"`
	OrchestratorAddress string `json:"orchestrator_address"`
}

func (s *Server) signOrchestratorClaim(user, address string) (string, time.Time, error) {
	now := s.currentTime()
	expires := now.Add(time.Hour).Truncate(time.Second)
	claims := orchestratorClaim{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: enrollmentIssuer, Subject: user, Audience: jwt.ClaimStrings{orchestratorClaimAudience},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(expires), ID: uuid.New().String(),
		},
		Scope: "orchestrators:claim", ControlCenter: strings.TrimRight(s.params.PublicAPIURL, "/"),
		OrchestratorAddress: address,
	}
	raw, err := s.params.signJWT(claims)
	return raw, expires, err
}

func (s *Server) verifyOrchestratorClaim(raw, user string) (*orchestratorClaim, error) {
	keys, err := s.params.enrollmentKeys()
	if err != nil {
		return nil, err
	}
	claims := new(orchestratorClaim)
	_, err = jwt.ParseWithClaims(raw, claims, keys.Key, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(enrollmentIssuer),
		jwt.WithAudience(orchestratorClaimAudience), jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(), jwt.WithTimeFunc(s.currentTime))
	if err != nil || claims.Subject != user || claims.Scope != "orchestrators:claim" ||
		claims.ControlCenter != strings.TrimRight(s.params.PublicAPIURL, "/") ||
		len(claims.Audience) != 1 || claims.Audience[0] != orchestratorClaimAudience ||
		claims.IssuedAt == nil || claims.ExpiresAt == nil ||
		claims.IssuedAt.After(s.currentTime()) || !claims.ExpiresAt.After(claims.IssuedAt.Time) ||
		claims.ExpiresAt.Sub(claims.IssuedAt.Time) > time.Hour {
		return nil, errors.New("invalid or expired orchestrator challenge")
	}
	id, idErr := uuid.Parse(claims.ID)
	address, addrErr := protocol.OrchestratorAddress(claims.OrchestratorAddress)
	if idErr != nil || id == uuid.Nil() || addrErr != nil || address == zeroAddress || address != claims.OrchestratorAddress {
		return nil, errors.New("invalid orchestrator challenge")
	}
	return claims, nil
}

func recoverOrchestrator(raw, encoded string) (string, error) {
	signature, err := hexutil.Decode(encoded)
	if err != nil || len(signature) != crypto.SignatureLength {
		return "", errors.New("invalid orchestrator signature")
	}
	switch signature[64] {
	case 27, 28:
		signature[64] -= 27
	case 0, 1:
	default:
		return "", errors.New("invalid orchestrator signature")
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	if !crypto.ValidateSignatureValues(signature[64], r, s, true) {
		return "", errors.New("invalid orchestrator signature")
	}
	public, err := crypto.SigToPub(accounts.TextHash([]byte(raw)), signature)
	if err != nil {
		return "", errors.New("invalid orchestrator signature")
	}
	return strings.ToLower(crypto.PubkeyToAddress(*public).Hex()), nil
}

func (s *Server) checkActive(ctx context.Context, address string) (bool, error) {
	if s.activeCheck != nil {
		return s.activeCheck(ctx, address)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	template, err := s.loadOnchainTemplate()
	if err != nil {
		return false, err
	}
	b, err := s.readOnchainRPC(template.RPCSecret)
	if err != nil {
		return false, err
	}
	rpc, err := eth.OpenRPC(string(b))
	if err != nil {
		return false, err
	}
	defer rpc.Close()
	if err = rpc.CheckChainID(ctx, big.NewInt(42161)); err != nil {
		return false, err
	}
	contracts, err := eth.OpenContracts(rpc, mainnetController)
	if err != nil {
		return false, err
	}
	inspection, err := contracts.Inspect(ctx)
	if err != nil {
		return false, err
	}
	values, err := inspection.Call(ctx, "bondingManager", "isActiveTranscoder", common.HexToAddress(address))
	if err != nil || len(values) != 1 {
		return false, errors.New("orchestrator activity unavailable")
	}
	active, ok := values[0].(bool)
	if !ok {
		return false, errors.New("orchestrator activity unavailable")
	}
	return active, nil
}

func (s *Server) orchestratorChallenge(w http.ResponseWriter, r *http.Request) {
	user, err := s.user(r.Context(), bearer(r))
	if err != nil {
		s.respondError(w, err)
		return
	}
	if s.params.networkMode() != "onchain" {
		fail(w, 404, "onchain orchestrator proof is unavailable")
		return
	}
	var in struct {
		Address string `json:"address"`
	}
	if boundedInput(r, &in, 4096) != nil {
		fail(w, 400, "invalid orchestrator address")
		return
	}
	address, err := protocol.OrchestratorAddress(in.Address)
	if err != nil || address == zeroAddress {
		fail(w, 400, "invalid orchestrator address")
		return
	}
	var exists bool
	if err = s.db.QueryRowContext(r.Context(), `SELECT EXISTS(SELECT FROM lpcc.orchestrators WHERE address=$1)`, address).Scan(&exists); err != nil {
		s.databaseError(w, err)
		return
	}
	if exists {
		s.respondError(w, problem(409, "orchestrator_claimed", "This orchestrator has already been claimed."))
		return
	}
	active, err := s.checkActive(r.Context(), address)
	if err != nil {
		s.respondError(w, problem(503, "chain_unavailable", "Could not verify orchestrator activity. Try again."))
		return
	}
	if !active {
		s.respondError(w, problem(403, "orchestrator_inactive", "Orchestrator is not active on chain."))
		return
	}
	challenge, expires, err := s.signOrchestratorClaim(user.ID, address)
	if err != nil {
		fail(w, 500, "could not issue orchestrator challenge")
		return
	}
	respond(w, 200, map[string]any{"challenge": challenge, "expires_at": expires})
}

func (s *Server) createOrchestrator(w http.ResponseWriter, r *http.Request) {
	user, err := s.user(r.Context(), bearer(r))
	if err != nil {
		s.respondError(w, err)
		return
	}
	var in struct {
		Address   string `json:"address"`
		Challenge string `json:"challenge"`
		Signature string `json:"signature"`
	}
	if boundedInput(r, &in, 16384) != nil {
		fail(w, 400, "invalid orchestrator claim")
		return
	}
	address, proofID := in.Address, sql.NullString{}
	if s.params.networkMode() == "onchain" {
		claim, err := s.verifyOrchestratorClaim(in.Challenge, user.ID)
		if err != nil {
			fail(w, 403, "invalid or expired orchestrator challenge")
			return
		}
		address = claim.OrchestratorAddress
		if in.Address != "" && !strings.EqualFold(in.Address, address) {
			fail(w, 403, "orchestrator address mismatch")
			return
		}
		signer, err := recoverOrchestrator(in.Challenge, in.Signature)
		if err != nil || signer != address {
			fail(w, 403, "orchestrator signature does not match address")
			return
		}
		active, err := s.checkActive(r.Context(), address)
		if err != nil {
			s.respondError(w, problem(503, "chain_unavailable", "Could not verify orchestrator activity. Try again."))
			return
		}
		if !active {
			s.respondError(w, problem(403, "orchestrator_inactive", "Orchestrator is not active on chain."))
			return
		}
		proofID = sql.NullString{String: claim.ID, Valid: true}
	} else if address == "" {
		address = zeroAddress
	}
	address, err = protocol.OrchestratorAddress(address)
	if err != nil || (s.params.networkMode() == "onchain" && address == zeroAddress) {
		fail(w, 400, "invalid orchestrator address")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.databaseError(w, err)
		return
	}
	defer tx.Rollback()
	var inserted string
	err = tx.QueryRowContext(r.Context(), `INSERT INTO lpcc.orchestrators(address,claimed_by_user_id,proof_jti)
 VALUES($1,$2,$3) ON CONFLICT(address) DO NOTHING RETURNING address`, address, user.ID, proofID).Scan(&inserted)
	if errors.Is(err, sql.ErrNoRows) {
		s.respondError(w, problem(409, "orchestrator_claimed", "This orchestrator has already been claimed."))
		return
	}
	if err != nil {
		s.databaseError(w, err)
		return
	}
	if _, err = tx.ExecContext(r.Context(), `INSERT INTO lpcc.orchestrator_memberships(user_id,orchestrator_address) VALUES($1,$2)`, user.ID, address); err != nil {
		s.databaseError(w, err)
		return
	}
	if err = tx.Commit(); err != nil {
		s.databaseError(w, err)
		return
	}
	respond(w, 201, map[string]string{"address": address})
}
