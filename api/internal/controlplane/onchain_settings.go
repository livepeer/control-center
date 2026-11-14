package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/livepeer/control-center/schema"
)

const mainnetController = "0xd8e8328501e9645d16cf49539efc04f734606ee4"
const zeroAddress = "0x0000000000000000000000000000000000000000"

func (p Params) networkMode() string {
	if p.Mode == "" {
		return "onchain"
	}
	return p.Mode
}

// ConfigureMode makes the deployment mode and chain identity immutable.
func (s *Server) ConfigureMode(ctx context.Context) error {
	mode := s.params.networkMode()
	if mode == "onchain" {
		if _, err := s.loadOnchainTemplate(); err != nil {
			return err
		}
	}
	chainID, controller := int64(0), ""
	if mode == "onchain" {
		chainID, controller = 42161, mainnetController
	}
	var stored string
	err := s.db.QueryRowContext(ctx, `INSERT INTO lpcc.control_center_mode(id,mode,chain_id,controller)
 VALUES(true,$1,$2,$3) ON CONFLICT(id) DO UPDATE SET mode=EXCLUDED.mode
 WHERE lpcc.control_center_mode.mode=EXCLUDED.mode
 AND lpcc.control_center_mode.chain_id=EXCLUDED.chain_id
 AND lpcc.control_center_mode.controller=EXCLUDED.controller
 RETURNING mode`, mode, chainID, controller).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("control center mode and chain identity cannot change after initialization")
	}
	return err
}

func (s *Server) loadOnchainTemplate() (onchain.Config, error) {
	bad := errors.New("invalid Control Center onchain configuration")
	if s.params.OnchainConfigFile == "" || len(s.params.OnchainWebhookSecret) < 32 || !machineconfig.ValidConnectorImage(s.params.RuntimeNodeImage) {
		return onchain.Config{}, bad
	}
	b, err := os.ReadFile(s.params.OnchainConfigFile)
	if err != nil || len(b) > 128<<10 {
		return onchain.Config{}, bad
	}
	var c onchain.Config
	if jsonv2.Unmarshal(b, &c, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)) != nil ||
		c.Version != 1 || c.Mode != "onchain" || c.Network != "arbitrum-one-mainnet" ||
		c.ChainID != 42161 || !strings.EqualFold(c.Controller, mainnetController) ||
		c.Recipient != "" || c.Generation != 0 || c.CredentialRevision != 0 {
		return onchain.Config{}, bad
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return onchain.Config{}, bad
	}
	for _, key := range []string{"recipient", "generation", "credential_revision"} {
		if _, present := fields[key]; present {
			return onchain.Config{}, bad
		}
	}
	c.Controller = mainnetController
	c.ETHUSDFeed = strings.ToLower(c.ETHUSDFeed)
	c.Recipient, c.Generation, c.CredentialRevision = "0x1111111111111111111111111111111111111111", 1, 1
	if c.Validate() != nil {
		return onchain.Config{}, bad
	}
	rpc, err := s.readOnchainRPC(c.RPCSecret)
	if err != nil || onchain.ValidateEndpoint(string(rpc), c.RPCGrants) != nil {
		return onchain.Config{}, bad
	}
	c.Recipient, c.Generation, c.CredentialRevision = "", 0, 0
	return c, nil
}

func loadOnchain(ctx context.Context, q rowQuerier, node string) (onchain.Config, error) {
	return loadInstallationOnchain(ctx, q, `(SELECT fingerprint FROM lpcc.enrollments WHERE node_id=$1)`, node)
}

func loadInstallationOnchain(ctx context.Context, q rowQuerier, key, identity string) (onchain.Config, error) {
	c := onchain.Offchain()
	var b []byte
	err := q.QueryRowContext(ctx, `SELECT c.config FROM lpcc.onchain_state b JOIN lpcc.onchain_configs c ON c.fingerprint=b.fingerprint AND c.generation=b.generation WHERE b.fingerprint=`+key, identity).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	if err == nil {
		err = c.Validate()
	}
	return c, err
}

// readOnchainRPC never exposes a path or a URL in its errors.
func (s *Server) readOnchainRPC(ref string) ([]byte, error) {
	bad := errors.New("onchain RPC secret unavailable")
	if !onchain.SecretRef.MatchString(ref) || !filepath.IsAbs(s.params.OnchainSecretsDir) {
		return nil, bad
	}
	path := filepath.Join(s.params.OnchainSecretsDir, ref)
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, bad
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, bad
	}
	defer f.Close()
	info, e = f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, bad
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return nil, bad
	}
	hash := sha256.Sum256(b)
	if hex.EncodeToString(hash[:]) != ref {
		return nil, bad
	}
	b = []byte(strings.TrimSpace(string(b)))
	u, e := url.Parse(string(b))
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Fragment != "" {
		return nil, bad
	}
	return b, nil
}

// syncOnchainConfig stores the automatic per-installation snapshot consumed by
// configuration rendering and process-scoped redemption grants.
func (s *Server) syncOnchainConfig(ctx context.Context, tx *sql.Tx, fingerprint, address string) (onchain.Config, bool, error) {
	if s.params.networkMode() != "onchain" {
		return onchain.Offchain(), false, nil
	}
	if address == zeroAddress {
		return onchain.Config{}, false, errors.New("onchain orchestrator address required")
	}
	next, err := s.loadOnchainTemplate()
	if err != nil {
		return onchain.Config{}, false, err
	}
	next.Recipient = address
	var raw []byte
	var recipient, controller string
	var chainID, generation int64
	err = tx.QueryRowContext(ctx, `SELECT s.recipient,s.chain_id,s.controller,s.generation,c.config
 FROM lpcc.onchain_state s JOIN lpcc.onchain_configs c ON c.fingerprint=s.fingerprint AND c.generation=s.generation
 WHERE s.fingerprint=$1 FOR UPDATE OF s`, fingerprint).Scan(&recipient, &chainID, &controller, &generation, &raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return onchain.Config{}, false, err
	}
	if err == nil {
		if recipient != address || chainID != 42161 || controller != mainnetController {
			return onchain.Config{}, false, errors.New("onchain recipient and chain identity are immutable")
		}
		var current onchain.Config
		if err = json.Unmarshal(raw, &current); err != nil {
			return onchain.Config{}, false, err
		}
		compare := next
		compare.Generation, compare.CredentialRevision = current.Generation, current.CredentialRevision
		a, _ := json.Marshal(compare)
		b, _ := json.Marshal(current)
		if string(a) == string(b) {
			return current, false, nil
		}
	}
	next.Generation = generation + 1
	next.CredentialRevision = uint64(next.Generation)
	if err = next.Validate(); err != nil {
		return onchain.Config{}, false, err
	}
	raw, err = json.Marshal(next)
	if err != nil {
		return onchain.Config{}, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO lpcc.onchain_configs(fingerprint,generation,config) VALUES($1,$2,$3)`, fingerprint, next.Generation, string(raw)); err != nil {
		return onchain.Config{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO lpcc.onchain_state(fingerprint,recipient,chain_id,controller,generation)
 VALUES($1,$2,42161,$3,$4) ON CONFLICT(fingerprint) DO UPDATE SET generation=EXCLUDED.generation`, fingerprint, address, mainnetController, next.Generation)
	return next, err == nil, err
}

func (s *Server) reconcileOnchain(ctx context.Context) error {
	if s.params.networkMode() != "onchain" {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT fingerprint,orchestrator_address,node_id FROM lpcc.machines ORDER BY fingerprint`)
	if err != nil {
		return err
	}
	type machine struct{ fingerprint, address, node string }
	var machines []machine
	for rows.Next() {
		var m machine
		if err = rows.Scan(&m.fingerprint, &m.address, &m.node); err != nil {
			break
		}
		machines = append(machines, m)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, m := range machines {
		tx, err := s.policyTx(ctx)
		if err != nil {
			return err
		}
		next, changed, err := s.syncOnchainConfig(ctx, tx, m.fingerprint, m.address)
		if err == nil && changed {
			var a *schema.AppAssignmentSetV1
			a, err = machineapps.Snapshot(ctx, tx, m.node)
			if err == nil && a != nil {
				for _, entry := range a.Entries {
					if entry.Revision != nil && entry.Desired == "present" {
						if err = next.Compatible(entry.Revision.Definition); err != nil {
							break
						}
					}
				}
			}
			if err == nil {
				_, err = tx.ExecContext(ctx, `UPDATE lpcc.machine_states SET revision=revision+1,next_attempt_at=now() WHERE node_id=$1`, m.node)
			}
		}
		if err == nil {
			err = tx.Commit()
		} else {
			tx.Rollback()
		}
		if err != nil {
			return err
		}
	}
	return nil
}
