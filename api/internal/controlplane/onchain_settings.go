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
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/j0sh/boa/pkg/boa"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/spf13/cobra"
)

func loadOnchain(ctx context.Context, q rowQuerier, node string) (onchain.Config, error) {
	c := onchain.Offchain()
	var b []byte
	err := q.QueryRowContext(ctx, `SELECT config FROM lpcc.onchain_configs WHERE node_id=$1 ORDER BY generation DESC LIMIT 1`, node).Scan(&b)
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

type onchainInput struct {
	Version  int                       `json:"version"`
	Machines map[string]onchain.Config `json:"machines"`
}
type onchainApplyParams struct {
	ConfigFile string `name:"config" env:"CONTROL_CENTER_CONFIG" configfile:"optional-default" basepath:"source" default:"config.toml" boa:"noconfig"`
	DatabaseParams
	OnchainSecretsDir        string `optional:"true"`
	OnchainWebhookSecret     string `secret:"true" optional:"true"`
	OnchainWebhookSecretFile string `secretfor:"OnchainWebhookSecret" basepath:"source"`
	RuntimeNodeImage         string `env:"RUNTIME_NODE_IMAGE" optional:"true"`
	File                     string `name:"file" boa:"noconfig" descr:"Onchain infrastructure JSON file"`
	ExpectedRevision         int64  `name:"expected-revision" min:"0" boa:"noconfig"`
}

func OnchainCommand() *cobra.Command {
	apply := boa.Cmd[onchainApplyParams]{Use: "apply", Short: "Apply deployment-owned onchain infrastructure", Args: cobra.NoArgs, RunFuncE: func(p *onchainApplyParams, cmd *cobra.Command, _ []string) error {
		b, e := os.ReadFile(p.File)
		if e != nil {
			return errors.New("onchain input unavailable")
		}
		var input onchainInput
		if len(b) > 128<<10 || jsonv2.Unmarshal(b, &input, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)) != nil || input.Version != 1 || len(input.Machines) == 0 || len(input.Machines) > 1000 {
			return errors.New("invalid onchain infrastructure document")
		}
		db, e := OpenDB(cmd.Context(), p.PGConnstr, p.PGPassword)
		if e != nil {
			return e
		}
		defer db.Close()
		s := New(db, Params{OnchainSecretsDir: p.OnchainSecretsDir, OnchainWebhookSecret: p.OnchainWebhookSecret, RuntimeNodeImage: p.RuntimeNodeImage}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		rev, e := s.applyOnchain(cmd.Context(), input, p.ExpectedRevision)
		if e == nil {
			fmt.Fprintln(cmd.OutOrStdout(), rev)
		}
		return e
	}}.ToCobra()
	return boa.Cmd[boa.NoParams]{Use: "onchain", Short: "Deployment onchain configuration", SubCmds: []*cobra.Command{apply}}.ToCobra()
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

func (s *Server) applyOnchain(ctx context.Context, input onchainInput, expected int64) (int64, error) {
	if input.Version != 1 || len(input.Machines) == 0 || len(input.Machines) > 1000 {
		return 0, errors.New("invalid onchain document")
	}
	nodes := make([]string, 0, len(input.Machines))
	for node, c := range input.Machines {
		c.Recipient = strings.ToLower(c.Recipient)
		c.Controller = strings.ToLower(c.Controller)
		c.ETHUSDFeed = strings.ToLower(c.ETHUSDFeed)
		input.Machines[node] = c
		if !regexp.MustCompile(`^lp-[0-9a-f]{16}$`).MatchString(node) || c.Generation != 0 {
			return 0, errors.New("invalid onchain machine identity")
		}
		if e := c.Validate(); e != nil {
			return 0, e
		}
		nodes = append(nodes, node)
		if c.Onchain() {
			if len(s.params.OnchainWebhookSecret) < 32 {
				return 0, errors.New("onchain operation requires a webhook service credential")
			}
			if !machineconfig.ValidConnectorImage(s.params.RuntimeNodeImage) {
				return 0, errors.New("onchain operation requires a pinned wrapper/Node image")
			}
			b, e := s.readOnchainRPC(c.RPCSecret)
			if e != nil {
				return 0, e
			}
			if e := onchain.ValidateEndpoint(string(b), c.RPCGrants); e != nil {
				return 0, e
			}
		}
	}
	sort.Strings(nodes)
	tx, e := s.policyTx(ctx)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	var revision int64
	if e = tx.QueryRowContext(ctx, `SELECT COALESCE(max(generation),0) FROM lpcc.onchain_configs`).Scan(&revision); e != nil {
		return 0, e
	}

	// Import is a complete desired snapshot: omission never silently disables onchain service.
	document, _ := json.Marshal(input.Machines)
	var omitted bool
	if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM (SELECT DISTINCT ON(node_id) node_id,config FROM lpcc.onchain_configs ORDER BY node_id,generation DESC) c WHERE config->>'mode'='onchain' AND NOT ($1::jsonb ? node_id))`, string(document)).Scan(&omitted); e != nil {
		return 0, e
	}
	if omitted {
		return 0, errors.New("explicit offchain intent is required")
	}
	changed := false
	for _, node := range nodes {
		c := input.Machines[node]
		old, e := loadOnchain(ctx, tx, node)
		if e != nil {
			return 0, e
		}
		c.Generation = old.Generation
		before, _ := json.Marshal(old)
		after, _ := json.Marshal(c)
		if string(before) == string(after) {
			continue
		}
		// Same locking order as assignment mutation and configuration publication.
		var epoch string
		e = tx.QueryRowContext(ctx, `SELECT enrollment_epoch::text FROM lpcc.machines WHERE node_id=$1 FOR UPDATE`, node).Scan(&epoch)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return 0, e
		}
		if epoch != "" {
			a, e := machineapps.Snapshot(ctx, tx, node, epoch)
			if e != nil {
				return 0, e
			}
			if a != nil {
				for _, a := range a.Entries {
					if a.Revision != nil && a.Desired == "present" {
						if e = c.Compatible(a.Revision.Definition); e != nil {
							return 0, definitionProblem(e)
						}
					}
				}
			}
		}
		var recipient, controller string
		var chain uint64
		e = tx.QueryRowContext(ctx, `SELECT config->>'recipient',(config->>'chain_id')::bigint,config->>'controller' FROM lpcc.onchain_configs WHERE node_id=$1 AND config->>'mode'='onchain' ORDER BY generation LIMIT 1`, node).Scan(&recipient, &chain, &controller)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return 0, e
		}
		if c.Onchain() {
			if recipient != "" && (!strings.EqualFold(recipient, c.Recipient) || chain != c.ChainID || !strings.EqualFold(controller, c.Controller)) {
				return 0, errors.New("onchain recipient, chain and controller are immutable")
			}
		}
		c.Generation = revision + 1
		after, _ = json.Marshal(c)
		if _, e = tx.ExecContext(ctx, `INSERT INTO lpcc.onchain_configs VALUES($1,$2,$3)`, node, c.Generation, string(after)); e != nil {
			return 0, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE lpcc.machine_states SET revision=revision+1,next_attempt_at=now() WHERE node_id=$1`, node); e != nil {
			return 0, e
		}
		if e = writeAudit(ctx, tx, "system", "deployment:onchain", "onchain.apply", AdminTarget{Kind: "machine", ID: node, Revision: revisionString(c.Generation)}, "success", "changed"); e != nil {
			return 0, e
		}
		changed = true
	}
	if expected > revision || (changed && expected != revision) {
		return 0, problem(409, "onchain_revision_changed", "Onchain infrastructure changed.")
	}
	if changed {
		revision++
	}
	return revision, tx.Commit()
}
