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
	"github.com/livepeer/control-center/api/internal/controlplane/payments"
	"github.com/livepeer/control-center/runtime/payment"
	"github.com/spf13/cobra"
)

type paymentInput struct {
	Version  int                       `json:"version"`
	Machines map[string]payment.Config `json:"machines"`
}
type paymentApplyParams struct {
	ConfigFile string `name:"config" env:"CONTROL_CENTER_CONFIG" configfile:"optional-default" basepath:"source" default:"config.toml" boa:"noconfig"`
	DatabaseParams
	PaymentSecretsDir        string `optional:"true"`
	PaymentWebhookSecret     string `secret:"true" optional:"true"`
	PaymentWebhookSecretFile string `secretfor:"PaymentWebhookSecret" basepath:"source"`
	RuntimeNodeImage         string `env:"RUNTIME_NODE_IMAGE" optional:"true"`
	File                     string `name:"file" boa:"noconfig" descr:"Payment infrastructure JSON file"`
	AcknowledgeRecovery      string `name:"acknowledge-recovery" optional:"true" boa:"noconfig" descr:"Confirm restored retained state after a fresh empty-queue observation"`
	ExpectedRevision         int64  `name:"expected-revision" min:"0" boa:"noconfig"`
}

func PaymentsCommand() *cobra.Command {
	apply := boa.Cmd[paymentApplyParams]{Use: "apply", Short: "Apply deployment-owned payment infrastructure", Args: cobra.NoArgs, RunFuncE: func(p *paymentApplyParams, cmd *cobra.Command, _ []string) error {
		b, e := os.ReadFile(p.File)
		if e != nil {
			return errors.New("payment input unavailable")
		}
		var input paymentInput
		if len(b) > 128<<10 || jsonv2.Unmarshal(b, &input, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)) != nil || input.Version != 1 || len(input.Machines) == 0 || len(input.Machines) > 1000 {
			return errors.New("invalid payment infrastructure document")
		}
		db, e := OpenDB(cmd.Context(), p.PGConnstr, p.PGPassword)
		if e != nil {
			return e
		}
		defer db.Close()
		s := New(db, Params{PaymentSecretsDir: p.PaymentSecretsDir, PaymentWebhookSecret: p.PaymentWebhookSecret, RuntimeNodeImage: p.RuntimeNodeImage}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		rev, e := s.applyPayments(cmd.Context(), input, p.ExpectedRevision, p.AcknowledgeRecovery)
		if e == nil {
			fmt.Fprintln(cmd.OutOrStdout(), rev)
		}
		return e
	}}.ToCobra()
	return boa.Cmd[boa.NoParams]{Use: "payments", Short: "Deployment payment configuration", SubCmds: []*cobra.Command{apply}}.ToCobra()
}

// readPaymentRPC never exposes a path or a URL in its errors.
func (s *Server) readPaymentRPC(ref string) ([]byte, error) {
	bad := errors.New("payment RPC secret unavailable")
	if !payment.SecretRef.MatchString(ref) || !filepath.IsAbs(s.params.PaymentSecretsDir) {
		return nil, bad
	}
	path := filepath.Join(s.params.PaymentSecretsDir, ref)
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
	b = []byte(strings.TrimSpace(string(b)))
	u, e := url.Parse(string(b))
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Fragment != "" {
		return nil, bad
	}
	return b, nil
}

func (s *Server) applyPayments(ctx context.Context, input paymentInput, expected int64, acknowledge ...string) (int64, error) {
	if input.Version != 1 || len(input.Machines) == 0 || len(input.Machines) > 1000 {
		return 0, errors.New("invalid payment document")
	}
	nodes := make([]string, 0, len(input.Machines))
	fingerprints := map[string]string{}
	for node, c := range input.Machines {
		c.Recipient = strings.ToLower(c.Recipient)
		c.Controller = strings.ToLower(c.Controller)
		c.ETHUSDFeed = strings.ToLower(c.ETHUSDFeed)
		input.Machines[node] = c
		if !regexp.MustCompile(`^lp-[0-9a-f]{16}$`).MatchString(node) || c.Generation != 0 {
			return 0, errors.New("invalid payment machine identity")
		}
		if e := c.Validate(); e != nil {
			return 0, e
		}
		nodes = append(nodes, node)
		if c.Paid() {
			if len(s.params.PaymentWebhookSecret) < 32 {
				return 0, errors.New("paid operation requires a webhook service credential")
			}
			if !machineconfigImage(s.params.RuntimeNodeImage) {
				return 0, errors.New("paid operation requires a pinned wrapper/Node image")
			}
			b, e := s.readPaymentRPC(c.RPCSecret)
			if e != nil {
				return 0, e
			}
			if e := payment.ValidateEndpoint(string(b), c.RPCGrants); e != nil {
				return 0, e
			}
			h := sha256.Sum256(b)
			fingerprints[c.RPCSecret] = hex.EncodeToString(h[:])
		}
	}
	sort.Strings(nodes)
	tx, e := s.policyTx(ctx)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	var revision int64
	if e = tx.QueryRowContext(ctx, `SELECT revision FROM lpcc.payment_revision WHERE id=true FOR UPDATE`).Scan(&revision); e != nil {
		return 0, e
	}

	// Import is a complete desired snapshot: omission never silently disables paid service.
	rows, e := tx.QueryContext(ctx, `SELECT node_id FROM lpcc.payment_machines WHERE config->>'mode'='paid'`)
	if e != nil {
		return 0, e
	}
	for rows.Next() {
		var n string
		if e = rows.Scan(&n); e != nil {
			break
		}
		if _, ok := input.Machines[n]; !ok {
			e = errors.New("explicit offchain intent is required")
			break
		}
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return 0, e
	}
	for ref, digest := range fingerprints {
		var old string
		e = tx.QueryRowContext(ctx, `SELECT fingerprint FROM lpcc.payment_secrets WHERE reference=$1`, ref).Scan(&old)
		if e == nil && old != digest {
			return 0, errors.New("referenced payment secret versions are immutable")
		}
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return 0, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO lpcc.payment_secrets(reference,fingerprint) VALUES($1,$2) ON CONFLICT DO NOTHING`, ref, digest); e != nil {
			return 0, e
		}
	}
	changed := false
	for _, node := range nodes {
		c := input.Machines[node]
		old, e := payments.Load(ctx, tx, node)
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
		e = tx.QueryRowContext(ctx, `SELECT recipient,chain_id,controller FROM lpcc.payment_machines WHERE node_id=$1 FOR UPDATE`, node).Scan(&recipient, &chain, &controller)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return 0, e
		}
		if c.Paid() {
			if recipient != "" && (!strings.EqualFold(recipient, c.Recipient) || chain != c.ChainID || !strings.EqualFold(controller, c.Controller)) {
				return 0, errors.New("payment recipient and chain binding are immutable")
			}
			recipient = strings.ToLower(c.Recipient)
			chain = c.ChainID
			controller = strings.ToLower(c.Controller)
			c.Recipient = recipient
			c.Controller = controller
		}
		c.Generation = old.Generation + 1
		after, _ = json.Marshal(c)
		_, e = tx.ExecContext(ctx, `INSERT INTO lpcc.payment_machines(node_id,recipient,chain_id,controller,generation,config) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(node_id) DO UPDATE SET recipient=EXCLUDED.recipient,chain_id=EXCLUDED.chain_id,controller=EXCLUDED.controller,generation=EXCLUDED.generation,config=EXCLUDED.config,drained=false`, node, recipient, chain, controller, c.Generation, string(after))
		if e != nil {
			return 0, e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO lpcc.payment_versions VALUES($1,$2,$3)`, node, c.Generation, string(after)); e != nil {
			return 0, e
		}
		if _, e = tx.ExecContext(ctx, `UPDATE lpcc.machine_states SET revision=revision+1,next_attempt_at=now() WHERE node_id=$1`, node); e != nil {
			return 0, e
		}
		if e = writeAudit(ctx, tx, "system", "deployment:payments", "payment.apply", AdminTarget{Kind: "machine", ID: node, Revision: revisionString(c.Generation)}, "success", "changed"); e != nil {
			return 0, e
		}
		changed = true
	}
	if len(acknowledge) > 0 && acknowledge[0] != "" {
		node := acknowledge[0]
		if _, ok := input.Machines[node]; !ok {
			return 0, errors.New("recovery acknowledgement requires the machine in the desired snapshot")
		}
		// Freeze publication and enrollment while checking the evidence against
		// the currently delivered workload, including configuration-only changes.
		var bundle []byte
		if e = tx.QueryRowContext(ctx, `SELECT c.bundle FROM lpcc.machines m JOIN lpcc.machine_configs c USING(node_id) WHERE m.node_id=$1 FOR UPDATE OF m`, node).Scan(&bundle); e != nil {
			return 0, errors.New("recovery acknowledgement requires a delivered configuration")
		}
		metadata, _, e := machineconfig.ReadApplied(bundle)
		if e != nil {
			return 0, e
		}
		var required bool
		if e = tx.QueryRowContext(ctx, `SELECT recovery_required FROM lpcc.payment_machines WHERE node_id=$1 FOR UPDATE`, node).Scan(&required); e != nil {
			return 0, e
		}
		if required {
			var ready bool
			e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.machines m JOIN lpcc.machine_reports r ON r.node_id=m.node_id AND r.epoch=m.enrollment_epoch AND r.credential_version=m.credential_version JOIN lpcc.payment_machines p ON p.node_id=m.node_id JOIN lpcc.payment_grants g ON g.grant_id::text=r.report#>>'{payment,grant_id}' AND g.node_id=m.node_id AND g.epoch=m.enrollment_epoch WHERE m.node_id=$1 AND r.component='runtime' AND r.generation=$2 AND r.report->>'config_digest'=$3 AND g.config_digest=$3 AND g.pod_uid=r.report#>>'{payment,pod_uid}' AND g.payment_generation=p.generation AND r.received_at>now()-interval '2 minutes' AND (r.report->>'observed_at')::timestamptz>now()-interval '2 minutes' AND NOT COALESCE((r.report->>'clock_uncertain')::boolean,false) AND r.report#>>'{payment,applied}'='true' AND r.report#>>'{payment,queue_known}'='true' AND r.report#>>'{payment,unsettled}'='0' AND (r.report#>>'{payment,generation}')::bigint=p.generation AND g.observed_at IS NOT NULL AND g.revoked_at IS NULL)`, node, metadata.Generation, metadata.ConfigDigest).Scan(&ready)
			if e != nil {
				return 0, e
			}
			if !ready {
				return 0, errors.New("restore payment state and obtain fresh zero-unsettled evidence before acknowledging recovery")
			}
			if _, e = tx.ExecContext(ctx, `UPDATE lpcc.payment_machines SET recovery_required=false WHERE node_id=$1`, node); e != nil {
				return 0, e
			}
			if e = writeAudit(ctx, tx, "system", "deployment:payments", "payment.recover", AdminTarget{Kind: "machine", ID: node, Revision: revisionString(revision + 1)}, "success", "recovery_acknowledged"); e != nil {
				return 0, e
			}
			changed = true
		}
	}
	if expected > revision || (changed && expected != revision) {
		return 0, problem(409, "payment_revision_changed", "Payment infrastructure changed.")
	}
	if changed {
		revision++
		if _, e = tx.ExecContext(ctx, `UPDATE lpcc.payment_revision SET revision=$1 WHERE id=true`, revision); e != nil {
			return 0, e
		}
	}
	return revision, tx.Commit()
}

func machineconfigImage(s string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}$`).MatchString(s)
}
