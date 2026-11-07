package controlplane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"
)

//go:embed templates
var templates embed.FS

func buildBundle(m Machine) ([]byte, string, error) {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	files := map[string][]byte{}
	err := fs.WalkDir(templates, "templates", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := templates.ReadFile(path)
		if err != nil {
			return err
		}
		data = []byte(renderMachineTemplate(string(data), m))
		if bytes.Contains(data, []byte("@INSTALL_DIR@")) || bytes.Contains(data, []byte("@NODE_ID@")) {
			return fmt.Errorf("unresolved template value")
		}
		files[strings.TrimPrefix(path, "templates/")] = data
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if err = addRoutingBundle(files, m); err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := files[name]
		header := &tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err = archive.WriteHeader(header); err != nil {
			return nil, "", err
		}
		if _, err = archive.Write(data); err != nil {
			return nil, "", err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, "", err
	}
	if err := compressed.Close(); err != nil {
		return nil, "", err
	}
	if output.Len() > 16<<20 {
		return nil, "", fmt.Errorf("configuration archive exceeds 16 MiB")
	}
	digest := sha256.Sum256(output.Bytes())
	return output.Bytes(), hex.EncodeToString(digest[:]), nil
}

func (s *Server) Reconcile(ctx context.Context) {
	run := func() {
		if s.discovery != nil {
			sourceCtx, stop := context.WithTimeout(ctx, 30*time.Second)
			err := s.discovery.Reconcile(sourceCtx)
			stop()
			if err != nil && ctx.Err() == nil {
				s.logger.Error("fleet discovery reconciliation failed", "reason", "reconcile_failed")
			}
		}
		passCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := s.reconcile(passCtx); err != nil && ctx.Err() == nil {
			s.logger.Error("configuration reconciliation failed", "error", err)
		}
	}
	run()
	ticker := time.NewTicker(s.params.ConfigReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		case <-s.reconcileWake:
			run()
		}
	}
}

func (s *Server) reconcile(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, owner_id::text, fingerprint, hostname, install_dir, k3s_version, epoch::text,credential_version,retired_at IS NOT NULL FROM lpcc.enrollments ORDER BY node_id,epoch`)
	if err != nil {
		return fmt.Errorf("read machine inventory: %w", err)
	}
	var machines []Machine
	for rows.Next() {
		var m Machine
		if err := rows.Scan(&m.NodeID, &m.OwnerID, &m.Fingerprint, &m.Hostname, &m.InstallDir, &m.K3sVersion, &m.Epoch, &m.CredentialVersion, &m.Terminal); err != nil {
			rows.Close()
			return err
		}
		machines = append(machines, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, m := range machines {
		m.ControlAPIURL = s.params.PublicAPIURL
		m.TunnelConfig = &s.params.TunnelParams
		routingRevision := int64(0)
		if state, rev, e := s.loadTunnel(ctx, m.NodeID, m.Epoch); e == nil {
			m.Routing = &state
			routingRevision = rev
		} else {
			var expected *apiProblem
			if !errors.As(e, &expected) || expected.status != 409 {
				return e
			}
		}
		if err := s.holdUnapprovedConfiguration(ctx, &m); err != nil {
			return err
		}
		data, digest, err := s.build(m)
		if err != nil {
			s.logger.Error("keeping previous configuration", "node_id", m.NodeID, "error", err)
			continue
		}
		if m.Terminal {
			if _, err = s.db.ExecContext(ctx, `UPDATE lpcc.enrollments SET terminal_bundle=$3,terminal_sha256=$4 WHERE node_id=$1 AND epoch=$2 AND retired_at IS NOT NULL AND terminal_bundle IS NULL`, m.NodeID, m.Epoch, data, digest); err != nil {
				return err
			}
			continue
		}
		if err := s.publishActiveBundle(ctx, m, routingRevision, data, digest); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) publishActiveBundle(ctx context.Context, m Machine, revision int64, data []byte, digest string) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var present int
	// Serialize enrollment refresh/removal and first tunnel-state creation. Lock
	// the artifact before reading its routing fence, so row-lock waits cannot
	// turn an earlier READ COMMITTED snapshot into a stale publication.
	e = tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machines WHERE node_id=$1 AND enrollment_epoch=$2 AND credential_version=$3 FOR UPDATE`, m.NodeID, m.Epoch, m.CredentialVersion).Scan(&present)
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	e = tx.QueryRowContext(ctx, `SELECT 1 FROM lpcc.machine_configs WHERE node_id=$1 FOR UPDATE`, m.NodeID).Scan(&present)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	var current int64
	e = tx.QueryRowContext(ctx, `SELECT revision FROM lpcc.machine_tunnels WHERE node_id=$1 AND epoch=$2 FOR SHARE`, m.NodeID, m.Epoch).Scan(&current)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if current != revision {
		return nil
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO lpcc.machine_configs(node_id,bundle,sha256) VALUES($1,$2,$3) ON CONFLICT(node_id) DO UPDATE SET bundle=EXCLUDED.bundle,sha256=EXCLUDED.sha256,generated_at=now() WHERE lpcc.machine_configs.sha256<>EXCLUDED.sha256`, m.NodeID, data, digest); e != nil {
		return e
	}
	return tx.Commit()
}
