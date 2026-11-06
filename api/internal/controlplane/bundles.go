package controlplane

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"strings"
	"time"
)

//go:embed templates
var templates embed.FS

func buildBundle(m Machine) ([]byte, string, error) {
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
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
		data = []byte(strings.NewReplacer("@NODE_ID@", m.NodeID, "@INSTALL_DIR@", m.InstallDir, "@K3S_VERSION@", m.K3sVersion).Replace(string(data)))
		if bytes.Contains(data, []byte("@INSTALL_DIR@")) || bytes.Contains(data, []byte("@NODE_ID@")) {
			return fmt.Errorf("unresolved template value")
		}
		header := &tar.Header{Name: strings.TrimPrefix(path, "templates/"), Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := archive.WriteHeader(header); err != nil {
			return err
		}
		_, err = archive.Write(data)
		return err
	})
	if err != nil {
		return nil, "", err
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
		}
	}
}

func (s *Server) reconcile(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, owner_id::text, fingerprint, hostname, install_dir, k3s_version FROM lpcc.machines ORDER BY node_id`)
	if err != nil {
		return fmt.Errorf("read machine inventory: %w", err)
	}
	var machines []Machine
	for rows.Next() {
		var m Machine
		if err := rows.Scan(&m.NodeID, &m.OwnerID, &m.Fingerprint, &m.Hostname, &m.InstallDir, &m.K3sVersion); err != nil {
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
		data, digest, err := s.build(m)
		if err != nil {
			s.logger.Error("keeping previous configuration", "node_id", m.NodeID, "error", err)
			continue
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO lpcc.machine_configs(node_id,bundle,sha256) VALUES($1,$2,$3)
   ON CONFLICT(node_id) DO UPDATE SET bundle=EXCLUDED.bundle,sha256=EXCLUDED.sha256,generated_at=now()
   WHERE lpcc.machine_configs.sha256<>EXCLUDED.sha256`, m.NodeID, data, digest); err != nil {
			return err
		}
	}
	return nil
}
