package controlplane

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/livepeer/control-center/api/internal/controlplane/payments"
	"github.com/livepeer/control-center/api/internal/migrations"
	"github.com/livepeer/control-center/api/internal/testdb"
	"github.com/livepeer/control-center/runtime/payment"
)

func TestPaymentMigrationPreservesExistingOffchainMachine(t *testing.T) {
	db := testdb.Open(t)
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	prior := fstest.MapFS{}
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() >= "009_" {
			continue
		}
		data, err := fs.ReadFile(files, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		prior[entry.Name()] = &fstest.MapFile{Data: data}
	}
	if err := migrations.Up(t.Context(), db, prior); err != nil {
		t.Fatal(err)
	}
	// These are the hashes already recorded by main, not hashes recomputed from
	// this branch. Editing either historical migration must reject this upgrade.
	if _, err := db.Exec(`UPDATE lpcc.migrations SET sha256=CASE version
	 WHEN 1 THEN '3faa2618112eb2080dac3cf9e8da1dbead8460e2c2c0b361a33c8c869ea46951'
	 WHEN 7 THEN 'ef717f935c921d5f9f5fd683e2bd3643e275fc273f5f5f8abf4ac3efcb30d23c'
	 END WHERE version IN (1,7)`); err != nil {
		t.Fatal(err)
	}
	const node = "lp-aaaaaaaaaaaaaaaa"
	const bundle = "retained pre-payment bundle"
	if _, err := db.Exec(`INSERT INTO auth.users(id,email) VALUES($1,'existing@example.invalid')`, ownerA); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO lpcc.machines(node_id,fingerprint,owner_id,hostname,install_dir,k3s_version)
	 VALUES($1,$2,$3,'existing','/srv/livepeer','v1.37.2+k3s1')`, node, strings.Repeat("a", 64), ownerA); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO lpcc.machine_configs(node_id,bundle,sha256) VALUES($1,$2,$3)`, node, []byte(bundle), strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	config, err := payments.Load(t.Context(), db, node)
	if err != nil || config.Mode != "offchain" || config.Generation != 0 {
		t.Fatal("existing machine acquired payment settings", config, err)
	}
	var retained []byte
	if err := db.QueryRow(`SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, node).Scan(&retained); err != nil || !bytes.Equal(retained, []byte(bundle)) {
		t.Fatal("migration changed the existing bundle", err)
	}
	// The replacement retirement trigger must also work for existing machines
	// without payment records, retaining the same pre-upgrade bundle.
	if _, err := db.Exec(`DELETE FROM lpcc.machines WHERE node_id=$1`, node); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT retained_bundle FROM lpcc.enrollments WHERE node_id=$1`, node).Scan(&retained); err != nil || !bytes.Equal(retained, []byte(bundle)) {
		t.Fatal("retirement lost the existing bundle", err)
	}
}

func TestPaymentMigrationRollbackPreservesPaymentHistory(t *testing.T) {
	s := newTestServer(t)
	config := onchainSettings(t, s)
	if _, err := s.applyPayments(t.Context(), paymentInput{Version: 1, Machines: map[string]payment.Config{"lp-aaaaaaaaaaaaaaaa": config}}, 0); err != nil {
		t.Fatal(err)
	}
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Down(t.Context(), s.db, files); err == nil || !strings.Contains(err.Error(), "retain payment schema") {
		t.Fatal("rollback did not protect payment history", err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.payment_versions`) != 1 {
		t.Fatal("rollback discarded payment history")
	}
}
