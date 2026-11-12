package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoaCommandsAndSecretHelp(t *testing.T) {
	for _, args := range [][]string{{"serve", "--help"}, {"migrate", "status", "--help"}} {
		cmd := command()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"pg-connstr", "pg-password", "jwt-signing-secret", "machine-token-secret"} {
			if strings.Contains(output.String(), "--"+name+" ") {
				t.Fatal("secret exposed as a CLI flag", name)
			}
		}
		if !strings.Contains(output.String(), "CONTROL_CENTER_CONFIG") {
			t.Fatal("config flag missing from help")
		}
	}
}

func TestMigrationConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, name := range []string{"CONTROL_CENTER_CONFIG", "PG_CONNSTR", "PG_CONNSTR_FILE", "PG_PASSWORD", "PG_PASSWORD_FILE"} {
		t.Setenv(name, "")
	}
	for name, contents := range map[string]string{
		"connection":  "postgres://example:[PG_PASSWORD]@localhost/test?sslmode=disable",
		"password":    "p@ss word",
		"config.toml": "PGConnstrFile = 'connection'\nPGPasswordFile = 'password'\nJWTSigningSecretFile = 'missing'\nMachineTokenSecretFile = 'missing'\n",
	} {
		if err := os.WriteFile(name, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := command()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	cmd.SetContext(ctx)
	cmd.SetArgs([]string{"migrate", "status"})
	if err := cmd.Execute(); err == nil || err.Error() != "PGConnstr must require TLS" {
		t.Fatal("migration must load database settings without reading application secrets", err)
	}
}

func TestOnchainCommandHelpDoesNotExposeSecrets(t *testing.T) {
	cmd := command()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"onchain", "apply", "--help"})
	if e := cmd.Execute(); e != nil {
		t.Fatal(e)
	}
	for _, flag := range []string{"--file", "--expected-revision", "--config"} {
		if !strings.Contains(out.String(), flag) {
			t.Fatal("missing flag", flag)
		}
	}
	for _, secret := range []string{"--onchain-webhook-secret ", "--pg-password "} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("secret CLI flag exposed")
		}
	}
}

func TestOnchainInputRejectsUnknownPricingAndDuplicateFields(t *testing.T) {
	t.Setenv("PG_CONNSTR", "postgres://unused.invalid/no-network")
	for _, body := range []string{
		`{"version":1,"machines":{"lp-aaaaaaaaaaaaaaaa":{"version":1,"mode":"offchain","price":"1"}}}`,
		`{"version":1,"version":1,"machines":{}}`,
		`{"version":2,"machines":{}}`,
	} {
		path := filepath.Join(t.TempDir(), "onchain.json")
		if e := os.WriteFile(path, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		cmd := command()
		cmd.SetArgs([]string{"onchain", "apply", "--config=", "--file", path, "--expected-revision", "0"})
		if e := cmd.Execute(); e == nil || e.Error() != "invalid onchain infrastructure document" {
			t.Fatal("invalid input was not rejected before database access", e)
		}
	}
}
