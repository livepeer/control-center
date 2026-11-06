package main

import (
	"bytes"
	"context"
	"os"
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
