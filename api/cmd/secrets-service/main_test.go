package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/livepeer/control-center/api/internal/secretservice"
)

func TestMigrationCommand(t *testing.T) {
	for _, subcommand := range []string{"up", "down", "status"} {
		t.Run(subcommand, func(t *testing.T) {
			cmd := command()
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetArgs([]string{"migrate", subcommand, "--help"})
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Setenv("SECRETS_DATABASE_URL_FILE", "")
	cmd := command()
	cmd.SetArgs([]string{"migrate", "status"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "SECRETS_DATABASE_URL_FILE") {
		t.Fatalf("status should need only the database URL file: %v", err)
	}
}

func TestUpstreamTransports(t *testing.T) {
	for _, tt := range []struct {
		name, auth, control, vault string
		valid                      bool
	}{
		{"private Vault", "https://auth.example", "https://control.example", "https://vault:8200", true},
		{"HTTP private Vault", "https://auth.example", "https://control.example", "http://vault:8200", false},
		{"external Vault", "https://auth.example", "https://control.example", "https://vault.example", true},
		{"HTTP auth", "http://auth.example", "https://control.example", "http://vault:8200", false},
		{"HTTP control", "https://auth.example", "http://control.example", "http://vault:8200", false},
		{"HTTP external Vault", "https://auth.example", "https://control.example", "http://vault.example:8200", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUpstreams(secretservice.Config{SupabaseURL: tt.auth, ControlURL: tt.control, VaultURL: tt.vault})
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v: %v", tt.valid, err)
			}
		})
	}
}
