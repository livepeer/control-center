package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/j0sh/boa/pkg/boa"
)

func TestCommands(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"migrate", "up", "--help"}, {"migrate", "down", "--help"}, {"migrate", "status", "--help"}} {
		cmd := command()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(output.String(), "SECRETS_DATABASE_URL_FILE") {
			t.Fatalf("%v: prefixed database environment variable missing from help", args)
		}
	}
	t.Setenv("SECRETS_DATABASE_URL", "")
	t.Setenv("SECRETS_DATABASE_URL_FILE", "")
	cmd := command()
	cmd.SetArgs([]string{"migrate", "status"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "database-url") {
		t.Fatalf("status should need only the database URL file: %v", err)
	}
	t.Chdir(t.TempDir())
	if err := os.WriteFile("database", []byte("postgres://localhost/test?sslmode=disable"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRETS_DATABASE_URL_FILE", "database")
	t.Setenv("SECRETS_IDENTITY_KEY_FILE", "missing")
	cmd = command()
	cmd.SetArgs([]string{"migrate", "status"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "PGConnstr must require TLS") {
		t.Fatalf("migration should load only database settings: %v", err)
	}
	cmd = command()
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "identity-key-file") {
		t.Fatalf("service should read its prefixed secret-file setting: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, tt := range []struct {
		name, auth, control, vault string
		signing                    int
		valid                      bool
	}{
		{"private Vault", "https://auth.example", "https://control.example", "https://vault:8200", 32, true},
		{"HTTP private Vault", "https://auth.example", "https://control.example", "http://vault:8200", 32, false},
		{"external Vault", "https://auth.example", "https://control.example", "https://vault.example", 32, true},
		{"HTTP auth", "http://auth.example", "https://control.example", "https://vault:8200", 32, false},
		{"HTTP control", "https://auth.example", "http://control.example", "https://vault:8200", 32, false},
		{"HTTP external Vault", "https://auth.example", "https://control.example", "http://vault.example:8200", 32, false},
		{"short signing key", "https://auth.example", "https://control.example", "https://vault:8200", 31, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := params{DatabaseURL: "postgres://localhost/test", IdentityKey: "identity", EncryptionKey: "encryption",
				SigningKey: strings.Repeat("k", tt.signing), ControlToken: "control", VaultToken: "vault",
				SupabaseURL: tt.auth, SupabaseKey: "publishable", ControlURL: tt.control, VaultURL: tt.vault, PublicURL: "https://secrets.example"}
			err := (boa.Cmd[params]{Params: &p, RawArgs: []string{}}).Validate()
			if (err == nil) != tt.valid || p.Listen != "127.0.0.1:8080" || p.SigningKeyID != "1" {
				t.Fatalf("valid=%v, listen=%q, signing-key-id=%q: %v", tt.valid, p.Listen, p.SigningKeyID, err)
			}
		})
	}
}
