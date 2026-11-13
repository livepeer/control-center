package main

import (
	"bytes"
	"strings"
	"testing"
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
