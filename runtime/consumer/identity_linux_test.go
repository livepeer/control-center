package consumer

import (
	"os"
	"testing"
)

// Probes run beside PID 1 but may not inspect it: a stacked AppArmor label
// (Ubuntu 25.04+) denies ptrace reads of PID 1 inside containers. Running the
// tests as a user other than PID 1's owner reproduces the same denial.
func TestProcessIdentityNeedsNoPtraceAccessToPID1(t *testing.T) {
	if _, err := os.ReadFile("/proc/1/stat"); err != nil {
		t.Skip("PID 1 is hidden from this process:", err)
	}
	a, err := processIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := processIdentity()
	if err != nil || a != b {
		t.Fatal("process identity changed between reads", err)
	}
}
