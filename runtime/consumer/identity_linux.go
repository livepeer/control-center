package consumer

import (
	"errors"
	"os"
)

func processIdentity() (string, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", errors.New("process_identity_unavailable")
	}
	// Probes share PID 1's namespace. Reading their own link needs no ptrace
	// access to PID 1, which stacked AppArmor labels deny (Ubuntu 25.04+).
	namespace, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return "", errors.New("process_identity_unavailable")
	}
	stat, err := os.ReadFile("/proc/1/stat")
	if err != nil || len(stat) > 8192 {
		return "", errors.New("process_identity_unavailable")
	}
	return hashProcess(string(boot), namespace, string(stat))
}
