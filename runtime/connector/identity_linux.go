package connector

import (
	"errors"
	"os"
)

func processIdentity() (string, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", errors.New("connector_process_identity")
	}
	namespace, err := os.Readlink("/proc/1/ns/pid")
	if err != nil {
		return "", errors.New("connector_process_identity")
	}
	stat, err := os.ReadFile("/proc/1/stat")
	if err != nil || len(stat) > 8192 {
		return "", errors.New("connector_process_identity")
	}
	return hashProcess(string(boot), namespace, string(stat))
}
