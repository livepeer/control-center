package machineconfig

import (
	"encoding/json"
	"errors"

	"github.com/livepeer/control-center/runtime/artifact"
)

func ReadApplied(data []byte) (Runtime, string, error) {
	var d Runtime
	files, err := artifact.Read(data)
	if err != nil {
		return d, "", err
	}
	metadata, manifest := files["runtime.json"], files["system/node/orchestrator.yaml"]
	if len(metadata) > 1<<20 || len(manifest) > 1<<20 {
		return d, "", errors.New("invalid stored Node configuration")
	}
	if err = json.Unmarshal(metadata, &d); err != nil {
		return d, "", err
	}
	if len(manifest) == 0 || d.ConfigDigest == "" {
		return d, "", errors.New("stored bundle has no Node workload or digest")
	}
	return d, string(manifest), nil
}
