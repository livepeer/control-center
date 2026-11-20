package machineconfig

import (
	"encoding/json"
	"errors"

	"github.com/livepeer/control-center/runtime/artifact"
)

type appliedWorkload struct {
	Runtime
	manifest    string
	upgradePlan string
}

func ReadApplied(data []byte) (Runtime, string, error) {
	workload, err := readAppliedWorkload(data)
	return workload.Runtime, workload.manifest, err
}

func readAppliedWorkload(data []byte) (appliedWorkload, error) {
	var workload appliedWorkload
	files, err := artifact.Read(data)
	if err != nil {
		return workload, err
	}
	metadata, manifest := files["runtime.json"], files["system/node/orchestrator.yaml"]
	if len(metadata) > 1<<20 || len(manifest) > 1<<20 {
		return workload, errors.New("invalid stored Node configuration")
	}
	if err = json.Unmarshal(metadata, &workload.Runtime); err != nil {
		return workload, err
	}
	if len(manifest) == 0 || workload.ConfigDigest == "" {
		return workload, errors.New("stored bundle has no Node workload or digest")
	}
	workload.manifest = string(manifest)
	workload.upgradePlan = string(files["upgrade-plan/plan.yaml"])
	return workload, nil
}

func (w appliedWorkload) hold(state *State) {
	state.HeldOrchestrator = w.manifest
	state.HeldOnchain = onchainJSON(w.Onchain)
	if state.HeldUpgradePlan == "" {
		state.HeldUpgradePlan = w.upgradePlan
	}
}
