package httpsource

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

type layoutState struct {
	Stage    string `json:"stage"`
	Epoch    string `json:"epoch"`
	Transfer string `json:"transfer"`
}

func (s *Source) readLayout() (layoutState, error) {
	var state layoutState
	b, err := os.ReadFile(filepath.Join(s.Store.Directory, "system-layout.json"))
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, errors.New("layout_state_unavailable")
	}
	if transport.Decode(b, &state) != nil || !artifact.HashPattern.MatchString(state.Transfer) || state.Epoch == "" || (state.Stage != "handoff" && state.Stage != "adopting" && state.Stage != "releasing" && state.Stage != "pruning" && state.Stage != "complete") {
		return layoutState{}, errors.New("layout_state_corrupt")
	}
	return state, nil
}

// A new epoch must first apply a legacy inventory before its format-3 handoff.
// A completed layout keeps its capability floor across subsequent enrollments.
func (s *Source) systemCapable(m contract.Metadata, rootRevision string) bool {
	state, err := s.readLayout()
	if err != nil {
		return false
	}
	if state.Stage == "complete" || (state.Stage != "" && state.Epoch == m.Epoch) {
		return true
	}
	b, err := s.Store.Get(rootRevision)
	if err != nil {
		return false
	}
	files, err := artifact.Read(b)
	if err != nil {
		return false
	}
	prior, err := transport.ReadMetadata(files["runtime.json"])
	return err == nil && prior.NodeID == m.NodeID && prior.Epoch == m.Epoch
}

// The durable transfer never shrinks. First the flat owner applies that union
// with pruning disabled; then children adopt it. Only after unique ownership is
// verified may current desired omissions be pruned by the new owners.
func (s *Source) systemLayout(ctx context.Context, files map[string][]byte, data []byte, m contract.Metadata) ([]byte, bool, error) {
	statePath := filepath.Join(s.Store.Directory, "system-layout.json")
	snapshotPath := filepath.Join(s.Store.Directory, "system-transfer.snapshot")
	state, err := s.readLayout()
	if err != nil {
		return nil, false, err
	}
	var b []byte
	if m.BundleFormat < contract.SystemBundleFormat {
		if state.Stage != "" {
			return nil, false, errors.New("system_layout_downgrade")
		}
		if s.SystemWorkloads {
			if err = s.setPrune(ctx, true); err != nil {
				return nil, false, err
			}
		}
		return data, false, nil
	}
	if !s.SystemWorkloads {
		return nil, false, errors.New("system_sockets_required")
	}
	var root fluxState
	if err = s.Kube.Request(ctx, http.MethodGet, fluxPath+"livepeer", nil, &root); err != nil {
		return nil, false, err
	}
	commit := func(stage string) error {
		state.Stage = stage
		b, _ := json.Marshal(state)
		return artifact.AtomicWrite(statePath, b, 0600)
	}
	if state.Stage == "complete" {
		// Bootstrap repair can seed prune:false again; ownership has already moved.
		if err = s.setPrune(ctx, true); err != nil {
			return nil, false, err
		}
		return data, false, nil
	}
	if state.Stage != "" && state.Epoch != m.Epoch {
		return nil, false, errors.New("unfinished_previous_layout")
	}
	var frozen map[string][]byte
	if state.Stage == "" {
		frozen, err = s.freezeTransfer(ctx, files, m, root)
		if err != nil {
			return nil, false, err
		}
		b, err = artifact.Pack(frozen)
		if err != nil {
			return nil, false, err
		}
		if err = artifact.AtomicWrite(snapshotPath, b, 0600); err != nil {
			return nil, false, err
		}
		state.Epoch = m.Epoch
		state.Transfer = artifact.Digest(b)
		if err = commit("handoff"); err != nil {
			return nil, false, err
		}
	} else {
		b, err = os.ReadFile(snapshotPath)
		if err != nil || artifact.Digest(b) != state.Transfer {
			return nil, false, errors.New("transfer_snapshot_unavailable")
		}
		frozen, err = artifact.Read(b)
		if err != nil {
			return nil, false, err
		}
	}
	if state.Stage == "handoff" || state.Stage == "adopting" {
		if root.Spec.Prune {
			if err = s.setPrune(ctx, false); err != nil {
				return nil, false, err
			}
		} else if state.Stage == "handoff" && s.appliedLayout(root, state, "handoff") != nil {
			if err = commit("adopting"); err != nil {
				return nil, false, err
			}
		} else if state.Stage == "adopting" && s.appliedLayout(root, state, "adopting") != nil && s.transferred(ctx, root, frozen) {
			if err = commit("releasing"); err != nil {
				return nil, false, err
			}
		}
	}
	if state.Stage == "releasing" {
		// Keep the adoption root unchanged until prune:true has actually reconciled.
		if !root.Spec.Prune {
			if err = s.setPrune(ctx, true); err != nil {
				return nil, false, err
			}
		} else if s.appliedLayout(root, state, "adopting") != nil {
			if err = commit("pruning"); err != nil {
				return nil, false, err
			}
		}
	}
	if state.Stage == "pruning" && !root.Spec.Prune {
		// Bootstrap repair may reset the root after children have started pruning.
		// Restore the root without ever republishing frozen child definitions.
		if err = s.setPrune(ctx, true); err != nil {
			return nil, false, err
		}
	}
	if state.Stage == "pruning" && root.Spec.Prune && s.appliedLayout(root, state, "pruning") != nil && s.transferPruned(ctx, root, files, frozen, state) {
		if err = commit("complete"); err != nil {
			return nil, false, err
		}
		return data, false, nil
	}
	out := copyFiles(files)
	for n, b := range frozen {
		if n != "kustomization.yaml" {
			out[n] = b
		}
	}
	phase := state.Stage
	if phase == "releasing" {
		phase = "adopting"
	}
	switch phase {
	case "handoff":
		// Support stays current; only ownership-moving resources and omitted parent
		// resources are frozen. app-desired and upgrade-plan are never frozen.
		out["management/kustomization.yaml"] = kustomization("app-reconciler.yaml")
		out["kustomization.yaml"] = kustomization(transferResources()...)
	case "adopting":
		out["management/system.yaml"] = adoptionDefinitions(files["management/system.yaml"])
		out["kustomization.yaml"] = kustomization("management")
	case "pruning":
		// Flux commits LastAppliedRevision only after optional health checks.
		// Complete canonical application before restoring the upgrade controller's
		// health gate; its upgrade-plan dependency remains in place throughout.
		out["management/system.yaml"] = []byte(strings.ReplaceAll(string(files["management/system.yaml"]), "wait: true", "wait: false"))
	}
	marker, _ := json.Marshal(struct {
		Transfer string `json:"transfer"`
		Phase    string `json:"phase"`
	}{state.Transfer, phase})
	out["system-layout-publication.json"] = marker
	b, err = artifact.Pack(out)
	return b, true, err
}

// LastAppliedRevision is set after apply and inventory publication. Health is
// irrelevant here. Generation also fences an in-flight prune:false reconcile.
func (s *Source) appliedLayout(k fluxState, state layoutState, phase string) map[string][]byte {
	if k.Status.ObservedGeneration != k.Metadata.Generation {
		return nil
	}
	b, err := s.Store.Get(k.Status.LastAppliedRevision)
	if err != nil {
		return nil
	}
	files, err := artifact.Read(b)
	if err != nil {
		return nil
	}
	var marker struct {
		Transfer string `json:"transfer"`
		Phase    string `json:"phase"`
	}
	if transport.Decode(files["system-layout-publication.json"], &marker) != nil || marker.Transfer != state.Transfer || marker.Phase != phase {
		return nil
	}
	return files
}

func (s *Source) transferPruned(ctx context.Context, root fluxState, files, frozen map[string][]byte, state layoutState) bool {
	for _, component := range systemComponents {
		current, err := manifestObjects(files, "system/"+component)
		if err != nil {
			return false
		}
		prior, err := manifestObjects(frozen, ".system-transfer/"+component)
		if err != nil {
			return false
		}
		var child fluxState
		if s.Kube.Request(ctx, http.MethodGet, fluxPath+"livepeer-"+component, nil, &child) != nil {
			return false
		}
		actual := s.appliedLayout(child, state, "pruning")
		if child.Spec.Path != "./system/"+component || actual == nil {
			return false
		}
		for n, b := range files {
			if strings.HasPrefix(n, "system/"+component+"/") && string(actual[n]) != string(b) {
				return false
			}
		}
		present := map[string]bool{}
		for _, o := range current {
			present[o.id()] = true
			if inventoryContains(root, o.id()) || !inventoryContains(child, o.id()) || !s.objectOwned(ctx, o, "livepeer-"+component) {
				return false
			}
		}
		for _, o := range prior {
			if present[o.id()] {
				continue
			}
			if inventoryContains(child, o.id()) {
				return false
			}
			if o.Metadata.Annotations["kustomize.toolkit.fluxcd.io/prune"] == "disabled" {
				continue
			}
			p, err := o.apiPath()
			if err != nil {
				return false
			}
			var object any
			if !transport.IsStatus(s.Kube.Request(ctx, http.MethodGet, p, nil, &object), 404) {
				return false
			}
		}
	}
	return true
}

func (s *Source) setPrune(ctx context.Context, enabled bool) error {
	var root fluxState
	if err := s.Kube.Request(ctx, http.MethodGet, fluxPath+"livepeer", nil, &root); err != nil {
		return err
	}
	if root.Spec.Prune == enabled {
		return nil
	}
	return s.Kube.Request(ctx, http.MethodPatch, fluxPath+"livepeer", map[string]any{"spec": map[string]any{"prune": enabled}}, nil)
}
