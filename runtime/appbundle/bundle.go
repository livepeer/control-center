// Package appbundle renders centrally supplied app groups and specializes only their local identity.
package appbundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
)

const Namespace = "livepeer-apps"
const Finalizer = "livepeer.io/app-incarnation"
const IndexFile = "app-desired/index.json"
const IntentFile = "app-desired/intent.json"
const MaxInstances = 128
const MaxRenderedBytes = 8 << 20

type Group struct {
	Key                  string   `json:"key"`
	RevisionID           string   `json:"revision_id"`
	ActivationGeneration int64    `json:"activation_generation"`
	Slot                 int      `json:"slot"`
	Name                 string   `json:"name"`
	Files                []string `json:"files"`
}
type Index struct {
	Version      int               `json:"version"`
	Available    bool              `json:"available"`
	IntentDigest string            `json:"intent_digest,omitempty"`
	Groups       []Group           `json:"groups"`
	Hashes       map[string]string `json:"hashes"`
}
type Payload struct {
	Index  Index
	Intent *schema.AppAssignmentSetV1
	Files  map[string][]byte
}
type Options struct{ StopSignals bool }

func Key(node, revision string, activation int64, slot int) string {
	return artifact.Digest([]byte(fmt.Sprintf("%s/%s/%d/%d", node, revision, activation, slot)))[7:27]
}
func newGroup(set schema.AppAssignmentSetV1, a schema.AppAssignment, slot int) Group {
	key := Key(set.NodeID, a.RevisionID, a.ActivationGeneration, slot)
	base := "app-desired/groups/" + key + "/"
	return Group{Key: key, RevisionID: a.RevisionID, ActivationGeneration: a.ActivationGeneration, Slot: slot, Name: "lp-app-" + key, Files: []string{base + "pod.json", base + "service.json"}}
}
func Unavailable() Payload {
	p := Payload{Index: Index{Version: 1, Groups: []Group{}, Hashes: map[string]string{}}, Files: map[string][]byte{}}
	p.Files[IndexFile], _ = json.Marshal(p.Index)
	return p
}
func Render(set schema.AppAssignmentSetV1, options Options) (Payload, error) {
	intent, err := schema.CanonicalAssignmentSet(set)
	if err != nil {
		return Payload{}, err
	}
	p := Payload{Index: Index{Version: 1, Available: true, IntentDigest: schema.Digest(intent), Groups: []Group{}, Hashes: map[string]string{IntentFile: schema.Digest(intent)}}, Intent: &set, Files: map[string][]byte{IntentFile: intent}}
	registrations := 0
	for _, a := range set.Entries {
		if a.Desired != "present" {
			continue
		}
		d := a.Revision.Definition
		registrations += max(1, len(d.Apps)) * a.Replicas
		if registrations > schema.MaxRegistrations {
			return Payload{}, errors.New("resource_refused")
		}
		if d.Instances.Mode != "reusable" {
			return Payload{}, errors.New("unsupported_instance_mode")
		}
		if d.Lifecycle.StopSignal != nil && !options.StopSignals {
			return Payload{}, errors.New("unsupported_stop_signal")
		}
		if len(p.Index.Groups)+a.Replicas > MaxInstances {
			return Payload{}, errors.New("resource_refused")
		}
		for slot := 0; slot < a.Replicas; slot++ {
			g := newGroup(set, a, slot)
			objects := renderGroup(g, set, d)
			for i, object := range objects {
				b, err := json.Marshal(object)
				if err != nil {
					return Payload{}, err
				}
				p.Files[g.Files[i]] = b
				p.Index.Hashes[g.Files[i]] = schema.Digest(b)
			}
			p.Index.Groups = append(p.Index.Groups, g)
		}
	}
	p.Files[IndexFile], err = json.Marshal(p.Index)
	if payloadBytes(p.Files) > MaxRenderedBytes {
		return Payload{}, errors.New("resource_refused")
	}
	return p, err
}
func payloadBytes(files map[string][]byte) int {
	n := 0
	for _, b := range files {
		n += len(b)
	}
	return n
}

type object = map[string]any

func renderGroup(g Group, set schema.AppAssignmentSetV1, d schema.DefinitionV1) []object {
	labels := map[string]string{"app": "livepeer-app", "livepeer.io/instance": g.Name, "livepeer.io/node": set.NodeID, "livepeer.io/egress": d.Network.Egress}
	metadata := func() object {
		return object{"name": g.Name, "namespace": Namespace, "labels": labels, "annotations": map[string]string{"livepeer.io/revision-id": g.RevisionID}}
	}
	container := object{"name": "app", "image": d.Container.Image, "imagePullPolicy": "IfNotPresent",
		"ports":           []object{{"name": "http", "containerPort": d.HTTP.Port}},
		"securityContext": object{"runAsNonRoot": true, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": object{"drop": []string{"ALL"}}},
		"resources":       object{"requests": quantities(d.Resources.Requests), "limits": quantities(d.Resources.Limits)}}
	if d.Container.Entrypoint != nil {
		container["command"] = *d.Container.Entrypoint
	}
	if d.Container.Command != nil {
		container["args"] = *d.Container.Command
	}
	if d.Container.WorkingDir != nil {
		container["workingDir"] = *d.Container.WorkingDir
	}
	if d.Container.User != nil {
		parts := strings.Split(*d.Container.User, ":")
		uid, _ := strconv.ParseInt(parts[0], 10, 64)
		gid, _ := strconv.ParseInt(parts[1], 10, 64)
		container["securityContext"].(object)["runAsUser"] = uid
		container["securityContext"].(object)["runAsGroup"] = gid
	}
	keys := make([]string, 0, len(d.Container.Environment))
	for key := range d.Container.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := []object{}
	for _, key := range keys {
		env = append(env, object{"name": key, "value": d.Container.Environment[key]})
	}
	for _, s := range d.Container.Secrets {
		env = append(env, object{"name": s.Name, "valueFrom": object{"secretKeyRef": object{"name": s.Secret, "key": s.Key}}})
	}
	if len(d.Apps) > 0 {
		apps, _ := json.Marshal(d.Apps)
		env = append(env, object{"name": "LIVEPEER_RUNTIME_APPS", "value": string(apps)}, object{"name": "LIVEPEER_RUNTIME_CAPACITY", "value": strconv.Itoa(d.Instances.CapacityPerInstance)})
	}
	container["env"] = env
	volumes := []object{{"name": "shm", "emptyDir": object{"medium": "Memory", "sizeLimit": strings.TrimSuffix(d.Filesystem.ShmSize, "B")}}}
	mounts := []object{{"name": "shm", "mountPath": "/dev/shm"}}
	for i, scratch := range d.Filesystem.Scratch {
		name := fmt.Sprintf("scratch-%d", i)
		volumes = append(volumes, object{"name": name, "emptyDir": object{"medium": "Memory", "sizeLimit": strings.TrimSuffix(scratch.Size, "B")}})
		mounts = append(mounts, object{"name": name, "mountPath": scratch.Path})
	}
	container["volumeMounts"] = mounts
	if d.Lifecycle.StopSignal != nil {
		container["lifecycle"] = object{"stopSignal": *d.Lifecycle.StopSignal}
	}
	grace, _ := strconv.ParseInt(strings.TrimSuffix(d.Lifecycle.StopGracePeriod, "s"), 10, 64)
	podMeta := metadata()
	podMeta["finalizers"] = []string{Finalizer}
	pod := object{"apiVersion": "v1", "kind": "Pod", "metadata": podMeta, "spec": object{
		"os": object{"name": "linux"}, "runtimeClassName": "gvisor", "serviceAccountName": "livepeer-app",
		"dnsPolicy": "None", "dnsConfig": object{"nameservers": []string{"1.1.1.1", "1.0.0.1"}},
		"automountServiceAccountToken": false, "restartPolicy": "Never", "terminationGracePeriodSeconds": grace,
		"nodeSelector":    map[string]string{"kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux", "livepeer.io/node-id": set.NodeID},
		"securityContext": object{"runAsNonRoot": true, "seccompProfile": object{"type": "RuntimeDefault"}},
		"containers":      []object{container}, "volumes": volumes}}
	service := object{"apiVersion": "v1", "kind": "Service", "metadata": metadata(), "spec": object{
		"type": "ClusterIP", "publishNotReadyAddresses": true, "selector": map[string]string{"livepeer.io/instance": g.Name},
		"ports": []object{{"name": "http", "port": d.HTTP.Port, "targetPort": d.HTTP.Port, "protocol": "TCP"}}}}
	return []object{pod, service}
}
func quantities(q schema.Quantities) object {
	return object{"cpu": q.CPU, "memory": strings.TrimSuffix(q.Memory, "B"), "ephemeral-storage": strings.TrimSuffix(q.EphemeralStorage, "B")}
}

func Read(files map[string][]byte, m contract.Metadata) (Payload, error) {
	p := Payload{Files: map[string][]byte{}}
	index, ok := files[IndexFile]
	if !ok || len(index) > 1<<20 || transport.Decode(index, &p.Index) != nil || p.Index.Version != 1 {
		return p, errors.New("app_index")
	}
	p.Files[IndexFile] = index
	if !p.Index.Available {
		if p.Index.IntentDigest != "" || len(p.Index.Groups) != 0 || len(p.Index.Hashes) != 0 {
			return p, errors.New("app_unavailable")
		}
		return p, nil
	}
	raw, ok := files[IntentFile]
	if !ok || schema.Digest(raw) != p.Index.IntentDigest || m.AppsDigest != p.Index.IntentDigest || m.AppsPayloadDigest != schema.Digest(index) {
		return p, errors.New("app_digest")
	}
	set, err := schema.DecodeAssignmentSet(raw)
	if err != nil || set.NodeID != m.NodeID || set.Generation != m.AppsGeneration {
		return p, errors.New("app_identity")
	}
	expected := map[string]Group{}
	for _, a := range set.Entries {
		if a.Desired == "present" {
			if a.Revision.Definition.Instances.Mode != "reusable" {
				return p, errors.New("unsupported_instance_mode")
			}
			for slot := 0; slot < a.Replicas; slot++ {
				g := newGroup(set, a, slot)
				expected[g.Key] = g
			}
		}
	}
	if len(expected) != len(p.Index.Groups) || len(expected) > MaxInstances {
		return p, errors.New("app_groups")
	}
	seen := map[string]bool{}
	for _, g := range p.Index.Groups {
		want, ok := expected[g.Key]
		a, _ := json.Marshal(g)
		b, _ := json.Marshal(want)
		if !ok || seen[g.Key] || string(a) != string(b) {
			return p, errors.New("app_group_identity")
		}
		seen[g.Key] = true
		for _, name := range g.Files {
			data, ok := files[name]
			if !ok || schema.Digest(data) != p.Index.Hashes[name] {
				return p, errors.New("app_resource_digest")
			}
			var resource struct {
				APIVersion string `json:"apiVersion"`
				Kind       string `json:"kind"`
				Metadata   struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			}
			if transport.Decode(data, &resource) != nil || resource.APIVersion != "v1" || (resource.Kind != "Pod" && resource.Kind != "Service") || resource.Metadata.Name != g.Name || resource.Metadata.Namespace != Namespace {
				return p, errors.New("app_resource")
			}
			p.Files[name] = data
		}
	}
	if len(p.Index.Hashes) != 1+2*len(expected) || p.Index.Hashes[IntentFile] != schema.Digest(raw) {
		return p, errors.New("app_membership")
	}
	p.Intent = &set
	p.Files[IntentFile] = raw
	if payloadBytes(p.Files) > MaxRenderedBytes {
		return p, errors.New("resource_refused")
	}
	return p, nil
}

var incarnationPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Instantiate changes identity fields only. Process/security/resource settings remain central.
func (p Payload) Instantiate(g Group, incarnation string) (map[string][]byte, string, error) {
	if !incarnationPattern.MatchString(incarnation) {
		return nil, "", errors.New("instance_identity")
	}
	name := g.Name + "-" + incarnation
	out := map[string][]byte{}
	for _, file := range g.Files {
		var resource object
		if err := transport.Decode(p.Files[file], &resource); err != nil {
			return nil, "", err
		}
		meta, ok := resource["metadata"].(map[string]any)
		if !ok {
			return nil, "", errors.New("instance_metadata")
		}
		meta["name"] = name
		labels, ok := meta["labels"].(map[string]any)
		if !ok {
			return nil, "", errors.New("instance_labels")
		}
		labels["livepeer.io/instance"] = name
		if resource["kind"] == "Pod" {
			spec, _ := resource["spec"].(map[string]any)
			containers, _ := spec["containers"].([]any)
			if len(containers) != 1 {
				return nil, "", errors.New("instance_pod")
			}
			container, _ := containers[0].(map[string]any)
			env, ok := container["env"].([]any)
			if container == nil || (container["env"] != nil && !ok) {
				return nil, "", errors.New("instance_pod")
			}
			for _, v := range env {
				if _, ok := v.(map[string]any); !ok {
					return nil, "", errors.New("instance_pod")
				}
			}
			container["env"] = append(env, object{"name": "LIVEPEER_RUNTIME_INSTANCE_ID", "value": incarnation})
		}
		if resource["kind"] == "Service" {
			spec, ok := resource["spec"].(map[string]any)
			if !ok {
				return nil, "", errors.New("instance_service")
			}
			spec["selector"] = map[string]string{"livepeer.io/instance": name}
		}
		b, err := json.Marshal(resource)
		if err != nil {
			return nil, "", err
		}
		out["instances/"+name+"/"+path.Base(file)] = b
	}
	return out, name, nil
}

func (p Payload) Digest() string { return schema.Digest(p.Files[IndexFile]) }
