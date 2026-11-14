package appreconciler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/livepeer/control-center/runtime/appbundle"

	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
	protocol "github.com/livepeer/control-center/secrets"
	"net/url"
	"time"
)

type SecretResolver interface {
	Activate(context.Context) error
	IdentityReady() bool
	VersionsAll(context.Context, []protocol.ResolveRequest) (map[string]protocol.VersionSet, map[string]string, error)
	Versions(context.Context, protocol.ResolveRequest) (protocol.VersionSet, error)
	Resolve(context.Context, protocol.ResolveRequest) (protocol.VersionSet, error)
}
type SecretDelivery struct {
	Client   SecretResolver
	Kube     *transport.Kube
	Next     time.Time
	failures int
	Targets  map[string]protocol.VersionSet
	Faults   map[string]string
}

func request(a schema.AppAssignment) protocol.ResolveRequest {
	return protocol.ResolveRequest{RevisionID: a.RevisionID, Generation: a.Generation, Activation: a.ActivationGeneration, Digest: a.Digest}
}
func (d *SecretDelivery) Poll(ctx context.Context, s State, now time.Time) {
	if d == nil {
		return
	}
	if !d.Client.IdentityReady() {
		d.Targets = map[string]protocol.VersionSet{}
		d.Faults = map[string]string{}
		d.identityFault(s, "secrets_unavailable")
		d.Next, d.failures = time.Time{}, 0
		return
	}
	if now.Before(d.Next) {
		return
	}
	identityFailed := false
	defer func() {
		failed := identityFailed
		for _, reason := range d.Faults {
			if reason == "secrets_unavailable" {
				failed = true
			}
		}
		if failed {
			if d.failures < 4 {
				d.failures++
			}
		} else {
			d.failures = 0
		}
		delay := 30 * time.Second * time.Duration(1<<d.failures)
		if delay > 5*time.Minute {
			delay = 5 * time.Minute
		}
		d.Next = now.Add(delay + time.Duration(now.Nanosecond()%5000)*time.Millisecond)
	}()
	d.Targets = map[string]protocol.VersionSet{}
	d.Faults = map[string]string{}
	// Activation also runs on idle machines.
	e := d.AdmissionReady(ctx)
	if e == nil {
		e = d.Client.Activate(ctx)
	}
	if e != nil {
		identityFailed = !errors.Is(e, protocol.ErrDenied)
		d.identityFault(s, secretFault(e))
		return
	}
	if s.Payload.Intent == nil {
		return
	}
	requests := []protocol.ResolveRequest{}
	for _, a := range s.Payload.Intent.Entries {
		if a.Desired == "present" && needsSecrets(a) {
			requests = append(requests, request(a))
		}
	}
	if len(requests) == 0 {
		live := false
		for _, i := range s.Instances {
			if i.Phase != "removed" && len(i.Definition.Container.Secrets) > 0 {
				live = true
			}
		}
		if !live {
			return
		}
	}
	sets, faults, e := d.Client.VersionsAll(ctx, requests)
	if e != nil {
		d.identityFault(s, secretFault(e))
		return
	}
	d.Targets = sets
	if faults != nil {
		d.Faults = faults
	}
}
func secretFault(e error) string {
	if errors.Is(e, protocol.ErrDenied) {
		return "secrets_denied"
	}
	return "secrets_unavailable"
}

func (d *SecretDelivery) identityFault(s State, reason string) {
	if s.Payload.Intent != nil {
		for _, a := range s.Payload.Intent.Entries {
			if needsSecrets(a) {
				d.Faults[a.RevisionID] = reason
			}
		}
	}
	for _, i := range s.Instances {
		if i.Phase != "removed" && len(i.Definition.Container.Secrets) > 0 {
			d.Faults[i.Group.RevisionID] = reason
		}
	}
	for _, i := range s.SecretSuccessors {
		d.Faults[i.Group.RevisionID] = reason
	}
}
func secretRevisionRelevant(s State, revision string) bool {
	if s.Payload.Intent != nil {
		for _, a := range s.Payload.Intent.Entries {
			if a.RevisionID == revision && a.Desired == "present" {
				return true
			}
		}
	}
	for _, i := range s.Instances {
		if i.Group.RevisionID == revision && (i.Phase != "removed" || !i.SecretCleanupDone) {
			return true
		}
	}
	for _, i := range s.SecretSuccessors {
		if i.Group.RevisionID == revision {
			return true
		}
	}
	return false
}
func preparationReason(e error) string {
	if errors.Is(e, protocol.ErrInvalid) {
		return "secret_invalid"
	}
	return "secrets_unavailable"
}

// AdmissionReady checks the live guard before activation and every new start.
const ownSecretRule = "request.operation != 'CREATE' || object.spec.containers.all(c, !has(c.env) || c.env.all(e, !has(e.valueFrom) || !has(e.valueFrom.secretKeyRef) || e.valueFrom.secretKeyRef.name == object.metadata.name))"

func (d *SecretDelivery) AdmissionReady(ctx context.Context) error {
	var ns struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if e := d.Kube.Request(ctx, "GET", "/api/v1/namespaces/livepeer-apps", nil, &ns); e != nil {
		return e
	}
	if ns.Metadata.Labels["livepeer.io/managed-apps"] != "true" {
		return protocol.ErrUnavailable
	}
	var policy struct {
		Spec struct {
			FailurePolicy string `json:"failurePolicy"`
			Validations   []struct {
				Expression string `json:"expression"`
			} `json:"validations"`
		} `json:"spec"`
	}
	if e := d.Kube.Request(ctx, "GET", "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/livepeer-app-pods", nil, &policy); e != nil {
		return e
	}
	guarded := false
	for _, v := range policy.Spec.Validations {
		if v.Expression == ownSecretRule {
			guarded = true
		}
	}
	var binding struct {
		Spec struct {
			PolicyName string   `json:"policyName"`
			Actions    []string `json:"validationActions"`
		} `json:"spec"`
	}
	if e := d.Kube.Request(ctx, "GET", "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/livepeer-app-pods", nil, &binding); e != nil {
		return e
	}
	deny := false
	for _, a := range binding.Spec.Actions {
		deny = deny || a == "Deny"
	}
	if !guarded || policy.Spec.FailurePolicy != "Fail" || binding.Spec.PolicyName != "livepeer-app-pods" || !deny {
		return protocol.ErrUnavailable
	}
	return nil
}
func needsSecrets(a schema.AppAssignment) bool {
	return a.Revision != nil && len(a.Revision.Definition.Container.Secrets) > 0
}
func (d *SecretDelivery) Prepare(ctx context.Context, a schema.AppAssignment, i *Instance) error {
	target, ok := d.Targets[a.RevisionID]
	if !ok {
		return protocol.ErrUnavailable
	}
	in := request(a)
	in.Expected = target.Digest
	v, e := d.Client.Resolve(ctx, in)
	if e != nil {
		return e
	}
	defer func() {
		for i := range v.Values {
			clear(v.Values[i].DataKey)
		}
	}()
	if v.NodeID == "" || v.NodeID != target.NodeID || v.IdentityGeneration < target.IdentityGeneration || v.PolicyGeneration < target.PolicyGeneration || v.Assignment.RevisionID != a.RevisionID || v.Assignment.Generation != a.Generation || v.Assignment.Activation != a.ActivationGeneration || v.Assignment.Digest != a.Digest || v.Digest != target.Digest {
		return protocol.ErrInvalid
	}
	data := map[string][]byte{}
	defer func() {
		for _, plain := range data {
			clear(plain)
		}
	}()
	total := 0
	for _, ref := range a.Revision.Definition.Container.Secrets {
		found := false
		for _, item := range v.Values {
			if item.Name != ref.Secret || item.Key != ref.Key {
				continue
			}
			plain, e := protocol.Decrypt(item.Ciphertext, item.DataKey)
			if e != nil {
				return e
			}
			total += len(plain)
			if total > protocol.MaxInjected {
				clear(plain)
				return protocol.ErrInvalid
			}
			local := protocol.LocalKey(ref.Secret, ref.Key)
			clear(data[local])
			data[local] = plain
			found = true
			break
		}
		if !found {
			return protocol.ErrInvalid
		}
	}
	for file, raw := range i.Files {
		var obj map[string]any
		if json.Unmarshal(raw, &obj) != nil {
			return protocol.ErrInvalid
		}
		if obj["kind"] != "Pod" {
			continue
		}
		spec, _ := obj["spec"].(map[string]any)
		containers, _ := spec["containers"].([]any)
		if len(containers) != 1 {
			return protocol.ErrInvalid
		}
		container, _ := containers[0].(map[string]any)
		// Bound each process string and leave headroom for image defaults and
		// runtime-provided variables. Validate before writing or withdrawing.
		processBytes := 0
		fits := func(size int) bool {
			processBytes += size + 8 // Include the terminating NUL and pointer.
			return size <= 128<<10 && processBytes <= 1<<20
		}
		for _, field := range []string{"command", "args"} {
			args, _ := container[field].([]any)
			for _, arg := range args {
				value, ok := arg.(string)
				if !ok || !fits(len(value)+1) {
					return protocol.ErrInvalid
				}
			}
		}
		env, _ := container["env"].([]any)
		for _, entry := range env {
			item, _ := entry.(map[string]any)
			variable, _ := item["name"].(string)
			value, _ := item["value"].(string)
			valueBytes := len(value)
			from, _ := item["valueFrom"].(map[string]any)
			ref, _ := from["secretKeyRef"].(map[string]any)
			if ref != nil {
				name, _ := ref["name"].(string)
				key, _ := ref["key"].(string)
				local := protocol.LocalKey(name, key)
				if _, ok := data[local]; !ok {
					return protocol.ErrInvalid
				}
				valueBytes = len(data[local])
				ref["name"] = i.Name
				ref["key"] = local
			}
			if !fits(len(variable) + 2 + valueBytes) {
				return protocol.ErrInvalid
			}
		}
		raw, e = json.Marshal(obj)
		if e != nil {
			return e
		}
		i.Files[file] = raw
	}
	// Data is written directly; the journal stores only this resource's identity.
	obj := map[string]any{"apiVersion": "v1", "kind": "Secret", "immutable": true, "metadata": map[string]any{"name": i.Name, "namespace": appbundle.Namespace, "labels": map[string]string{"livepeer.io/managed-secret": "true"}, "annotations": map[string]string{"livepeer.io/secret-version": v.Digest}}, "data": data}
	e = d.Kube.Request(ctx, "POST", "/api/v1/namespaces/"+appbundle.Namespace+"/secrets", obj, nil)
	if transport.IsStatus(e, 409) {
		var existing struct {
			Metadata struct {
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
		}
		e = d.Kube.Request(ctx, "GET", "/api/v1/namespaces/"+appbundle.Namespace+"/secrets/"+url.PathEscape(i.Name), nil, &existing)
		if e == nil && existing.Metadata.Annotations["livepeer.io/secret-version"] != v.Digest {
			if i.SecretPrepared || i.PodUID != "" || i.PublicationStarted {
				return protocol.ErrDenied
			}
			// The durable preparation has never published a Pod. Reconcile a
			// Secret left by a successful create followed by a journal crash.
			if e = d.Delete(ctx, i.Name); e == nil {
				e = d.Kube.Request(ctx, "POST", "/api/v1/namespaces/"+appbundle.Namespace+"/secrets", obj, nil)
			}
		}
	}
	if e != nil {
		return e
	}
	i.SecretVersion = v.Digest
	i.SecretPrepared = true
	i.SecretPolicy = v.PolicyGeneration
	return nil
}
func preparationFailed(reason string) bool {
	return reason == "secret_invalid" || reason == "secrets_unavailable"
}
func mergePreparedSecret(current, prepared *Instance) {
	if current == nil || current.ID != prepared.ID {
		return
	}
	current.Files = prepared.Files
	current.SecretVersion = prepared.SecretVersion
	current.SecretPolicy = prepared.SecretPolicy
	current.SecretPrepared = prepared.SecretPrepared
	if preparationFailed(current.Reason) {
		current.Reason = ""
	}
}
func (c *Controller) preparedSecret(ctx context.Context, a schema.AppAssignment, i *Instance) (*Instance, error) {
	copy := *i
	copy.SecretVersion = c.Secrets.Targets[a.RevisionID].Digest
	copy.Files = map[string][]byte{}
	for k, v := range i.Files {
		copy.Files[k] = append([]byte(nil), v...)
	}
	copy.Reason = ""
	if e := c.Secrets.Prepare(ctx, a, &copy); e != nil {
		if err := c.Journal.Update(func(st *State) error {
			if current := st.Instances[i.ID]; current != nil && current.Phase == "starting" && current.PodUID == "" && current.WithdrawalID == "" && (current.Reason == "" || preparationFailed(current.Reason)) {
				current.Reason = preparationReason(e)
			}
			for _, next := range st.SecretSuccessors {
				if next.ID == i.ID && next.Phase == "starting" && (next.Reason == "" || preparationFailed(next.Reason)) {
					next.Reason = preparationReason(e)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return &copy, nil
}
func (d *SecretDelivery) Authorize(ctx context.Context, a schema.AppAssignment, i *Instance) error {
	if e := d.AdmissionReady(ctx); e != nil {
		return e
	}
	in := request(a)
	in.Expected = i.SecretVersion
	v, e := d.Client.Versions(ctx, in)
	if e != nil {
		return e
	}
	if v.Digest != i.SecretVersion || v.PolicyGeneration < i.SecretPolicy {
		return protocol.ErrDenied
	}
	return nil
}
func (d *SecretDelivery) Delete(ctx context.Context, name string) error {
	e := d.Kube.Request(ctx, "DELETE", "/api/v1/namespaces/"+appbundle.Namespace+"/secrets/"+url.PathEscape(name), nil, nil)
	if transport.IsStatus(e, 404) {
		return nil
	}
	return e
}

// Historical replacement metadata remains after cleanup. Only live source
// incarnations and an unsatisfied prerequisite suspend independent rotation.
func centralSecretTransition(s State, a schema.AppAssignment) bool {
	if !a.StartAllowed {
		return true
	}
	source := ""
	if a.Replacement != nil {
		source = a.Replacement.RevisionID
	}
	if a.StartAfter != nil {
		source = a.StartAfter.RevisionID
	}
	for _, i := range s.Instances {
		if i.Group.RevisionID == source && occupied(i) {
			return true
		}
	}
	return false
}

// StageRotation prepares a successor before its healthy source is withdrawn.
// Its resource name is journaled first; retries reconcile the same immutable Secret.
func (d *SecretDelivery) StageRotation(ctx context.Context, c *Controller, s State) error {
	if d == nil || s.Payload.Intent == nil {
		return nil
	}
	for _, a := range s.Payload.Intent.Entries {
		if a.Desired != "present" || !needsSecrets(a) || centralSecretTransition(s, a) {
			continue
		}
		target, ok := d.Targets[a.RevisionID]
		if !ok {
			continue
		}
		for _, old := range s.Instances {
			if old.Group.RevisionID != a.RevisionID || old.Phase == "removed" || (!old.SecretPrepared && old.PodUID == "") || old.SecretVersion == target.Digest || old.WithdrawalID != "" {
				continue
			}
			next := s.SecretSuccessors[old.ID]
			if next != nil && (next.Phase == "retired" || (next.SecretVersion != "" && next.SecretVersion != target.Digest)) {
				if e := c.cancelSecretPreparation(ctx, old.ID, next); e != nil {
					return e
				}
				next = nil
			}
			if next == nil {
				id := randomID()
				files, name, e := s.Payload.Instantiate(old.Group, id)
				if e != nil {
					return e
				}
				next = &Instance{ID: id, Group: old.Group, Generation: a.Generation, Definition: a.Revision.Definition, Files: files, Name: name, SecretVersion: target.Digest, Phase: "starting", CreatedAt: c.now()}
				if e = c.Journal.Update(func(st *State) error {
					if st.SecretSuccessors == nil {
						st.SecretSuccessors = map[string]*Instance{}
					}
					st.SecretSuccessors[old.ID] = next
					return nil
				}); e != nil {
					return e
				}
			}
			if !next.SecretPrepared {
				prepared, e := c.preparedSecret(ctx, a, next)
				if e != nil {
					return e
				}
				if prepared == nil {
					continue
				}
				if e = c.Journal.Update(func(st *State) error { mergePreparedSecret(st.SecretSuccessors[old.ID], prepared); return nil }); e != nil {
					return e
				}
			}
		}
	}
	return nil
}

func (c *Controller) collectSecrets(ctx context.Context) error {
	if c.Secrets == nil {
		return nil
	}
	st := c.Journal.View()
	for _, i := range st.Instances {
		if i.Phase == "removed" && !i.SecretCleanupDone {
			if e := c.Secrets.Delete(ctx, i.Name); e != nil {
				return e
			}
			if e := c.Journal.Update(func(state *State) error {
				if current := state.Instances[i.ID]; current != nil {
					current.SecretPrepared = false
					current.SecretCleanupDone = true
				}
				return nil
			}); e != nil {
				return e
			}
		}
	}
	if st.Payload.Intent == nil {
		return nil
	}
	for oldID, next := range st.SecretSuccessors {
		valid := false
		for _, a := range st.Payload.Intent.Entries {
			if a.RevisionID == next.Group.RevisionID && a.Desired == "present" && !centralSecretTransition(st, a) && a.Generation == next.Generation {
				valid = true
			}
		}
		if st.Instances[oldID] == nil {
			valid = false
		}
		if target, observed := c.Secrets.Targets[next.Group.RevisionID]; observed && next.SecretVersion != "" && next.SecretVersion != target.Digest {
			valid = false
		}
		if fault := c.Secrets.Faults[next.Group.RevisionID]; fault == "secret_missing" || fault == "secrets_denied" {
			valid = false
		}
		if next.Phase == "retired" {
			valid = false
		}
		if !valid {
			if e := c.cancelSecretPreparation(ctx, oldID, next); e != nil {
				return e
			}
		}
	}
	return nil
}

// Persist cancellation before external deletion so observed denial, deletion
// or supersession remains actionable through later authorization outages.
func (c *Controller) cancelSecretPreparation(ctx context.Context, oldID string, next *Instance) error {
	if e := c.Journal.Update(func(st *State) error {
		if pending := st.SecretSuccessors[oldID]; pending != nil {
			pending.Phase = "retired"
		}
		return nil
	}); e != nil {
		return e
	}
	if e := c.Secrets.Delete(ctx, next.Name); e != nil {
		return e
	}
	return c.Journal.Update(func(st *State) error { delete(st.SecretSuccessors, oldID); return nil })
}
func (c *Controller) secretSuccessorReady(i *Instance, s *State, now time.Time) bool {
	c.mu.Lock()
	p, ok := c.proofs[i.ID]
	c.mu.Unlock()
	return ok && p.PodUID == i.PodUID && p.Observation.RunnerID == s.Identity.RunnerID && p.Observation.Credential == s.Identity.Credential && now.Before(p.Observation.At.Add(p.Observation.TTL)) && p.App.Status == "ready" && c.Probes.Ready(i.ID, i.PodUID)
}
