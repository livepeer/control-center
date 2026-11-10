package schema

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"github.com/j0sh/boa/pkg/boa"
	"math"
	"regexp"
	"strconv"
	"strings"
	"uuid"
)

const MaxAppAssignments = 100
const MaxAppIntentBytes = 900 << 10

type AppCleanupPolicy struct {
	StopSignal      *string `json:"stop_signal"`
	StopGracePeriod string  `json:"stop_grace_period"`
}

type AppStartAfter struct {
	RevisionID string `json:"source_revision_id"`
	Generation int64  `json:"source_removal_generation"`
}

// AppReplacement identifies a rolling replacement; it does not grant a bypass of StartAfter.
type AppReplacement struct {
	RevisionID           string `json:"source_revision_id"`
	ActivationGeneration int64  `json:"source_activation_generation"`
	Generation           int64  `json:"source_removal_generation"`
	Replicas             int    `json:"replica_limit"`
}

// Generation orders intent edits. ActivationGeneration identifies an incarnation
// across scale edits, and changes only after removal and a fresh assignment.
type AppAssignment struct {
	RevisionRef
	Generation           int64             `json:"generation"`
	ActivationGeneration int64             `json:"activation_generation"`
	Desired              string            `json:"desired"`
	Cleanup              AppCleanupPolicy  `json:"cleanup"`
	Revision             *ResolvedRevision `json:"revision,omitempty"`
	Replicas             int               `json:"replicas,omitempty"`
	Replacement          *AppReplacement   `json:"replacement,omitempty"`
	StartAfter           *AppStartAfter    `json:"start_after,omitempty"`
	StartAllowed         bool              `json:"start_allowed"`
}

type AppAssignmentSetV1 struct {
	SchemaVersion int             `json:"schema_version"`
	NodeID        string          `json:"node_id"`
	Epoch         string          `json:"epoch"`
	Generation    int64           `json:"apps_generation"`
	Entries       []AppAssignment `json:"entries"`
}

var assignmentNodePattern = regexp.MustCompile(`^lp-[0-9a-f]{16}$`)

func canonicalUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != (uuid.UUID{}) && id.String() == s
}

func CleanupPolicy(d DefinitionV1) AppCleanupPolicy {
	return AppCleanupPolicy{d.Lifecycle.StopSignal, d.Lifecycle.StopGracePeriod}
}

func (a AppAssignment) Absent() AppAssignment {
	a.Desired = "absent"
	a.Revision = nil
	a.Replicas = 0
	a.StartAfter = nil
	a.Replacement = nil
	a.StartAllowed = false
	return a
}

func (s AppAssignmentSetV1) Validate() error {
	if s.SchemaVersion != 1 || !assignmentNodePattern.MatchString(s.NodeID) || !canonicalUUID(s.Epoch) || s.Generation < 1 || s.Entries == nil || len(s.Entries) > MaxAppAssignments {
		return fmt.Errorf("invalid app assignment set envelope")
	}
	previous := ""
	for _, a := range s.Entries {
		if !canonicalUUID(a.RevisionID) || a.RevisionID <= previous || !digestPattern.MatchString(a.Digest) || a.Generation < 1 || a.ActivationGeneration < 1 || a.ActivationGeneration > a.Generation {
			return fmt.Errorf("invalid or duplicate assignment identity")
		}
		previous = a.RevisionID
		n, err := strconv.ParseInt(strings.TrimSuffix(a.Cleanup.StopGracePeriod, "s"), 10, 64)
		if err != nil || n < 0 || n > 300 || a.Cleanup.StopGracePeriod != strconv.FormatInt(n, 10)+"s" {
			return fmt.Errorf("invalid cleanup duration")
		}
		if err := boa.Validate(Lifecycle{StartupTimeout: "120s", StopSignal: a.Cleanup.StopSignal, StopGracePeriod: a.Cleanup.StopGracePeriod}); err != nil {
			return fmt.Errorf("invalid cleanup lifecycle")
		}

		switch a.Desired {
		case "present":
			if r := a.Replacement; r != nil && (!canonicalUUID(r.RevisionID) || r.RevisionID == a.RevisionID || r.Generation < 1 || r.ActivationGeneration < 1 || r.ActivationGeneration > r.Generation || r.Replicas <= 1 || r.Replicas != a.Replicas) {
				return fmt.Errorf("invalid rolling replacement")
			}
			if a.Revision == nil || a.Revision.RevisionRef != a.RevisionRef || a.Revision.Verify() != nil || ValidateReplicaCount(a.Replicas) != nil {
				return fmt.Errorf("invalid pinned assignment definition")
			}
			policy, _ := json.Marshal(CleanupPolicy(a.Revision.Definition))
			actual, _ := json.Marshal(a.Cleanup)
			if string(policy) != string(actual) {
				return fmt.Errorf("cleanup policy differs from pinned definition")
			}
			if a.StartAfter == nil && !a.StartAllowed {
				return fmt.Errorf("unconditional assignment cannot be blocked")
			}
			if a.StartAfter != nil && (!canonicalUUID(a.StartAfter.RevisionID) || a.StartAfter.RevisionID == a.RevisionID || a.StartAfter.Generation < 1) {
				return fmt.Errorf("invalid cleanup prerequisite")
			}
		case "absent":
			if a.Revision != nil || a.Replicas != 0 || a.StartAfter != nil || a.Replacement != nil || a.StartAllowed {
				return fmt.Errorf("removal must be a compact tombstone")
			}
		default:
			return fmt.Errorf("unsupported assignment desired state")
		}
	}
	return nil
}

// Struct field order, sorted entries and normalized definitions define v1 bytes.
func CanonicalAssignmentSet(s AppAssignmentSetV1) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(s)
	if len(b) > MaxAppIntentBytes {
		return nil, fmt.Errorf("assignment set too large")
	}
	return b, err
}

func DecodeAssignmentSet(b []byte) (AppAssignmentSetV1, error) {
	var s AppAssignmentSetV1
	if len(b) > MaxAppIntentBytes {
		return s, fmt.Errorf("assignment set too large")
	}
	if err := jsonv2.Unmarshal(b, &s, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return s, err
	}
	var raw struct {
		Entries []map[string]json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return s, err
	}
	for _, a := range raw.Entries {
		for _, key := range []string{"revision_id", "digest", "generation", "activation_generation", "desired", "cleanup", "start_allowed"} {
			if _, ok := a[key]; !ok {
				return s, fmt.Errorf("missing assignment field %s", key)
			}
		}
		if r, ok := a["revision"]; ok {
			if _, err := DecodeRevision(r); err != nil {
				return s, err
			}
		}
	}
	return s, s.Validate()
}

// Reserve the larger present/removal form and maximum counter widths, so a
// previously admitted assignment can always be removed without growing the set.
func CheckAssignmentBudget(s AppAssignmentSetV1) error {
	registrations := 0
	for _, a := range s.Entries {
		if a.Desired != "present" {
			continue
		}
		if a.Revision == nil {
			return fmt.Errorf("missing present revision")
		}
		count := max(1, len(a.Revision.Definition.Apps))
		if a.Replicas < 1 || count > MaxRegistrations/a.Replicas {
			return fmt.Errorf("registration budget exceeded")
		}
		registrations += count * a.Replicas
		if registrations > MaxRegistrations {
			return fmt.Errorf("registration budget exceeded")
		}
	}
	s.Generation = math.MaxInt64
	s.Entries = append([]AppAssignment{}, s.Entries...)
	for i, a := range s.Entries {
		a.Generation = math.MaxInt64
		a.ActivationGeneration = math.MaxInt64
		if a.StartAfter != nil {
			p := *a.StartAfter
			p.Generation = math.MaxInt64
			a.StartAfter = &p
			a.StartAllowed = false
		}
		present, _ := json.Marshal(a)
		removed, _ := json.Marshal(a.Absent())
		if len(removed) > len(present) {
			a = a.Absent()
		}
		s.Entries[i] = a
	}
	_, err := CanonicalAssignmentSet(s)
	return err
}
