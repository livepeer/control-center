package machineconfig

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
)

var statusCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)
var statusID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
var revisionID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func validCode(s string) bool  { return s == "" || statusCode.MatchString(s) }
func optionalID(s string) bool { return s == "" || statusID.MatchString(s) }

func (s *Manager) validateObservations(ctx context.Context, m Machine, r Report) error {
	if r.Software != nil && r.Component != "runtime" {
		return ErrStaleStatus
	}
	if !optionalID(r.ObserverID) {
		return ErrStaleStatus
	}
	if !validCode(r.AppsError) || !validCode(r.DeliveryReason) {
		return ErrStaleStatus
	}
	stages := []*contract.StageIdentity{r.Downloaded}
	members := []contract.AssignmentStatus{}
	var downloadedDigest, downloadedArtifact, desiredDigest string
	var desiredGeneration int64
	if r.Downloaded != nil {
		downloadedDigest = r.Downloaded.AppsDigest
		downloadedArtifact = strings.TrimPrefix(r.Downloaded.ArtifactDigest, "sha256:")
	}
	if r.Apps != nil {
		a := r.Apps
		desiredDigest, desiredGeneration = a.DesiredDigest, a.DesiredGeneration
		for _, digest := range []string{a.StagedDigest, a.PublishedDigest, a.AppliedDigest} {
			if digest != "" && !artifact.HashPattern.MatchString(digest) {
				return ErrStaleStatus
			}
		}
		if a.Instances == nil || len(a.Instances) > 128 || len(a.Assignments) > 100 || !validCode(a.Reason) || a.InstancesTotal < 0 || a.InstancesOmitted < 0 || a.InstancesTotal != len(a.Instances)+a.InstancesOmitted {
			return ErrStaleStatus
		}
		stages = append(stages, &contract.StageIdentity{Generation: a.DesiredGeneration, AppsDigest: a.DesiredDigest}, a.Staged, a.Published, a.Applied)
		seen := map[string]bool{}
		for _, i := range a.Instances {
			if !revisionID.MatchString(i.RevisionID) || i.Generation < 1 || i.ActivationGeneration < 1 || i.ActivationGeneration > i.Generation || !statusID.MatchString(i.InstanceID) || len(i.InstanceID) > 64 || seen[i.InstanceID] || !optionalID(i.PodUID) || !optionalID(i.RunnerID) || !optionalID(i.AppID) || !optionalID(i.WithdrawalID) || !validCode(i.Reason) || !validCode(i.WorkloadReason) || !validCode(i.Phase) || i.Capacity < 0 || i.Capacity > 10000 || i.Sessions < -1 {
				return ErrStaleStatus
			}
			seen[i.InstanceID] = true
			if i.Probe != nil && (i.Probe.Failures < 0 || i.Probe.Failures > 1000000 || i.Probe.ExpiresAt.Before(i.Probe.ObservedAt)) {
				return ErrStaleStatus
			}
		}
		seen = map[string]bool{}
		for _, a := range a.Assignments {
			if !revisionID.MatchString(a.RevisionID) || seen[a.RevisionID] || a.Generation < 1 || a.ActivationGeneration < 1 || a.ActivationGeneration > a.Generation || !validCode(a.Reason) || a.Instances < 0 || a.Ready < 0 || a.Registered < 0 || a.CleanupPending < 0 || a.Ready > a.Instances || a.Registered > a.Instances || a.CleanupPending > a.Instances {
				return ErrStaleStatus
			}
			seen[a.RevisionID] = true
		}
		// Both current summaries and retained incarnation identities must have
		// actually been delivered to this enrollment, not merely exist in the catalog.
		members = append(members, a.Assignments...)
		for _, i := range a.Instances {
			members = append(members, contract.AssignmentStatus{RevisionID: i.RevisionID, Generation: i.Generation, ActivationGeneration: i.ActivationGeneration})
		}
	}
	deliveredStages := []contract.StageIdentity{}
	for _, stage := range stages {
		if stage == nil {
			continue
		}
		if stage.Generation < 0 || (stage.AppsDigest != "" && !artifact.HashPattern.MatchString(stage.AppsDigest)) || (stage.ArtifactDigest != "" && !artifact.HashPattern.MatchString(stage.ArtifactDigest)) {
			return ErrStaleStatus
		}
		if stage.AppsDigest == "" {
			if stage.Generation != 0 {
				return ErrStaleStatus
			}
			continue
		}
		deliveredStages = append(deliveredStages, *stage)
	}
	if r.Apps == nil && len(deliveredStages) == 0 {
		return nil
	}
	memberJSON, _ := json.Marshal(members)
	stageJSON, _ := json.Marshal(deliveredStages)
	// Each check has its own delivery witness; an artifact and its reported
	// generation may have been recorded by different deliveries. The scalar
	// stage EXISTS keeps each lookup constrained by the delivery digest index.
	var downloaded, bound, membership, knownStages bool
	err := s.store.DB.QueryRowContext(ctx, `SELECT
 ($2::text='' OR EXISTS(SELECT FROM lpcc.machine_app_deliveries WHERE node_id=$1 AND apps_digest=$2 AND bundle_sha256=$3)),
 (NOT $4::boolean OR NOT EXISTS(SELECT FROM lpcc.machine_app_deliveries WHERE node_id=$1 AND terminal)
 OR EXISTS(SELECT FROM lpcc.machine_app_deliveries WHERE node_id=$1 AND terminal AND apps_generation=$5 AND apps_digest=$6)),
 NOT EXISTS(SELECT FROM jsonb_to_recordset($7::jsonb) AS i(revision_id text,generation bigint,activation_generation bigint)
 WHERE NOT EXISTS(SELECT FROM lpcc.machine_app_deliveries d WHERE d.node_id=$1 AND d.entries @> jsonb_build_array(jsonb_build_object('revision_id',i.revision_id,'generation',i.generation,'activation_generation',i.activation_generation)))),
 NOT EXISTS(SELECT FROM jsonb_to_recordset($8::jsonb) AS s(generation bigint,apps_digest text)
 WHERE NOT (SELECT EXISTS(SELECT FROM lpcc.machine_app_deliveries d WHERE d.node_id=$1 AND d.apps_digest=s.apps_digest AND (s.generation=0 OR d.apps_generation=s.generation))))`,
		m.NodeID, downloadedDigest, downloadedArtifact, r.Apps != nil && m.Terminal && r.Component == "runner", desiredGeneration, desiredDigest, string(memberJSON), string(stageJSON)).Scan(&downloaded, &bound, &membership, &knownStages)
	if err != nil {
		return err
	}
	if !downloaded || !bound || !membership || !knownStages {
		return ErrStaleStatus
	}
	return nil
}

// ObservationTime is shared by status projections and safety gates. Receipt
// time may cap a measurement's age but cannot make an old observation younger.
func ObservationTime(r Report, received time.Time) time.Time {
	if r.ClockUncertain || r.ObservedAt.IsZero() {
		return time.Time{}
	}
	if r.ObservedAt.Before(received) {
		return r.ObservedAt
	}
	return received
}
