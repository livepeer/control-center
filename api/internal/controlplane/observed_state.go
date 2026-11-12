package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	fleet "github.com/livepeer/control-center/api/internal/controlplane/discovery"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/livepeer/control-center/schema"
)

type componentObservation struct {
	Onchain             *onchain.Observation    `json:"onchain,omitempty"`
	ObserverID          string                  `json:"observer_id,omitempty"`
	ObserverStartedAt   *time.Time              `json:"observer_started_at,omitempty"`
	Component           string                  `json:"component"`
	Generation          int64                   `json:"generation"`
	ObservedAt          time.Time               `json:"observed_at,omitempty"`
	ReceivedAt          *time.Time              `json:"received_at,omitempty"`
	ExpiresAt           *time.Time              `json:"expires_at,omitempty"`
	Fresh               bool                    `json:"fresh"`
	Current             bool                    `json:"current"`
	Ready               bool                    `json:"ready"`
	Reason              string                  `json:"reason"`
	ClockUncertain      bool                    `json:"clock_uncertain"`
	BundleSHA256        string                  `json:"bundle_sha256,omitempty"`
	ConfigDigest        string                  `json:"config_digest,omitempty"`
	Downloaded          *contract.StageIdentity `json:"downloaded,omitempty"`
	DownloadedAt        *time.Time              `json:"downloaded_at,omitempty"`
	DeliveryReason      string                  `json:"delivery_reason,omitempty"`
	AppsError           string                  `json:"apps_error,omitempty"`
	ConnectorObservedAt *time.Time              `json:"connector_observed_at,omitempty"`
	ConnectorExpiresAt  *time.Time              `json:"connector_expires_at,omitempty"`
	Apps                *contract.AppStatus     `json:"apps,omitempty"`
}

// These explicit response types are shared by owners and administrators. Never
// serialize catalog/assignment persistence types, routing ledgers or raw logs here.
type observedAssignment struct {
	RevisionID           string     `json:"revision_id"`
	Digest               string     `json:"digest"`
	Name                 string     `json:"name"`
	Version              string     `json:"version"`
	Revision             int64      `json:"revision"`
	Generation           int64      `json:"generation"`
	ActivationGeneration int64      `json:"activation_generation"`
	Desired              string     `json:"desired"`
	Replicas             int        `json:"replicas"`
	StartAllowed         bool       `json:"start_allowed"`
	CompletedAt          *time.Time `json:"completed_at"`
	Failure              string     `json:"failure,omitempty"`
	Health               struct {
		Type             string `json:"type"`
		Interval         string `json:"interval"`
		Timeout          string `json:"timeout"`
		FailureThreshold int    `json:"failure_threshold"`
	} `json:"health"`
	Mode          string   `json:"-"`
	DiscoveryApps []string `json:"-"`
}

type tunnelObservation struct {
	Enabled          bool       `json:"enabled"`
	Ready            bool       `json:"ready"`
	Reason           string     `json:"reason"`
	VerifiedAt       *time.Time `json:"verified_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	SourceGeneration int64      `json:"source_generation"`
	CleanupComplete  bool       `json:"cleanup_complete"`
}

type machineObservation struct {
	Onchain                     onchainView                 `json:"onchain"`
	NodeID                      string                      `json:"node_id"`
	Epoch                       string                      `json:"epoch"`
	Hostname                    string                      `json:"hostname"`
	Lifecycle                   string                      `json:"lifecycle"`
	RolloutGeneration           int64                       `json:"rollout_generation"`
	Requested                   contract.StageIdentity      `json:"requested"`
	Delivered                   *contract.StageIdentity     `json:"delivered,omitempty"`
	DeliveredAt                 *time.Time                  `json:"delivered_at,omitempty"`
	DeliveryReason              string                      `json:"delivery_reason,omitempty"`
	Assignments                 []observedAssignment        `json:"assignments"`
	AssignmentsOmitted          bool                        `json:"assignments_omitted"`
	Components                  []componentObservation      `json:"components"`
	Tunnel                      tunnelObservation           `json:"tunnel"`
	DiscoveryEnabled            bool                        `json:"discovery_enabled"`
	DiscoveryInitialized        bool                        `json:"discovery_initialized"`
	DiscoverySelectionExpiresAt *time.Time                  `json:"discovery_selection_expires_at,omitempty"`
	DiscoverySelectionStale     bool                        `json:"discovery_selection_stale"`
	DiscoverySource             *fleet.SourceStatus         `json:"discovery_source,omitempty"`
	Membership                  map[string]fleet.Membership `json:"membership"`
	ExternalReachability        string                      `json:"external_reachability"`
	ServerTime                  time.Time                   `json:"server_time"`
}

var observationReason = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

func safeObservationReason(value string) string {
	if value == "" || observationReason.MatchString(value) {
		return value
	}
	return "unknown_failure"
}
func timePointer(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (s *Server) observedState(w http.ResponseWriter, r *http.Request) {
	u, err := s.user(r.Context(), bearer(r))
	if err != nil {
		s.respondError(w, err)
		return
	}
	node, epoch := r.PathValue("node_id"), r.URL.Query().Get("epoch")
	if epoch != "" && !appID(epoch) {
		s.respondError(w, problem(400, "invalid_epoch", "Provide an enrollment UUID."))
		return
	}
	var owner string
	var m Machine
	err = s.db.QueryRowContext(r.Context(), `SELECT e.epoch::text,e.owner_id::text,e.hostname,e.credential_version,e.retired_at IS NOT NULL FROM lpcc.enrollments e
 WHERE e.node_id=$1 AND (($2<>'' AND e.epoch::text=$2) OR ($2='' AND EXISTS(SELECT FROM lpcc.machines m WHERE m.node_id=e.node_id AND m.enrollment_epoch=e.epoch)))`, node, epoch).Scan(&m.Epoch, &owner, &m.Hostname, &m.CredentialVersion, &m.Terminal)
	if errors.Is(err, sql.ErrNoRows) {
		err = problem(404, "machine_not_found", "Machine enrollment not found.")
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	if owner != u.ID {
		admin, e := s.adminStatus(r.Context(), u)
		if e != nil {
			s.respondError(w, e)
			return
		}
		if !admin {
			s.respondError(w, problem(404, "machine_not_found", "Machine enrollment not found."))
			return
		}
	}
	m.NodeID = node
	view, err := s.machineObservation(r.Context(), m)
	if err != nil {
		s.respondError(w, err)
		return
	}
	respond(w, 200, view)
}

func (s *Server) machineObservation(ctx context.Context, m Machine) (machineObservation, error) {
	now := time.Now().UTC()
	v := machineObservation{NodeID: m.NodeID, Epoch: m.Epoch, Hostname: m.Hostname, Assignments: []observedAssignment{}, Components: []componentObservation{}, Membership: map[string]fleet.Membership{}, ExternalReachability: "unverified", ServerTime: now}
	ttl := s.params.TunnelStatusTTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	record, err := (machineconfig.Store{DB: s.db}).Load(ctx, m.NodeID, m.Epoch)
	if errors.Is(err, sql.ErrNoRows) {
		record.State = machineconfig.InitialState(m.Terminal)
	} else if err != nil {
		return v, err
	}
	v.Onchain, err = s.onchainView(ctx, m)
	if err != nil {
		return v, err
	}
	v.Lifecycle, v.RolloutGeneration = record.Lifecycle, record.Generation
	if m.Terminal {
		var ack *time.Time
		if err := s.db.QueryRowContext(ctx, `SELECT removal_ack_at FROM lpcc.enrollments WHERE node_id=$1 AND epoch=$2`, m.NodeID, m.Epoch).Scan(&ack); err != nil {
			return v, err
		}
		v.Lifecycle = "cleanup_pending"
		if ack != nil {
			v.Lifecycle = "removed"
		}
	}
	var route tunnel.RoutingState
	if len(record.Routing) > 0 && json.Unmarshal(record.Routing, &route) != nil {
		return v, errors.New("invalid routing state")
	}
	v.Tunnel = tunnelObservation{Enabled: route.TunnelID != "" || s.params.CloudflareEnabled, Ready: route.Ready && route.ReadyGeneration == record.Generation && !route.VerifiedAt.IsZero() && now.Before(route.VerifiedAt.Add(ttl)), Reason: safeObservationReason(route.Reason), VerifiedAt: timePointer(route.VerifiedAt), SourceGeneration: route.SourceGeneration, CleanupComplete: route.CleanupComplete}
	if !route.VerifiedAt.IsZero() {
		v.Tunnel.ExpiresAt = timePointer(route.VerifiedAt.Add(ttl))
	}
	err = s.db.QueryRowContext(ctx, `SELECT apps_generation,COALESCE(apps_error,'') FROM lpcc.machine_states WHERE node_id=$1 AND epoch=$2`, m.NodeID, m.Epoch).Scan(&v.Requested.Generation, &v.DeliveryReason)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return v, err
	}
	v.DeliveryReason = safeObservationReason(v.DeliveryReason)
	var delivered contract.StageIdentity
	var at time.Time
	err = s.db.QueryRowContext(ctx, `SELECT apps_generation,apps_digest,'sha256:'||bundle_sha256,published_at FROM lpcc.machine_app_deliveries WHERE node_id=$1 AND epoch=$2 ORDER BY published_at DESC,apps_generation DESC LIMIT 1`, m.NodeID, m.Epoch).Scan(&delivered.Generation, &delivered.AppsDigest, &delivered.ArtifactDigest, &at)
	if err == nil {
		v.Delivered, v.DeliveredAt = &delivered, &at
	} else if !errors.Is(err, sql.ErrNoRows) {
		return v, err
	}
	v.Assignments, v.AssignmentsOmitted, err = s.observedAssignments(ctx, m)
	if err != nil {
		return v, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT component,report,received_at FROM lpcc.machine_reports WHERE node_id=$1 AND epoch=$2 AND credential_version=$3 ORDER BY component`, m.NodeID, m.Epoch, m.CredentialVersion)
	if err != nil {
		return v, err
	}
	observations := map[string]componentObservation{}
	for rows.Next() {
		var name string
		var raw []byte
		var received time.Time
		var report machineconfig.Report
		if err = rows.Scan(&name, &raw, &received); err != nil {
			break
		}
		if err = json.Unmarshal(raw, &report); err != nil {
			break
		}
		effective := machineconfig.ObservationTime(report, received)
		var expires *time.Time
		if !effective.IsZero() {
			expires = timePointer(effective.Add(ttl))
		}
		c := componentObservation{Component: name, Generation: report.Generation, ObservedAt: report.ObservedAt, ReceivedAt: &received, ExpiresAt: expires, Fresh: expires != nil && now.Before(*expires), Current: report.Generation == record.Generation, Ready: report.Ready, Reason: safeObservationReason(report.Reason), ClockUncertain: report.ClockUncertain, BundleSHA256: report.BundleSHA256, ConfigDigest: report.ConfigDigest, DeliveryReason: safeObservationReason(report.DeliveryReason)}
		c.Onchain = report.Onchain
		if c.Onchain != nil {
			copy := *c.Onchain
			copy.GrantID = ""
			if !c.Fresh || !c.Current || c.ClockUncertain {
				copy.Ready = false
				copy.Applied = false
				copy.Handoff = "unverified"
			}
			c.Onchain = &copy
		}
		c.AppsError = safeObservationReason(report.AppsError)
		c.Apps, c.Downloaded, c.DownloadedAt = report.Apps, report.Downloaded, timePointer(report.DownloadedAt)
		c.ObserverID, c.ObserverStartedAt = report.ObserverID, timePointer(report.ObserverStartedAt)
		c.ConnectorObservedAt, c.ConnectorExpiresAt = timePointer(report.ConnectorObservedAt), timePointer(report.ConnectorExpiresAt)
		if name == "connector" && (report.ConnectorObservedAt.IsZero() || !now.Before(report.ConnectorExpiresAt)) {
			c.Ready = false
			if report.Ready {
				c.Reason = "connector_observation_stale"
			}
		}
		if c.ClockUncertain {
			c.Ready = false
			c.Reason = "clock_uncertain"
		}
		observations[name] = c
	}
	readErr := rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	if readErr != nil {
		return v, readErr
	}
	for _, name := range []string{"runtime", "app-reconciler", "runner", "connector"} {
		if c, ok := observations[name]; ok {
			v.Components = append(v.Components, c)
		} else {
			v.Components = append(v.Components, componentObservation{Component: name, Reason: "unreported"})
		}
	}
	if s.discovery != nil {
		status := s.discovery.Status()
		v.DiscoveryEnabled, v.DiscoveryInitialized, v.DiscoverySelectionStale = status.Enabled, status.Initialized, status.SelectionStale
		v.DiscoverySelectionExpiresAt = status.SelectionExpiresAt
		for _, source := range status.Sources {
			if source.NodeID == m.NodeID && source.Epoch == m.Epoch {
				v.DiscoverySource = &source
				break
			}
		}
		byRevision := map[string]observedAssignment{}
		for _, a := range v.Assignments {
			byRevision[a.RevisionID] = a
		}
		if app := observations["runner"].Apps; app != nil {
			queries := []fleet.MembershipQuery{}
			for _, i := range app.Instances {
				a, ok := byRevision[i.RevisionID]
				if !ok || i.AppID == "" {
					continue
				}
				queries = append(queries, a.membershipQueries(i, route.ServiceURL, route.ProxyURLTemplate)...)
			}
			v.Membership = s.discovery.Memberships(m.NodeID, m.Epoch, queries)
		}
	}
	return v, nil
}

func (a observedAssignment) membershipQueries(i contract.InstanceStatus, serviceURL, proxyTemplate string) []fleet.MembershipQuery {
	names := a.DiscoveryApps
	if len(names) == 0 {
		names = []string{a.Name}
	}
	queries := make([]fleet.MembershipQuery, len(names))
	for n, name := range names {
		id := i.AppID
		if len(a.DiscoveryApps) > 0 {
			id = fmt.Sprintf("r-%s-%d", i.InstanceID, n)
		}
		endpoint := strings.TrimRight(serviceURL, "/") + "/apps/" + url.PathEscape(id) + "/session"
		if a.Mode == "single-shot" {
			endpoint = strings.Replace(proxyTemplate, "{proxy}", id, 1)
		}
		queries[n] = fleet.MembershipQuery{InstanceID: i.InstanceID, Endpoint: endpoint, App: name, Version: a.Version}
	}
	return queries
}

func (s *Server) observedAssignments(ctx context.Context, m Machine) ([]observedAssignment, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT v.intent-'revision',r.app_name,r.app_version,r.revision,r.canonical,c.received_at,CASE WHEN c.received_at IS NULL THEN COALESCE(d.reason,'') ELSE '' END FROM lpcc.machine_app_heads v `+` JOIN lpcc.app_revisions r ON r.revision_id=v.revision_id
 LEFT JOIN lpcc.machine_app_completions c ON c.node_id=v.node_id AND c.epoch=v.epoch AND c.revision_id=v.revision_id AND c.generation=v.generation
 LEFT JOIN lpcc.machine_app_diagnostics d ON d.node_id=v.node_id AND d.epoch=v.epoch AND d.revision_id=v.revision_id AND d.generation=v.generation
 WHERE v.node_id=$1 AND v.epoch=$2 AND (v.intent->>'desired'='present' OR c.received_at IS NULL) ORDER BY v.revision_id LIMIT 101`, m.NodeID, m.Epoch)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	result := []observedAssignment{}
	for rows.Next() {
		var a observedAssignment
		var intent, canonical []byte
		var definition schema.DefinitionV1
		var assignment schema.AppAssignment
		if err = rows.Scan(&intent, &a.Name, &a.Version, &a.Revision, &canonical, &a.CompletedAt, &a.Failure); err != nil {
			return nil, false, err
		}
		if err = json.Unmarshal(intent, &assignment); err != nil {
			return nil, false, err
		}
		if err = json.Unmarshal(canonical, &definition); err != nil {
			return nil, false, err
		}
		a.RevisionID, a.Digest, a.Generation, a.ActivationGeneration = assignment.RevisionID, assignment.Digest, assignment.Generation, assignment.ActivationGeneration
		a.Desired, a.Replicas, a.StartAllowed = assignment.Desired, assignment.Replicas, assignment.StartAllowed
		a.Failure = safeObservationReason(a.Failure)
		a.Health.Type, a.Health.Interval, a.Health.Timeout, a.Health.FailureThreshold = definition.Health.Readiness.Type, definition.Health.Readiness.Interval, definition.Health.Readiness.Timeout, definition.Health.Readiness.FailureThreshold
		a.Mode = definition.Runner.Mode
		for _, app := range definition.Apps {
			a.DiscoveryApps = append(a.DiscoveryApps, app.Name)
		}
		result = append(result, a)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	omitted := len(result) > 100
	if omitted {
		result = result[:100]
	}
	return result, omitted, nil
}

type observedMachineSummary struct {
	NodeID            string     `json:"node_id"`
	Epoch             string     `json:"epoch"`
	Hostname          string     `json:"hostname"`
	OwnerID           *string    `json:"owner_id,omitempty"`
	InstallDir        string     `json:"install_dir,omitempty"`
	K3sVersion        string     `json:"k3s_version"`
	CreatedAt         time.Time  `json:"created_at"`
	LastConfigFetchAt *time.Time `json:"last_config_fetch_at"`
	Lifecycle         string     `json:"lifecycle"`
	Terminal          bool       `json:"terminal"`
	LastObservedAt    *time.Time `json:"last_observed_at"`
	ReportState       string     `json:"report_state"`
}

func (s *Server) observedMachineList(ctx context.Context, owner string, admin bool) ([]observedMachineSummary, error) {
	rows, err := s.db.QueryContext(ctx, `WITH inventory AS (
 SELECT m.node_id,m.enrollment_epoch AS epoch,m.hostname,m.owner_id,m.install_dir,m.k3s_version,m.created_at,m.last_config_fetch_at,m.credential_version,false AS terminal,COALESCE(s.rollout->>'lifecycle','active') AS lifecycle
 FROM lpcc.machines m LEFT JOIN lpcc.machine_states s ON s.node_id=m.node_id AND s.epoch=m.enrollment_epoch
 UNION ALL
 SELECT e.node_id,e.epoch,e.hostname,e.owner_id,e.install_dir,e.k3s_version,e.retired_at,NULL::timestamptz,e.credential_version,true,'cleanup_pending'
 FROM lpcc.enrollments e WHERE e.retired_at IS NOT NULL AND e.removal_ack_at IS NULL
 ) SELECT i.node_id,i.epoch::text,i.hostname,i.owner_id::text,i.install_dir,i.k3s_version,i.created_at,i.last_config_fetch_at,i.terminal,i.lifecycle,
 CASE WHEN COALESCE((r.report->>'clock_uncertain')::boolean,false) THEN NULL
 ELSE LEAST(r.received_at,(r.report->>'observed_at')::timestamptz) END, COALESCE((r.report->>'clock_uncertain')::boolean,false)
 FROM inventory i LEFT JOIN lpcc.machine_reports r ON r.node_id=i.node_id AND r.epoch=i.epoch AND r.credential_version=i.credential_version AND r.component='runtime'
 WHERE ($1='' OR i.owner_id::text=$1) ORDER BY i.created_at DESC,i.node_id,i.epoch`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []observedMachineSummary{}
	ttl := s.params.TunnelStatusTTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	for rows.Next() {
		var m observedMachineSummary
		var id string
		var clockUncertain bool
		if err = rows.Scan(&m.NodeID, &m.Epoch, &m.Hostname, &id, &m.InstallDir, &m.K3sVersion, &m.CreatedAt, &m.LastConfigFetchAt, &m.Terminal, &m.Lifecycle, &m.LastObservedAt, &clockUncertain); err != nil {
			return nil, err
		}
		if admin {
			m.OwnerID = &id
			m.InstallDir = ""
		}
		m.ReportState = "unreported"
		if clockUncertain {
			m.ReportState = "clock_uncertain"
		} else if m.LastObservedAt != nil {
			m.ReportState = "observed"
			if time.Since(*m.LastObservedAt) > ttl {
				m.ReportState = "stale"
			}
		}
		result = append(result, m)
	}
	return result, rows.Err()
}

type onchainView struct {
	Desired             onchain.Config `json:"desired"`
	DeliveredGeneration int64          `json:"delivered_generation"`
}

func (s *Server) onchainView(ctx context.Context, m Machine) (onchainView, error) {
	var v onchainView
	var err error
	v.Desired, err = loadOnchain(ctx, s.db, m.NodeID)
	if err != nil {
		return v, err
	}
	v.Desired.RPCSecret = ""
	v.Desired.RPCGrants = nil
	v.Desired.RedeemerGrants = nil
	var b []byte
	if m.Terminal {
		err = s.db.QueryRowContext(ctx, `SELECT retained_bundle FROM lpcc.enrollments WHERE node_id=$1 AND epoch=$2`, m.NodeID, m.Epoch).Scan(&b)
	} else {
		err = s.db.QueryRowContext(ctx, `SELECT bundle FROM lpcc.machine_configs WHERE node_id=$1`, m.NodeID).Scan(&b)
	}
	if err == nil {
		files, e := artifact.Read(b)
		if e == nil {
			var meta contract.Metadata
			if json.Unmarshal(files["runtime.json"], &meta) == nil {
				v.DeliveredGeneration = meta.Onchain.Generation
			}
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return v, err
}
