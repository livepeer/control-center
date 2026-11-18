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
	"sync"
	"time"

	fleet "github.com/livepeer/control-center/api/internal/controlplane/discovery"
	"github.com/livepeer/control-center/api/internal/controlplane/machineapps"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/onchain"
)

type componentObservation struct {
	Software            []contract.SoftwareIdentity `json:"software,omitempty"`
	IngressReady        bool                        `json:"ingress_ready"`
	IngressConfigDigest string                      `json:"ingress_config_digest,omitempty"`

	K3sVersion          string                  `json:"k3s_version,omitempty"`
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
	IngressVerified  bool       `json:"-"`
	Reason           string     `json:"reason"`
	VerifiedAt       *time.Time `json:"verified_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	SourceGeneration int64      `json:"source_generation"`
	CleanupComplete  bool       `json:"cleanup_complete"`
}

type machineObservation struct {
	Onchain                     onchainView                 `json:"onchain"`
	NodeID                      string                      `json:"node_id"`
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
	ReadinessEvidence           *machineReadinessEvidence   `json:"readiness_evidence,omitempty"`
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
	node := r.PathValue("node_id")
	var owner string
	var m Machine
	err = s.db.QueryRowContext(r.Context(), `SELECT e.node_id::text,e.orchestrator_address::text,e.hostname,e.credential_version,e.retired_at IS NOT NULL FROM lpcc.enrollments e
 WHERE e.node_id=$1`, node).Scan(&m.NodeID, &owner, &m.Hostname, &m.CredentialVersion, &m.Terminal)
	if errors.Is(err, sql.ErrNoRows) {
		err = problem(404, "machine_not_found", "Machine enrollment not found.")
	}
	if err != nil {
		s.respondError(w, err)
		return
	}
	allowed, e := member(r.Context(), s.db, u.ID, owner)
	if e != nil {
		s.respondError(w, e)
		return
	}
	if !allowed {
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

// The fleet and detail reads share a single statement snapshot of the current
// configuration, bounded assignments and reports for the current enrollment.
const observationColumns = `s.rollout,s.state,COALESCE(s.apps_generation,0),COALESCE(s.apps_error,''),
 oc.config,COALESCE(d.apps_generation,0),COALESCE(d.apps_digest,''),COALESCE('sha256:'||d.bundle_sha256,''),d.published_at,
 assignments.data,reports.data`

const observationJoins = `
 LEFT JOIN lpcc.enrollments e ON e.node_id=i.node_id
 LEFT JOIN lpcc.machine_states s ON s.node_id=i.node_id
 LEFT JOIN lpcc.onchain_state os ON os.fingerprint=e.fingerprint
 LEFT JOIN lpcc.onchain_configs oc ON oc.fingerprint=os.fingerprint AND oc.generation=os.generation
 LEFT JOIN LATERAL (
  SELECT apps_generation,apps_digest,bundle_sha256,published_at FROM lpcc.machine_app_deliveries
  WHERE node_id=i.node_id ORDER BY published_at DESC,apps_generation DESC LIMIT 1
 ) d ON true
 LEFT JOIN LATERAL (
  SELECT jsonb_agg(to_jsonb(a) ORDER BY a.revision_id) AS data FROM (
   SELECT v.revision_id,v.intent->>'digest' AS digest,v.generation,(v.intent->>'activation_generation')::bigint AS activation_generation,
          v.intent->>'desired' AS desired,(v.intent->>'replicas')::integer AS replicas,` + machineapps.StartAllowedSQL + ` AS start_allowed,
          r.app_name AS name,r.app_version AS version,r.revision,c.received_at AS completed_at,
          CASE WHEN c.received_at IS NULL THEN COALESCE(d.reason,'') ELSE '' END AS failure,
          CASE WHEN i.detail THEN def.canonical#>'{health,readiness}' END AS health,def.canonical->'runner'->>'mode' AS mode,
          jsonb_path_query_array(def.canonical,'$.apps[*].name') AS discovery_apps
   FROM lpcc.machine_app_heads v
   JOIN lpcc.app_revisions r ON r.revision_id=v.revision_id
   CROSS JOIN LATERAL (SELECT CASE WHEN i.detail OR i.discovery THEN convert_from(r.canonical,'UTF8')::jsonb END AS canonical) def
   LEFT JOIN lpcc.machine_app_completions c ON c.node_id=v.node_id AND c.revision_id=v.revision_id AND c.generation=v.generation
   LEFT JOIN lpcc.machine_app_diagnostics d ON d.node_id=v.node_id AND d.revision_id=v.revision_id AND d.generation=v.generation
   WHERE i.include_assignments AND v.node_id=i.node_id AND (v.intent->>'desired'='present' OR c.received_at IS NULL)
   ORDER BY v.revision_id LIMIT 101
  ) a
 ) assignments ON true
 LEFT JOIN LATERAL (
  SELECT jsonb_agg(to_jsonb(r)) AS data FROM (
   SELECT component,received_at,CASE WHEN i.detail THEN report ELSE jsonb_build_object(
    'generation',report->'generation','ready',report->'ready','reason',report->'reason',
    'observed_at',report->'observed_at','clock_uncertain',report->'clock_uncertain',
    'onchain',report->'onchain','ingress_ready',report->'ingress_ready','ingress_config_digest',report->'ingress_config_digest',
    'connector_observed_at',report->'connector_observed_at','connector_expires_at',report->'connector_expires_at',
    'apps_error',report->'apps_error','downloaded',report->'downloaded',
    'apps',CASE WHEN jsonb_typeof(report->'apps')='object' THEN jsonb_build_object(
     'desired_generation',report#>'{apps,desired_generation}','desired_digest',report#>'{apps,desired_digest}',
     'applied',report#>'{apps,applied}','reason',report#>'{apps,reason}','assignments',report#>'{apps,assignments}',
     'instances',(SELECT jsonb_agg(jsonb_build_object(
      'revision_id',inst->'revision_id','generation',inst->'generation','activation_generation',inst->'activation_generation',
      'instance_id',inst->'instance_id','app_id',inst->'app_id','admission_expires_at',inst->'admission_expires_at',
      'reason',inst->'reason','workload_reason',inst->'workload_reason','withdrawal_id',inst->'withdrawal_id','phase',inst->'phase',
      'probe',CASE WHEN inst#>'{probe,expires_at}' IS NOT NULL THEN jsonb_build_object('expires_at',inst#>'{probe,expires_at}') END
     )) FROM jsonb_array_elements(COALESCE(NULLIF(report#>'{apps,instances}','null'),'[]')) inst
     WHERE (i.discovery AND inst ? 'admission_expires_at') OR inst ? 'workload_reason' OR inst ? 'reason')
    ) END
   ) END AS report FROM lpcc.machine_reports
   WHERE node_id=i.node_id AND credential_version=i.credential_version
  ) r
 ) reports ON true`

type machineObservationFacts struct {
	rollout, routing, onchain, assignments, reports []byte
	generation                                      int64
	deliveryReason                                  string
	delivered                                       contract.StageIdentity
	deliveredAt                                     *time.Time
}

func (f *machineObservationFacts) scanFields() []any {
	return []any{&f.rollout, &f.routing, &f.generation, &f.deliveryReason, &f.onchain,
		&f.delivered.Generation, &f.delivered.AppsDigest, &f.delivered.ArtifactDigest, &f.deliveredAt, &f.assignments, &f.reports}
}

func (s *Server) observationTTL() time.Duration {
	if s.params.TunnelStatusTTL > 0 {
		return s.params.TunnelStatusTTL
	}
	return 2 * time.Minute
}

func (s *Server) machineObservation(ctx context.Context, m Machine) (machineObservation, error) {
	var facts machineObservationFacts
	var bundle []byte
	var ack *time.Time
	err := s.db.QueryRowContext(ctx, `SELECT `+observationColumns+`,
 CASE WHEN i.terminal THEN e.retained_bundle ELSE c.bundle END,e.removal_ack_at
 FROM (SELECT $1::text AS node_id,$2::boolean AS terminal,$3::bigint AS credential_version,true AS include_assignments,true AS detail,true AS discovery) i`+observationJoins+`
 LEFT JOIN lpcc.machine_configs c ON c.node_id=i.node_id AND NOT i.terminal
 WHERE NOT i.terminal OR e.node_id IS NOT NULL`, m.NodeID, m.Terminal, m.CredentialVersion).
		Scan(append(facts.scanFields(), &bundle, &ack)...)
	if err != nil {
		return machineObservation{}, err
	}
	v, route, err := s.composeMachineObservation(m, facts, time.Now().UTC())
	if err != nil {
		return v, err
	}
	if m.Terminal && ack != nil {
		v.Lifecycle = "removed"
	}
	if meta, _, err := machineconfig.ReadApplied(bundle); err == nil {
		v.Onchain.DeliveredGeneration = meta.Onchain.Generation
	}
	if s.discovery != nil {
		status := s.discovery.Status()
		for i := range status.Sources {
			if status.Sources[i].NodeID == m.NodeID {
				v.DiscoverySource = &status.Sources[i]
				break
			}
		}
		observeDiscovery(&v, route, status, s.discovery.Memberships, false)
	}
	v.ReadinessEvidence = v.readinessEvidence()
	return v, nil
}

func (s *Server) composeMachineObservation(m Machine, facts machineObservationFacts, now time.Time) (machineObservation, tunnel.RoutingState, error) {
	v := machineObservation{NodeID: m.NodeID, Hostname: m.Hostname, Assignments: []observedAssignment{}, Components: []componentObservation{}, Membership: map[string]fleet.Membership{}, ExternalReachability: "unverified", ServerTime: now}
	ttl := s.observationTTL()
	record := machineconfig.InitialState(m.Terminal)
	var route tunnel.RoutingState
	if facts.rollout != nil {
		if err := json.Unmarshal(facts.rollout, &record); err != nil {
			return v, route, err
		}
	}
	if facts.routing != nil {
		if err := json.Unmarshal(facts.routing, &route); err != nil {
			return v, route, err
		}
	}
	var err error
	v.Onchain, err = newOnchainView(facts.onchain)
	if err != nil {
		return v, route, err
	}
	v.Lifecycle, v.RolloutGeneration = record.Lifecycle, record.Generation
	if m.Terminal {
		v.Lifecycle = "cleanup_pending"
	}
	v.Tunnel = tunnelObservation{Enabled: route.TunnelID != "" || s.params.CloudflareEnabled, Ready: route.Ready && route.ReadyGeneration == record.Generation && !route.VerifiedAt.IsZero() && now.Before(route.VerifiedAt.Add(ttl)), Reason: safeObservationReason(route.Reason), VerifiedAt: timePointer(route.VerifiedAt), SourceGeneration: route.SourceGeneration, CleanupComplete: route.CleanupComplete}
	if !route.VerifiedAt.IsZero() {
		v.Tunnel.ExpiresAt = timePointer(route.VerifiedAt.Add(ttl))
	}
	v.Requested.Generation, v.DeliveryReason = facts.generation, safeObservationReason(facts.deliveryReason)
	if facts.deliveredAt != nil {
		v.Delivered, v.DeliveredAt = &facts.delivered, facts.deliveredAt
	}
	v.Assignments, v.AssignmentsOmitted, err = observedAssignments(facts.assignments)
	if err != nil {
		return v, route, err
	}
	var reports []struct {
		Component  string
		Report     machineconfig.Report
		ReceivedAt time.Time `json:"received_at"`
	}
	if facts.reports != nil {
		if err := json.Unmarshal(facts.reports, &reports); err != nil {
			return v, route, err
		}
	}
	observations := map[string]componentObservation{}
	for _, row := range reports {
		name, report := row.Component, row.Report
		effective := machineconfig.ObservationTime(report, row.ReceivedAt)
		var expires *time.Time
		if !effective.IsZero() {
			expires = timePointer(effective.Add(ttl))
		}
		c := componentObservation{Component: name, Generation: report.Generation, ObservedAt: report.ObservedAt, ReceivedAt: &row.ReceivedAt, ExpiresAt: expires, Fresh: expires != nil && now.Before(*expires), Current: report.Generation == record.Generation, Ready: report.Ready, Reason: safeObservationReason(report.Reason), ClockUncertain: report.ClockUncertain, BundleSHA256: report.BundleSHA256, ConfigDigest: report.ConfigDigest, DeliveryReason: safeObservationReason(report.DeliveryReason)}
		c.Software, c.K3sVersion = report.Software, report.K3sVersion
		c.IngressReady, c.IngressConfigDigest = report.IngressReady, report.IngressConfigDigest
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
	for _, name := range []string{"runtime", "app-reconciler", "runner", "connector"} {
		if c, ok := observations[name]; ok {
			v.Components = append(v.Components, c)
		} else {
			v.Components = append(v.Components, componentObservation{Component: name, Reason: "unreported"})
		}
	}
	if runtime := observations["runtime"]; runtime.currentAt(now) {
		v.Tunnel.IngressVerified = runtime.IngressReady && route.IngressAuthDigest != "" && runtime.IngressConfigDigest == route.IngressAuthDigest
	}
	return v, route, nil
}

func observeDiscovery(v *machineObservation, route tunnel.RoutingState, status fleet.Status, memberships func(string, []fleet.MembershipQuery) map[string]fleet.Membership, readinessOnly bool) {
	v.DiscoveryEnabled, v.DiscoveryInitialized, v.DiscoverySelectionStale = status.Enabled, status.Initialized, status.SelectionStale
	v.DiscoverySelectionExpiresAt = status.SelectionExpiresAt
	runner := v.component("runner")
	if runner.Apps == nil {
		return
	}
	if readinessOnly {
		source := v.DiscoverySource
		if source == nil || source.Stale || source.State == "excluded" ||
			!status.Initialized || status.SelectionStale || v.currentApps(runner) == nil {
			return
		}
	}
	byRevision := make(map[string]observedAssignment, len(v.Assignments))
	for _, a := range v.Assignments {
		byRevision[a.RevisionID] = a
	}
	var queries []fleet.MembershipQuery
	for _, i := range runner.Apps.Instances {
		a, ok := byRevision[i.RevisionID]
		if !ok || i.AppID == "" || (readinessOnly && !v.ServerTime.Before(i.AdmissionExpiresAt)) {
			continue
		}
		queries = append(queries, a.membershipQueries(i, route.ServiceURL, route.ProxyURLTemplate)...)
	}
	if len(queries) > 0 {
		v.Membership = memberships(v.NodeID, queries)
	}
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

func observedAssignments(raw []byte) ([]observedAssignment, bool, error) {
	var rows []struct {
		observedAssignment
		Mode          string
		DiscoveryApps []string `json:"discovery_apps"`
	}
	if raw != nil {
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, false, err
		}
	}
	omitted := len(rows) > 100
	if omitted {
		rows = rows[:100]
	}
	result := make([]observedAssignment, 0, len(rows))
	for _, row := range rows {
		a := row.observedAssignment
		a.Failure = safeObservationReason(a.Failure)
		if interval, _ := time.ParseDuration(a.Health.Interval); interval < 10*time.Second {
			a.Health.Interval = "10s"
		}
		a.Mode, a.DiscoveryApps = row.Mode, row.DiscoveryApps
		result = append(result, a)
	}
	return result, omitted, nil
}

type observedMachineSummary struct {
	NodeID              string                    `json:"node_id"`
	Hostname            string                    `json:"hostname"`
	OrchestratorAddress *string                   `json:"orchestrator_address,omitempty"`
	InstallDir          string                    `json:"install_dir,omitempty"`
	K3sVersion          string                    `json:"k3s_version"`
	CreatedAt           time.Time                 `json:"created_at"`
	LastConfigFetchAt   *time.Time                `json:"last_config_fetch_at"`
	Lifecycle           string                    `json:"lifecycle"`
	Terminal            bool                      `json:"terminal"`
	LastObservedAt      *time.Time                `json:"last_observed_at"`
	ReportState         string                    `json:"report_state"`
	ReadinessEvidence   *machineReadinessEvidence `json:"readiness_evidence,omitempty"`
}

func (s *Server) observedMachineList(ctx context.Context, owner string, admin bool) ([]observedMachineSummary, error) {
	rows, err := s.db.QueryContext(ctx, `WITH inventory AS (
 SELECT m.node_id,m.hostname,m.orchestrator_address,m.install_dir,m.k3s_version,m.created_at,m.last_config_fetch_at,m.credential_version,false AS terminal,true AS include_assignments,false AS detail,$2::boolean AS discovery
 FROM lpcc.machines m WHERE ($1='' OR m.orchestrator_address::text=$1)
 UNION ALL
 SELECT e.node_id,e.hostname,e.orchestrator_address,e.install_dir,e.k3s_version,e.retired_at,NULL::timestamptz,e.credential_version,true,false,false,false
 FROM lpcc.enrollments e WHERE e.retired_at IS NOT NULL AND e.removal_ack_at IS NULL AND ($1='' OR e.orchestrator_address::text=$1)
 ) SELECT i.node_id,i.hostname,i.orchestrator_address::text,i.install_dir,i.k3s_version,i.created_at,i.last_config_fetch_at,i.terminal,`+observationColumns+`
 FROM inventory i`+observationJoins+`
 ORDER BY i.created_at DESC,i.node_id`, owner, s.discovery != nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var discovery fleet.Status
	var memberships func(string, []fleet.MembershipQuery) map[string]fleet.Membership
	var sources map[string]*fleet.SourceStatus
	result := []observedMachineSummary{}
	for rows.Next() {
		var m observedMachineSummary
		var ownerAddress string
		var facts machineObservationFacts
		fields := []any{&m.NodeID, &m.Hostname, &ownerAddress, &m.InstallDir, &m.K3sVersion, &m.CreatedAt, &m.LastConfigFetchAt, &m.Terminal}
		if err := rows.Scan(append(fields, facts.scanFields()...)...); err != nil {
			return nil, err
		}
		if admin {
			m.OrchestratorAddress = &ownerAddress
			m.InstallDir = ""
		}
		view, route, err := s.composeMachineObservation(Machine{NodeID: m.NodeID, Hostname: m.Hostname, Terminal: m.Terminal}, facts, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		m.Lifecycle = view.Lifecycle
		runtime := view.component("runtime")
		m.ReportState = "unreported"
		if runtime.ClockUncertain {
			m.ReportState = "clock_uncertain"
		} else if runtime.ExpiresAt != nil {
			m.LastObservedAt = timePointer(runtime.ExpiresAt.Add(-s.observationTTL()))
			m.ReportState = "observed"
			if !runtime.Fresh {
				m.ReportState = "stale"
			}
		}
		if s.discovery != nil && view.Lifecycle == "active" {
			if sources == nil {
				discovery = s.discovery.Status()
				sources = make(map[string]*fleet.SourceStatus, len(discovery.Sources))
				for i := range discovery.Sources {
					source := &discovery.Sources[i]
					sources[source.NodeID] = source
				}
				snapshot := sync.OnceValue(s.discovery.MembershipSnapshot)
				memberships = func(node string, queries []fleet.MembershipQuery) map[string]fleet.Membership {
					return snapshot().Memberships(node, queries)
				}
			}
			view.DiscoverySource = sources[m.NodeID]
			observeDiscovery(&view, route, discovery, memberships, true)
		}
		m.ReadinessEvidence = view.readinessEvidence()
		result = append(result, m)
	}
	return result, rows.Err()
}

type onchainView struct {
	Desired             onchain.Config `json:"desired"`
	DeliveredGeneration int64          `json:"delivered_generation"`
}

func newOnchainView(config []byte) (onchainView, error) {
	v := onchainView{Desired: onchain.Offchain()}
	if config != nil {
		if err := json.Unmarshal(config, &v.Desired); err != nil {
			return v, err
		}
		if err := v.Desired.Validate(); err != nil {
			return v, err
		}
	}
	v.Desired.RPCSecret = ""
	v.Desired.RPCGrants = nil
	v.Desired.RedeemerGrants = nil
	return v, nil
}
