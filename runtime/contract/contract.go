// Package contract contains the machine wire contract shared by delivery and Runtime.
package contract

import (
	"github.com/livepeer/control-center/runtime/onchain"
	"time"
)

const BundleFormat = 3

type Metadata struct {
	Onchain                 onchain.Config `json:"onchain"`
	OnchainCredentialsRef   string         `json:"onchain_credentials_ref,omitempty"`
	OnchainActive           bool           `json:"onchain_active"`
	NodeID                  string         `json:"node_id"`
	CredentialVersion       int64          `json:"credential_version"`
	Generation              int64          `json:"generation"`
	Terminal                bool           `json:"terminal"`
	TerminalCleanup         bool           `json:"terminal_cleanup,omitempty"`
	TerminalInputDigest     string         `json:"terminal_input_digest,omitempty"`
	DrainRequested          bool           `json:"drain_requested"`
	ConfigDigest            string         `json:"config_digest"`
	ServiceURL              string         `json:"service_url"`
	TunnelID                string         `json:"tunnel_id"`
	TokenGeneration         int64          `json:"credential_generation"`
	ProviderVersion         int64          `json:"provider_version"`
	APIURL                  string         `json:"api_url"`
	RunnerServiceURL        string         `json:"runner_service_url"`
	ProxyURLTemplate        string         `json:"proxy_url_template"`
	DiscoveryURL            string         `json:"discovery_url"`
	IngressDigest           string         `json:"ingress_digest"`
	AppsGeneration          int64          `json:"apps_generation,omitempty"`
	AppsDigest              string         `json:"apps_digest,omitempty"`
	ConnectorTokenRef       string         `json:"connector_token_ref"`
	BundleFormat            int            `json:"bundle_format,omitempty"`
	AppsPayloadDigest       string         `json:"apps_payload_digest,omitempty"`
	AppsError               string         `json:"apps_error,omitempty"`
	RequestedAppsGeneration int64          `json:"requested_apps_generation,omitempty"`
	DrainTarget             string         `json:"drain_target,omitempty"`
	DrainStartedAt          time.Time      `json:"drain_started_at,omitempty"`
	DrainDeadline           time.Time      `json:"drain_deadline,omitempty"`
	UpgradeDigest           string         `json:"upgrade_digest,omitempty"`
	UpgradeVersion          string         `json:"upgrade_version,omitempty"`
}

type Evidence struct {
	Target                string    `json:"target"`
	OwnerID               string    `json:"owner_id"`
	CredentialFingerprint string    `json:"credential_fingerprint"`
	WithdrawalID          string    `json:"withdrawal_id"`
	MutationSequence      *uint64   `json:"mutation_sequence"`
	ObservedAt            time.Time `json:"observed_at"`
	ExpiresAt             time.Time `json:"expires_at"`
	Kind                  string    `json:"kind"`
}

type InstanceStatus struct {
	RevisionID           string       `json:"revision_id"`
	Generation           int64        `json:"generation"`
	ActivationGeneration int64        `json:"activation_generation"`
	InstanceID           string       `json:"instance_id"`
	PodUID               string       `json:"pod_uid,omitempty"`
	AppID                string       `json:"app_id,omitempty"`
	Phase                string       `json:"phase"`
	Ready                bool         `json:"ready"`
	Registered           bool         `json:"registered"`
	Capacity             int          `json:"capacity"`
	Sessions             int          `json:"sessions"`
	Reason               string       `json:"reason,omitempty"`
	Deadline             time.Time    `json:"deadline,omitempty"`
	Forced               bool         `json:"forced,omitempty"`
	RemovalPublishedAt   time.Time    `json:"removal_published_at,omitempty"`
	TerminatedAt         time.Time    `json:"terminated_at,omitempty"`
	RunnerID             string       `json:"runner_id,omitempty"`
	WithdrawalID         string       `json:"withdrawal_id,omitempty"`
	DrainExpiredAt       time.Time    `json:"drain_expired_at,omitempty"`
	RegistrationGone     bool         `json:"registration_gone,omitempty"`
	NodeObservedAt       time.Time    `json:"node_observed_at,omitempty"`
	NodeExpiresAt        time.Time    `json:"node_expires_at,omitempty"`
	AcceptedSequence     *uint64      `json:"accepted_sequence,omitempty"`
	StartupDeadline      time.Time    `json:"startup_deadline,omitempty"`
	Probe                *ProbeStatus `json:"probe,omitempty"`
	WorkloadReason       string       `json:"workload_reason,omitempty"`
}

const MaxStatusBytes = 128 << 10

// StageIdentity keeps an artifact's original intent independent of newer input.
// Generation zero means the source generation is unknown.
type StageIdentity struct {
	Generation     int64  `json:"generation"`
	AppsDigest     string `json:"apps_digest,omitempty"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
}

type ProbeStatus struct {
	ObservedAt time.Time `json:"observed_at"`
	DueAt      time.Time `json:"due_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Success    bool      `json:"success"`
	Failures   int       `json:"failures"`
	Started    bool      `json:"started"`
}

type AssignmentStatus struct {
	NodeExpiresAt        time.Time `json:"node_expires_at,omitempty"`
	ProbeExpiresAt       time.Time `json:"probe_expires_at,omitempty"`
	RevisionID           string    `json:"revision_id"`
	Generation           int64     `json:"generation"`
	ActivationGeneration int64     `json:"activation_generation"`
	Reason               string    `json:"reason,omitempty"`
	Instances            int       `json:"instances"`
	Ready                int       `json:"ready"`
	Registered           int       `json:"registered"`
	CleanupPending       int       `json:"cleanup_pending"`
}

type AppStatus struct {
	DesiredGeneration int64              `json:"desired_generation"`
	DesiredDigest     string             `json:"desired_digest,omitempty"`
	StagedDigest      string             `json:"staged_digest,omitempty"`
	PublishedDigest   string             `json:"published_digest,omitempty"`
	AppliedDigest     string             `json:"applied_digest,omitempty"`
	Reason            string             `json:"reason,omitempty"`
	Instances         []InstanceStatus   `json:"instances"`
	OwnerRecreatedAt  time.Time          `json:"owner_recreated_at,omitempty"`
	Staged            *StageIdentity     `json:"staged,omitempty"`
	Published         *StageIdentity     `json:"published,omitempty"`
	Applied           *StageIdentity     `json:"applied,omitempty"`
	Assignments       []AssignmentStatus `json:"assignments,omitempty"`
	InstancesTotal    int                `json:"instances_total,omitempty"`
	InstancesOmitted  int                `json:"instances_omitted,omitempty"`
}
