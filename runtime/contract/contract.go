// Package contract contains the machine wire contract shared by delivery and Runtime.
package contract

import "time"

const BundleFormat = 2

type Metadata struct {
	NodeID                  string    `json:"node_id"`
	Epoch                   string    `json:"epoch"`
	CredentialVersion       int64     `json:"credential_version"`
	Generation              int64     `json:"generation"`
	Terminal                bool      `json:"terminal"`
	TerminalCleanup         bool      `json:"terminal_cleanup,omitempty"`
	TerminalInputDigest     string    `json:"terminal_input_digest,omitempty"`
	DrainRequested          bool      `json:"drain_requested"`
	ConfigDigest            string    `json:"config_digest"`
	ServiceURL              string    `json:"service_url"`
	TunnelID                string    `json:"tunnel_id"`
	TokenGeneration         int64     `json:"credential_generation"`
	ProviderVersion         int64     `json:"provider_version"`
	APIURL                  string    `json:"api_url"`
	RunnerServiceURL        string    `json:"runner_service_url"`
	ProxyURLTemplate        string    `json:"proxy_url_template"`
	DiscoveryURL            string    `json:"discovery_url"`
	IngressDigest           string    `json:"ingress_digest"`
	AppsGeneration          int64     `json:"apps_generation,omitempty"`
	AppsDigest              string    `json:"apps_digest,omitempty"`
	ConnectorTokenRef       string    `json:"connector_token_ref"`
	BundleFormat            int       `json:"bundle_format,omitempty"`
	AppsPayloadDigest       string    `json:"apps_payload_digest,omitempty"`
	AppsError               string    `json:"apps_error,omitempty"`
	RequestedAppsGeneration int64     `json:"requested_apps_generation,omitempty"`
	DrainTarget             string    `json:"drain_target,omitempty"`
	DrainStartedAt          time.Time `json:"drain_started_at,omitempty"`
	DrainDeadline           time.Time `json:"drain_deadline,omitempty"`
	UpgradeDigest           string    `json:"upgrade_digest,omitempty"`
	UpgradeVersion          string    `json:"upgrade_version,omitempty"`
}

type Evidence struct {
	Target                string    `json:"target"`
	OwnerID               string    `json:"owner_id"`
	CredentialFingerprint string    `json:"credential_fingerprint"`
	WithdrawalID          string    `json:"withdrawal_id"`
	MutationSequence      uint64    `json:"mutation_sequence"`
	ObservedAt            time.Time `json:"observed_at"`
	ExpiresAt             time.Time `json:"expires_at"`
	Kind                  string    `json:"kind"`
}

type InstanceStatus struct {
	RevisionID           string    `json:"revision_id"`
	Generation           int64     `json:"generation"`
	ActivationGeneration int64     `json:"activation_generation"`
	InstanceID           string    `json:"instance_id"`
	PodUID               string    `json:"pod_uid,omitempty"`
	AppID                string    `json:"app_id,omitempty"`
	Phase                string    `json:"phase"`
	Ready                bool      `json:"ready"`
	Registered           bool      `json:"registered"`
	Capacity             int       `json:"capacity"`
	Sessions             int       `json:"sessions"`
	Reason               string    `json:"reason,omitempty"`
	Deadline             time.Time `json:"deadline,omitempty"`
	Forced               bool      `json:"forced,omitempty"`
	CancelAttemptAt      time.Time `json:"cancel_attempt_at,omitempty"`
	RemovalPublishedAt   time.Time `json:"removal_published_at,omitempty"`
	TerminatedAt         time.Time `json:"terminated_at,omitempty"`
}

type AppStatus struct {
	DesiredGeneration int64            `json:"desired_generation"`
	DesiredDigest     string           `json:"desired_digest,omitempty"`
	StagedDigest      string           `json:"staged_digest,omitempty"`
	PublishedDigest   string           `json:"published_digest,omitempty"`
	AppliedDigest     string           `json:"applied_digest,omitempty"`
	Reason            string           `json:"reason,omitempty"`
	Instances         []InstanceStatus `json:"instances"`
	OwnerRecreatedAt  time.Time        `json:"owner_recreated_at,omitempty"`
}
