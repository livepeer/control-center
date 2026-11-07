package controlplane

import (
	"context"
	"time"
)

// RoutingState is the non-secret #111 desired-state input. Only the bundle
// reconciler renders it. A source generation changes when its URL or credential
// reference changes; transport health alone does not replace a Collector source.
type RoutingState struct {
	Lifecycle            string                `json:"lifecycle"`
	Generation           int64                 `json:"generation"`
	EndpointGeneration   int64                 `json:"endpoint_generation"`
	AccountID            string                `json:"account_id"`
	ZoneID               string                `json:"zone_id"`
	TeamName             string                `json:"team_name"`
	RotationReason       string                `json:"rotation_reason,omitempty"`
	TunnelID             string                `json:"tunnel_id"`
	ServiceURL           string                `json:"service_url"`
	ProxyURLTemplate     string                `json:"proxy_url_template"`
	DiscoveryURL         string                `json:"discovery_url"`
	IngressDigest        string                `json:"ingress_digest"`
	ProviderVersion      int64                 `json:"provider_version"`
	CredentialGeneration int64                 `json:"credential_generation"`
	SourceGeneration     int64                 `json:"source_generation"`
	AccessVersion        int64                 `json:"access_version"`
	Resources            map[string]CFResource `json:"resources"`
	Ready                bool                  `json:"ready"`
	VerifiedAt           time.Time             `json:"verified_at,omitempty"`
	VerifiedGeneration   int64                 `json:"verified_generation"`
	Reason               string                `json:"reason"`
	CleanupComplete      bool                  `json:"cleanup_complete"`
	ConnectorRevoked     bool                  `json:"connector_revoked,omitempty"`
	Quarantined          bool                  `json:"quarantined,omitempty"`
	AppliedIngress       []IngressRule         `json:"applied_ingress,omitempty"`
	RotateTunnel         bool                  `json:"rotate_tunnel,omitempty"`
	TokenFingerprint     string                `json:"token_fingerprint,omitempty"`
	RotationStarted      bool                  `json:"rotation_started,omitempty"`
	Compromised          bool                  `json:"compromised,omitempty"`
	DrainRequested       bool                  `json:"drain_requested,omitempty"`
	EndpointDrainURL     string                `json:"endpoint_drain_url,omitempty"`
	DrainStartedAt       time.Time             `json:"drain_started_at,omitempty"`
	HeldOrchestrator     string                `json:"held_orchestrator,omitempty"`
	PendingConfigDigest  string                `json:"pending_config_digest,omitempty"`
	ApprovedConfigDigest string                `json:"approved_config_digest,omitempty"`
	RotateAccess         bool                  `json:"rotate_access,omitempty"`
	CompromisedAccess    bool                  `json:"compromised_access,omitempty"`
}

// CFResource stores an operation intent before any create. Pending operations
// with an unknown outcome are discovered by ownership before they can be retried.
type CFResource struct {
	Kind              string    `json:"kind"`
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Host              string    `json:"host,omitempty"`
	Pending           bool      `json:"pending,omitempty"`
	Audience          string    `json:"audience,omitempty"`
	Target            string    `json:"target,omitempty"`
	Proxied           bool      `json:"proxied,omitempty"`
	Absent            bool      `json:"absent,omitempty"`
	ObservedAbsent    bool      `json:"observed_absent,omitempty"`
	Watch             bool      `json:"watch,omitempty"`
	AttemptAt         time.Time `json:"attempt_at,omitempty"`
	Attempts          int       `json:"attempts,omitempty"`
	AuditAfter        time.Time `json:"audit_after,omitempty"`
	CreationTarget    string    `json:"creation_target,omitempty"`
	OperationVersion  int64     `json:"operation_version,omitempty"`
	CredentialVersion int64     `json:"credential_version,omitempty"`
	Duration          string    `json:"duration,omitempty"`
}

type AccessCredential struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type DiscoverySource struct {
	ID                 string `json:"id"`
	NodeID             string `json:"node_id"`
	Epoch              string `json:"epoch"`
	URL                string `json:"url"`
	Lifecycle          string `json:"lifecycle"`
	Ready              bool   `json:"ready"`
	Generation         int64  `json:"generation"`
	CredentialRef      string `json:"credential_ref"`
	CredentialVersion  int64  `json:"credential_version"`
	Reason             string `json:"reason"`
	RotationReason     string `json:"rotation_reason,omitempty"`
	VerifiedGeneration int64  `json:"verified_generation"`
}

// TunnelProvider is injectable: tests use simulated services, never an account.
// Implementations must bound responses and must not return provider error bodies.
type TunnelProvider interface {
	Find(context.Context, CFResource) ([]CFResource, error)
	FindOwned(context.Context, CFResource) ([]CFResource, error)
	Create(context.Context, CFResource, string) (CFResource, *AccessCredential, time.Time, error)
	Configure(context.Context, string, []IngressRule) (int64, error)
	Protect(context.Context, CFResource, []string) error
	ConnectorToken(context.Context, string) (string, error)
	RotateConnector(context.Context, string) error
	Delete(context.Context, CFResource, string) error
	Disconnect(context.Context, string) error
	Route(context.Context, CFResource, string) error
}

type MachineReport struct {
	Epoch             string `json:"epoch"`
	CredentialVersion int64  `json:"credential_version"`
	Component         string `json:"component"`
	Generation        int64  `json:"generation"`
	BundleSHA256      string `json:"bundle_sha256,omitempty"`
	ConfigDigest      string `json:"config_digest,omitempty"`
	ProviderVersion   int64  `json:"provider_version,omitempty"`
	TokenGeneration   int64  `json:"token_generation,omitempty"`
	Ready             bool   `json:"ready"`
	Drained           bool   `json:"drained"`
	HTTPS             bool   `json:"https"`
	ConnectorAbsent   bool   `json:"connector_absent"`
	Reason            string `json:"reason,omitempty"`
}
