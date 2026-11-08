// Package machineconfig plans, renders and publishes machine configuration.
package machineconfig

import (
	"regexp"
	"time"
)

const PrivateOrchestrator = "http://orchestrator.livepeer.svc.cluster.local:8935"

type Machine struct {
	NodeID, Epoch, InstallDir, K3sVersion string
	CredentialVersion                     int64
	Terminal                              bool
}

// State is the enrollment's workload rollout, independent of any provider.
type State struct {
	Lifecycle            string    `json:"lifecycle"`
	Generation           int64     `json:"generation"`
	DrainRequested       bool      `json:"drain_requested,omitempty"`
	DrainStartedAt       time.Time `json:"drain_started_at,omitempty"`
	Target               string    `json:"target,omitempty"`
	HeldOrchestrator     string    `json:"held_orchestrator,omitempty"`
	PendingConfigDigest  string    `json:"pending_config_digest,omitempty"`
	ApprovedConfigDigest string    `json:"approved_config_digest,omitempty"`
	RolloutReason        string    `json:"rollout_reason,omitempty"`
}

func InitialState(terminal bool) State {
	lifecycle := "active"
	if terminal {
		lifecycle = "removed"
	}
	return State{Lifecycle: lifecycle, Generation: 1}
}

// Exposure contains only the routing facts consumed by configuration rendering.
type Exposure struct {
	TunnelID, ServiceURL, ProxyURLTemplate, DiscoveryURL, IngressDigest string
	CredentialGeneration, ProviderVersion                               int64
}

type ConnectorConfig struct {
	Image                              string
	NodeAddresses, PrivateControlCIDRs []string
}

type Desired struct {
	Machine
	State         State
	Exposure      *Exposure
	Connector     ConnectorConfig
	ControlAPIURL string
}

var imageDigestPattern = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}$`)

func ValidConnectorImage(image string) bool { return imageDigestPattern.MatchString(image) }

type Report struct {
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
