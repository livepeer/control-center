// Package machineconfig plans, renders and publishes machine configuration.
package machineconfig

import (
	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/payment"
	"github.com/livepeer/control-center/schema"
	"regexp"
	"time"
)

const PrivateOrchestrator = contract.PrivateOrchestrator

type Machine struct {
	NodeID, Epoch, InstallDir, K3sVersion string
	CredentialVersion                     int64
	Terminal                              bool
}

// State is the enrollment's workload rollout, independent of any provider.
type State struct {
	ConnectorImage         string    `json:"connector_image,omitempty"`
	HeldUpgradePlan        string    `json:"held_upgrade_plan,omitempty"`
	ApplyingConfigDigest   string    `json:"applying_config_digest,omitempty"`
	ApplyingUpgradeVersion string    `json:"applying_upgrade_version,omitempty"`
	Lifecycle              string    `json:"lifecycle"`
	Generation             int64     `json:"generation"`
	DrainRequested         bool      `json:"drain_requested,omitempty"`
	DrainStartedAt         time.Time `json:"drain_started_at,omitempty"`
	DrainedGeneration      int64     `json:"drained_generation,omitempty"`
	Target                 string    `json:"target,omitempty"`
	PaymentSettled         bool      `json:"payment_settled,omitempty"`
	PaymentDrainAfter      time.Time `json:"payment_drain_after,omitempty"`
	HeldPayment            string    `json:"held_payment,omitempty"`
	HeldOrchestrator       string    `json:"held_orchestrator,omitempty"`
	PendingConfigDigest    string    `json:"pending_config_digest,omitempty"`
	ApprovedConfigDigest   string    `json:"approved_config_digest,omitempty"`
	RolloutReason          string    `json:"rollout_reason,omitempty"`
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
	Image         string
	NodeAddresses []string
}

type Desired struct {
	Payment      payment.Config
	PaymentError error
	PaymentReady bool
	Machine
	Apps                    *schema.AppAssignmentSetV1
	State                   State
	Exposure                *Exposure
	Connector               ConnectorConfig
	ControlAPIURL           string
	RuntimeImage            string
	NodeDrainTimeout        *time.Duration
	NodeImage               string
	StopSignals             bool
	AppPayload              *appbundle.Payload
	AppsError               string
	RequestedAppsGeneration int64
	DrainTimeout            time.Duration
	RetainedFiles           map[string][]byte
}

var imageDigestPattern = regexp.MustCompile(`^[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}$`)

func ValidConnectorImage(image string) bool { return imageDigestPattern.MatchString(image) }

type Report struct {
	Payment             *payment.Observation    `json:"payment,omitempty"`
	ObserverID          string                  `json:"observer_id,omitempty"`
	ObserverStartedAt   time.Time               `json:"observer_started_at,omitempty"`
	ClockUncertain      bool                    `json:"clock_uncertain,omitempty"`
	DownloadedAt        time.Time               `json:"downloaded_at,omitempty"`
	DeliveryReason      string                  `json:"delivery_reason,omitempty"`
	ConnectorObservedAt time.Time               `json:"connector_observed_at,omitempty"`
	ConnectorExpiresAt  time.Time               `json:"connector_expires_at,omitempty"`
	ReportVersion       int                     `json:"report_version,omitempty"`
	ObservedAt          time.Time               `json:"observed_at,omitempty"`
	Downloaded          *contract.StageIdentity `json:"downloaded,omitempty"`
	Epoch               string                  `json:"epoch"`
	CredentialVersion   int64                   `json:"credential_version"`
	Component           string                  `json:"component"`
	Generation          int64                   `json:"generation"`
	BundleSHA256        string                  `json:"bundle_sha256,omitempty"`
	ConfigDigest        string                  `json:"config_digest,omitempty"`
	K3sVersion          string                  `json:"k3s_version,omitempty"`
	ProviderVersion     int64                   `json:"provider_version,omitempty"`
	TokenGeneration     int64                   `json:"token_generation,omitempty"`
	Ready               bool                    `json:"ready"`
	Drained             bool                    `json:"drained"`
	HTTPS               bool                    `json:"https"`
	ConnectorAbsent     bool                    `json:"connector_absent"`
	Reason              string                  `json:"reason,omitempty"`
	BundleFormat        int                     `json:"bundle_format,omitempty"`
	AppsError           string                  `json:"apps_error,omitempty"`
	Sequence            uint64                  `json:"sequence,omitempty"`
	Evidence            *contract.Evidence      `json:"evidence,omitempty"`
	Apps                *contract.AppStatus     `json:"apps,omitempty"`
}
