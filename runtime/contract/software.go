package contract

import (
	"regexp"
	"time"
)

const MaxSoftwareContainers = 64

const HostSoftwareTTL = time.Minute

// BuildIdentity comes from the binary itself, never from a desired image tag.
type BuildIdentity struct {
	Version  string `json:"version,omitempty"`
	Commit   string `json:"commit,omitempty"`
	Modified bool   `json:"modified,omitempty"`
}

type ProcessIdentity struct {
	BuildIdentity
	PodUID      string    `json:"pod_uid"`
	ContainerID string    `json:"container_id"`
	StartedAt   time.Time `json:"started_at"`
}

// ContainerIdentity contains kubelet observations of a running container.
// Image is the reported reference; only ImageID/Digest identify resolved content.
type ContainerIdentity struct {
	Namespace   string    `json:"namespace"`
	Workload    string    `json:"workload"`
	PodName     string    `json:"pod_name"`
	PodUID      string    `json:"pod_uid"`
	Container   string    `json:"container"`
	ContainerID string    `json:"container_id"`
	Image       string    `json:"image,omitempty"`
	ImageID     string    `json:"image_id,omitempty"`
	Digest      string    `json:"digest,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	Ready       bool      `json:"ready"`
}

// HostSoftware is a separate, short-lived host observation. Installed runsc
// can differ from the immutable binaries still serving existing sandboxes.
type HostSoftware struct {
	NodeID            string    `json:"node_id"`
	CredentialVersion int64     `json:"credential_version"`
	ObservedAt        time.Time `json:"observed_at"`
	FluxCLI           string    `json:"flux_cli,omitempty"`
	GVisorInstalled   string    `json:"gvisor_installed,omitempty"`
	GVisorRunning     []string  `json:"gvisor_running"`
}

type SoftwareStatus struct {
	Runtime    BuildIdentity       `json:"runtime"`
	Node       *ProcessIdentity    `json:"node,omitempty"`
	Host       *HostSoftware       `json:"host,omitempty"`
	Containers []ContainerIdentity `json:"containers"`
	Incomplete bool                `json:"incomplete,omitempty"`
}

var softwareToken = regexp.MustCompile(`^[A-Za-z0-9._+:/@-]{0,512}$`)
var softwareVersion = regexp.MustCompile(`^[A-Za-z0-9._+-]{0,128}$`)
var softwareCommit = regexp.MustCompile(`^([a-fA-F0-9]{7,64})?$`)
var softwareDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func (b BuildIdentity) Valid() bool {
	return softwareVersion.MatchString(b.Version) && softwareCommit.MatchString(b.Commit)
}

func (h HostSoftware) Valid(node string, credential int64) bool {
	if h.NodeID != node || h.CredentialVersion != credential || h.ObservedAt.IsZero() || !softwareVersion.MatchString(h.FluxCLI) || !softwareVersion.MatchString(h.GVisorInstalled) || len(h.GVisorRunning) > 8 {
		return false
	}
	for _, v := range h.GVisorRunning {
		if v == "" || !softwareVersion.MatchString(v) {
			return false
		}
	}
	return true
}

func (s SoftwareStatus) Valid(node string, credential int64) bool {
	if !s.Runtime.Valid() || len(s.Containers) > MaxSoftwareContainers || (s.Host != nil && !s.Host.Valid(node, credential)) {
		return false
	}
	if s.Node != nil && !s.Node.Valid() {
		return false
	}
	for _, c := range s.Containers {
		if !c.Valid() {
			return false
		}
	}
	return true
}

func (n ProcessIdentity) Valid() bool {
	return n.BuildIdentity.Valid() && n.PodUID != "" && n.ContainerID != "" && softwareToken.MatchString(n.PodUID) && softwareToken.MatchString(n.ContainerID) && !n.StartedAt.IsZero()
}

func (c ContainerIdentity) Valid() bool {
	if !SystemWorkload(c.Namespace, c.Workload) || c.PodUID == "" || c.PodName == "" || c.Container == "" || c.ContainerID == "" || c.StartedAt.IsZero() || (c.Digest != "" && !softwareDigest.MatchString(c.Digest)) {
		return false
	}
	for _, value := range []string{c.PodUID, c.PodName, c.Container, c.ContainerID, c.Image, c.ImageID} {
		if !softwareToken.MatchString(value) {
			return false
		}
	}
	return true
}

func SystemWorkload(namespace, workload string) bool {
	if namespace == "livepeer" && workload == "orchestrator" {
		return true
	}
	if namespace == "flux-system" {
		switch workload {
		case "livepeer-http-source", "livepeer-app-reconciler", "livepeer-tunnel", "source-controller", "kustomize-controller":
			return true
		}
	}
	if namespace == "kube-system" {
		return workload == "coredns" || workload == "local-path-provisioner"
	}
	return namespace == "system-upgrade" && (workload == "system-upgrade-controller" || workload == "livepeer-k3s-upgrade")
}
