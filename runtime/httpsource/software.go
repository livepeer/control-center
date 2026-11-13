package httpsource

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/runtime/version"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

var resolvedDigest = regexp.MustCompile(`(?:^|[@/])sha256:([0-9a-f]{64})$`)

// software takes new observations on every report. It never borrows desired
// versions or retains a successful observation across a failed read.
func (s *Source) software(ctx context.Context, m contract.Metadata, nodeName string) *contract.SoftwareStatus {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	o := &contract.SoftwareStatus{Runtime: version.Current(), Containers: []contract.ContainerIdentity{}}
	if !o.Runtime.Valid() {
		o.Runtime, o.Incomplete = contract.BuildIdentity{}, true
	}
	if o.Runtime.Version == "" || o.Runtime.Commit == "" {
		o.Incomplete = true
	}
	if nodeName == "" {
		o.Incomplete = true
	} else {
		for _, namespace := range []string{"livepeer", "flux-system", "system-upgrade", "kube-system"} {
			var pods transport.PodList
			attempt, done := context.WithTimeout(ctx, time.Second)
			err := s.Kube.Request(attempt, http.MethodGet, "/api/v1/namespaces/"+namespace+"/pods?fieldSelector="+url.QueryEscape("spec.nodeName="+nodeName), nil, &pods)
			done()
			if err != nil {
				o.Incomplete = true
				continue
			}
			for _, p := range pods.Items {
				workload := systemWorkload(namespace, p.Metadata.Labels)
				if workload == "" || p.Spec.NodeName != nodeName {
					continue
				}
				statuses := append(p.Status.ContainerStatuses, p.Status.InitContainerStatuses...)
				for _, c := range statuses {
					if c.State.Running == nil {
						continue
					}
					if len(o.Containers) == contract.MaxSoftwareContainers {
						o.Incomplete = true
						continue
					}
					digest := ""
					if match := resolvedDigest.FindStringSubmatch(c.ImageID); len(match) == 2 {
						digest = "sha256:" + match[1]
					}
					if digest == "" {
						o.Incomplete = true
					}
					identity := contract.ContainerIdentity{Namespace: namespace, Workload: workload, PodName: p.Metadata.Name, PodUID: p.Metadata.UID, Container: c.Name, ContainerID: c.ContainerID, Image: c.Image, ImageID: c.ImageID, Digest: digest, StartedAt: c.State.Running.StartedAt, Ready: c.Ready}
					if identity.Valid() {
						o.Containers = append(o.Containers, identity)
					} else {
						o.Incomplete = true
					}
				}
			}
		}
		o.Node = s.nodeBuild(ctx, nodeName)
		if o.Node == nil || o.Node.Version == "" || o.Node.Commit == "" {
			o.Incomplete = true
		}
	}
	if s.HostSoftwareFile != "" {
		f, err := os.Open(s.HostSoftwareFile)
		if err == nil {
			defer f.Close()
			b, err := io.ReadAll(io.LimitReader(f, 8193))
			var h contract.HostSoftware
			if err == nil && len(b) <= 8192 && transport.Decode(b, &h) == nil && h.Valid(m.NodeID, m.CredentialVersion) && time.Since(h.ObservedAt) >= -5*time.Second && time.Since(h.ObservedAt) < contract.HostSoftwareTTL {
				o.Host = &h
			}
		}
	}
	if o.Host == nil || o.Host.FluxCLI == "" || o.Host.GVisorInstalled == "" || o.Host.GVisorRunning == nil {
		o.Incomplete = true
	}
	return o
}

func systemWorkload(namespace string, labels map[string]string) string {
	app := labels["app"]
	if contract.SystemWorkload(namespace, app) {
		return app
	}
	if namespace == "system-upgrade" && labels["app.kubernetes.io/name"] == "system-upgrade-controller" {
		return "system-upgrade-controller"
	}
	if namespace == "system-upgrade" && labels["upgrade.cattle.io/plan"] == "livepeer-k3s" {
		return "livepeer-k3s-upgrade"
	}
	if namespace == "kube-system" && labels["k8s-app"] == "kube-dns" {
		return "coredns"
	}
	return ""
}

func (s *Source) nodeBuild(ctx context.Context, nodeName string) *contract.ProcessIdentity {
	pod, err := transport.ObserveNode(ctx, s.Kube)
	if err != nil || pod.UID == "" || pod.NodeName != nodeName || net.ParseIP(pod.IP) == nil || pod.Container.ContainerID == "" || pod.Container.State.Running == nil || pod.Container.State.Running.StartedAt.IsZero() {
		return nil
	}
	probe, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(probe, http.MethodGet, "http://"+net.JoinHostPort(pod.IP, "8936")+"/metrics", nil)
	resp, err := s.Control.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, err := readBounded(resp, 1<<20)
	if err != nil {
		return nil
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	metrics, err := parser.TextToMetricFamilies(bytes.NewReader(b))
	if err != nil || metrics["livepeer_build_info"] == nil {
		return nil
	}
	var build *contract.BuildIdentity
	for _, metric := range metrics["livepeer_build_info"].Metric {
		v, component := contract.BuildIdentity{}, ""
		for _, label := range metric.Label {
			switch label.GetName() {
			case "version":
				v.Version = label.GetValue()
			case "revision":
				v.Commit = label.GetValue()
			case "component":
				component = label.GetValue()
			}
		}
		if component != "orchestrator" || metric.GetGauge().GetValue() != 1 {
			continue
		}
		if build != nil { // Ambiguous process metadata is unknown.
			return nil
		}
		if strings.EqualFold(v.Commit, "unknown") {
			v.Commit = ""
		}
		build = &v
	}
	if build == nil || !build.Valid() {
		return nil
	}
	// A Pod UID alone does not fence a restart within the same Pod.
	after, err := transport.ObserveNode(ctx, s.Kube)
	if err != nil || after.UID != pod.UID || after.Container.ContainerID != pod.Container.ContainerID || after.Container.State.Running == nil || !after.Container.State.Running.StartedAt.Equal(pod.Container.State.Running.StartedAt) {
		return nil
	}
	identity := &contract.ProcessIdentity{BuildIdentity: *build, PodUID: pod.UID, ContainerID: pod.Container.ContainerID, StartedAt: pod.Container.State.Running.StartedAt}
	if !identity.Valid() {
		return nil
	}
	return identity
}
