package httpsource

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// Set by release builds; unstamped binaries retain unknown fields.
var Version, Commit string

type installedRecord struct {
	RecordedAt time.Time `json:"recorded_at"`
	FluxCLI    string    `json:"flux_cli"`
	GVisor     string    `json:"gvisor"`
}

func (s *Source) software(ctx context.Context, node string) []contract.SoftwareIdentity {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	o := []contract.SoftwareIdentity{{Component: "runtime", Scope: "running", Version: Version, Commit: Commit}}
	for _, ns := range []string{"livepeer", "flux-system", "kube-system", "system-upgrade"} {
		var pods transport.PodList
		if node == "" || s.Kube.Request(ctx, "GET", "/api/v1/namespaces/"+ns+"/pods?fieldSelector="+url.QueryEscape("spec.nodeName="+node), nil, &pods) != nil {
			continue
		}
		for _, p := range pods.Items {
			workload := systemWorkload(ns, p.Metadata.Labels)
			if workload == "" || p.Spec.NodeName != node {
				continue
			}
			for _, c := range append(p.Status.ContainerStatuses, p.Status.InitContainerStatuses...) {
				if c.State.Running == nil {
					continue
				}
				if p.Metadata.UID == "" || c.ContainerID == "" || c.ImageID == "" || len(o) == 64 {
					continue
				}
				o = append(o, contract.SoftwareIdentity{Component: ns + "/" + workload + "/" + c.Name, Scope: "running", PodUID: p.Metadata.UID, ContainerID: c.ContainerID, ImageID: c.ImageID})
			}
		}
	}
	if n := s.nodeBuild(ctx, node); n != nil {
		o = append(o, *n)
	}
	if f, err := os.Open(s.InstalledSoftwareFile); err == nil {
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, 8193))
		var i installedRecord
		if err == nil && len(b) <= 8192 && transport.Decode(b, &i) == nil && !i.RecordedAt.IsZero() && !i.RecordedAt.After(time.Now().Add(5*time.Second)) {
			o = append(o, contract.SoftwareIdentity{Component: "flux-cli", Scope: "installed", Version: i.FluxCLI, RecordedAt: &i.RecordedAt}, contract.SoftwareIdentity{Component: "gvisor", Scope: "installed", Version: i.GVisor, RecordedAt: &i.RecordedAt})
		}
	}
	return o
}

func systemWorkload(ns string, labels map[string]string) string {
	app := labels["app"]
	if ns == "kube-system" && labels["k8s-app"] == "kube-dns" {
		app = "coredns"
	}
	if ns == "kube-system" && labels["app.kubernetes.io/name"] == "traefik" {
		app = "traefik"
	}
	if ns == "system-upgrade" {
		app = labels["app.kubernetes.io/name"]
		if labels["upgrade.cattle.io/plan"] == "livepeer-k3s" {
			app = "livepeer-k3s-upgrade"
		}
	}
	switch ns + "/" + app {
	case "livepeer/ingress-auth", "kube-system/traefik", "livepeer/orchestrator", "flux-system/livepeer-http-source", "flux-system/livepeer-app-reconciler", "flux-system/livepeer-tunnel", "flux-system/source-controller", "flux-system/kustomize-controller", "kube-system/coredns", "kube-system/local-path-provisioner", "system-upgrade/system-upgrade-controller", "system-upgrade/livepeer-k3s-upgrade":
		return app
	}
	return ""
}

func (s *Source) nodeBuild(ctx context.Context, node string) *contract.SoftwareIdentity {
	pod, err := transport.ObserveNode(ctx, s.Kube)
	if err != nil || pod.UID == "" || pod.ContainerID == "" || pod.NodeName != node || net.ParseIP(pod.IP) == nil {
		return nil
	}
	probe, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(probe, "GET", "http://"+net.JoinHostPort(pod.IP, "8936")+"/metrics", nil)
	resp, err := s.Control.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, err := readBounded(resp, 1<<20)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	metrics, err := parser.TextToMetricFamilies(bytes.NewReader(b))
	if err != nil || metrics["livepeer_build_info"] == nil || len(metrics["livepeer_build_info"].Metric) != 1 {
		return nil
	}
	metric := metrics["livepeer_build_info"].Metric[0]
	labels := map[string]string{}
	for _, l := range metric.Label {
		labels[l.GetName()] = l.GetValue()
	}
	if labels["component"] != "orchestrator" || metric.GetGauge().GetValue() != 1 || len(labels["version"]) > 128 || len(labels["revision"]) > 128 {
		return nil
	}
	// Container ID fences a restart within a Pod as well as a Pod replacement.
	after, err := transport.ObserveNode(ctx, s.Kube)
	if err != nil || after.UID != pod.UID || after.ContainerID != pod.ContainerID {
		return nil
	}
	return &contract.SoftwareIdentity{Component: "livepeer-node", Scope: "running", Version: labels["version"], Commit: labels["revision"], PodUID: pod.UID, ContainerID: pod.ContainerID}
}
