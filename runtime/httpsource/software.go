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
	build := contract.SoftwareIdentity{Component: "runtime", Scope: "running", Version: Version, Commit: Commit}
	o := []contract.SoftwareIdentity{build}
	for _, ns := range []string{"livepeer", "flux-system"} {
		var pods transport.PodList
		if node == "" || s.Kube.Request(ctx, "GET", "/api/v1/namespaces/"+ns+"/pods?fieldSelector="+url.QueryEscape("spec.nodeName="+node), nil, &pods) != nil {
			continue
		}
		for _, p := range pods.Items {
			workload := systemWorkload(ns, p.Metadata.Labels)
			if workload == "" || p.Spec.NodeName != node {
				continue
			}
			for _, c := range p.Status.ContainerStatuses {
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
	switch ns + "/" + app {
	case "livepeer/orchestrator", "flux-system/livepeer-http-source", "flux-system/livepeer-app-reconciler", "flux-system/livepeer-tunnel", "flux-system/source-controller", "flux-system/kustomize-controller":
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
	if err != nil || metrics["livepeer_build_info"] == nil {
		return nil
	}
	var build *contract.SoftwareIdentity
	for _, metric := range metrics["livepeer_build_info"].Metric {
		labels := map[string]string{}
		for _, l := range metric.Label {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["component"] != "orchestrator" || metric.GetGauge().GetValue() != 1 {
			continue
		}
		if build != nil || len(labels["version"]) > 128 || len(labels["revision"]) > 128 {
			return nil
		}
		commit := labels["revision"]
		build = &contract.SoftwareIdentity{Component: "livepeer-node", Scope: "running", Version: labels["version"], Commit: commit, PodUID: pod.UID, ContainerID: pod.ContainerID}
	}
	// Container ID fences a restart within a Pod as well as a Pod replacement.
	after, err := transport.ObserveNode(ctx, s.Kube)
	if err != nil || after.UID != pod.UID || after.ContainerID != pod.ContainerID {
		return nil
	}
	return build
}
