package consumer

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/onchain"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

func (i *Integration) Observe(ctx context.Context, m contract.Metadata, applied, ready bool, podUID string) *onchain.Observation {
	o := &onchain.Observation{Generation: m.Onchain.Generation, Mode: m.Onchain.Mode, PodUID: podUID, Applied: applied, Ready: ready, Handoff: "unverified"}
	if !m.Onchain.Onchain() {
		return o
	}
	i.mu.Lock()
	a := i.grant
	proof := i.observation
	i.mu.Unlock()
	if !applied || a == nil || proof == nil || proof.Association != *a || time.Since(proof.ObservedAt) > 30*time.Second || a.PodUID != podUID || a.NodeID != m.NodeID || a.OnchainGeneration != m.Onchain.Generation || a.ConfigDigest != m.ConfigDigest || i.checkPod(ctx, a.Launch) != nil {
		o.Applied = false
		o.Ready = false
		return o
	}
	o.Ready = ready && proof.Ready
	o.GrantID = a.GrantID
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://orchestrator.livepeer.svc.cluster.local:8936/metrics", nil)
	// Private fixed origin; never use URLs from metrics or reports.
	client := *http.DefaultClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := client.Do(req)
	if e != nil {
		return o
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return o
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return o
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, e := parser.TextToMetricFamilies(strings.NewReader(string(b)))
	if e != nil {
		return o
	}
	var ack, fail float64
	for _, v := range families["livepeer_redemption_transitions_total"].GetMetric() {
		labels := map[string]string{}
		for _, label := range v.Label {
			labels[label.GetName()] = label.GetValue()
		}
		if labels["component"] == "orchestrator" {
			switch labels["event"] {
			case "acknowledged":
				ack += v.GetCounter().GetValue()
			case "retryable", "rejected":
				fail += v.GetCounter().GetValue()
			}
		}
	}
	if i.checkPod(ctx, a.Launch) != nil {
		return o
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.grant != a {
		return o
	}
	now := time.Now()
	if i.metricsGrant == a.GrantID && (ack < i.lastAck || fail < i.lastErr) {
		return o
	}
	if i.metricsGrant != a.GrantID {
		i.metricsGrant, i.lastAck, i.lastErr = a.GrantID, ack, fail
		i.handoffAt = time.Time{}
		return o // A counter baseline cannot date an earlier handoff after restart.
	}
	if ack > i.lastAck || fail > i.lastErr {
		i.handoff, i.handoffAt = "healthy", now
		if fail > i.lastErr {
			i.handoff = "degraded"
		}
	}
	i.lastAck, i.lastErr = ack, fail
	if now.Sub(i.handoffAt) < 2*time.Minute {
		o.Handoff = i.handoff
	}
	return o
}
