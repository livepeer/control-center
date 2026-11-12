package orchestrator

import (
	"context"
	"io"
	"math"
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
	if !applied || a == nil || proof == nil || proof.Association != *a || time.Since(proof.ObservedAt) > 30*time.Second || a.PodUID != podUID || a.Epoch != m.Epoch || a.OnchainGeneration != m.Onchain.Generation || a.ConfigDigest != m.ConfigDigest || i.checkPod(ctx, a.Launch, m) != nil {
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
	healthy := false
	states := map[string]bool{}
	var total int64
	var ack, fail float64
	for name, f := range families {
		for _, v := range f.Metric {
			labels := map[string]string{}
			for _, l := range v.Label {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["component"] != "orchestrator" {
				continue
			}
			switch name {
			case "livepeer_collector_healthy":
				if v.Gauge == nil {
					return o
				}
				if labels["collector"] == "redemptions" && v.GetGauge().GetValue() == 1 {
					healthy = true
				}
			case "livepeer_redemption_queue_tickets":
				if v.Gauge == nil {
					return o
				}
				n := v.GetGauge().GetValue()
				s := labels["state"]
				if states[s] || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 10000000 || math.Trunc(n) != n {
					return o
				}
				states[s] = true
				total += int64(n)
			case "livepeer_redemption_transitions_total":
				if labels["event"] == "acknowledged" {
					ack += v.GetCounter().GetValue()
				}
				if labels["event"] == "retryable" || labels["event"] == "rejected" {
					fail += v.GetCounter().GetValue()
				}
			}
		}
	}
	for _, s := range []string{"waiting", "eligible", "in_flight", "awaiting_finality", "rejected", "blocked", "unknown"} {
		if !states[s] {
			return o
		}
	}
	if i.checkPod(ctx, a.Launch, m) != nil {
		return o
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.grant != a {
		return o
	}
	o.QueueKnown = healthy && len(states) == 7
	o.Unsettled = total
	now := time.Now()
	if i.metricsGrant == a.GrantID && (ack < i.lastAck || fail < i.lastErr) {
		return o
	}
	if i.metricsGrant != a.GrantID {
		i.metricsGrant = a.GrantID
		i.lastAck = ack
		i.lastErr = fail
		i.ackAt = time.Time{}
		i.errAt = time.Time{}
		return o // A counter baseline cannot date an earlier handoff after restart.
	}
	if ack > i.lastAck {
		i.ackAt = now
	}
	if fail > i.lastErr {
		i.errAt = now
	}
	i.lastAck = ack
	i.lastErr = fail
	if !i.errAt.IsZero() && !i.ackAt.After(i.errAt) && now.Sub(i.errAt) < 2*time.Minute {
		o.Handoff = "degraded"
	} else if !i.ackAt.IsZero() && now.Sub(i.ackAt) < 2*time.Minute {
		o.Handoff = "healthy"
	}
	return o
}
