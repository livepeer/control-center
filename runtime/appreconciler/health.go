package appreconciler

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
	"github.com/livepeer/control-center/schema"
)

type health struct {
	uid            string
	ready, pending bool
	started        bool
	failures       int
	next           time.Time
	observedAt     time.Time
	observedDue    time.Time
	success        bool
	timeout        time.Duration
}
type probeResult struct {
	id, uid string
	success bool
	at      time.Time
}
type Probes struct {
	mu       sync.Mutex
	values   map[string]*health
	results  chan probeResult
	OnChange func()
	Client   *http.Client
	// Address is used by local contract tests; production always probes the immutable Service.
	Address func(*Instance) string
	targets map[string]*Instance
	view    View
}

func NewProbes() *Probes {
	return &Probes{values: map[string]*health{}, results: make(chan probeResult, 256), Client: transport.HTTPClient()}
}
func (p *Probes) Configure(instances map[string]*Instance, view View) {
	targets := map[string]*Instance{}
	for id, i := range instances {
		targets[id] = &Instance{ID: id, Name: i.Name, Phase: i.Phase, Definition: schema.DefinitionV1{HTTP: i.Definition.HTTP, Health: i.Definition.Health}}
	}
	p.mu.Lock()
	p.targets, p.view = targets, view
	p.mu.Unlock()
}
func (p *Probes) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			p.mu.Lock()
			instances, view := p.targets, p.view
			p.mu.Unlock()
			if instances != nil {
				p.Poll(ctx, instances, view, now)
				if p.OnChange != nil {
					p.OnChange()
				}
			}
		}
	}
}
func (p *Probes) Ready(id, uid string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.values[id]
	return h != nil && h.uid == uid && h.ready
}
func (p *Probes) Started(id, uid string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.values[id]
	return h != nil && h.uid == uid && h.started
}
func (p *Probes) Poll(ctx context.Context, instances map[string]*Instance, view View, now time.Time) map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		select {
		case r := <-p.results:
			h := p.values[r.id]
			i := instances[r.id]
			if h == nil || i == nil || h.uid != r.uid {
				continue
			}
			h.pending = false
			h.observedAt, h.success, h.observedDue = r.at, r.success, h.next
			if r.success {
				h.ready = true
				h.started = true
				h.failures = 0
			} else {
				h.failures++
				if h.failures >= i.Definition.Health.Readiness.FailureThreshold {
					h.ready = false
				}
			}
		default:
			goto consumed
		}
	}
consumed:
	ready := map[string]bool{}
	for id, h := range p.values {
		if instances[id] == nil {
			delete(p.values, id)
		} else {
			ready[id] = h.ready
		}
	}
	for id, i := range instances {
		pod, exists := view.Pods[i.Name]
		if !exists || pod.UID == "" || pod.Deleting || pod.Phase != "Running" || !view.Endpoints[i.Name][pod.UID] || i.Phase == "removed" {
			delete(p.values, id)
			ready[id] = false
			continue
		}
		h := p.values[id]
		if h == nil || h.uid != pod.UID {
			h = &health{uid: pod.UID}
			p.values[id] = h
		}
		ready[id] = h.ready
		if h.pending || now.Before(h.next) {
			continue
		}
		h.pending = true
		interval, _ := time.ParseDuration(i.Definition.Health.Readiness.Interval)
		h.next = now.Add(max(interval, 10*time.Second))
		timeout, _ := time.ParseDuration(i.Definition.Health.Readiness.Timeout)
		h.timeout = timeout
		target := privateURL(i.Name, i.Definition.HTTP.Port)
		if p.Address != nil {
			target = p.Address(i)
		}
		kind := i.Definition.Health.Readiness.Type
		if path := i.Definition.Health.Readiness.Path; path != nil {
			target += *path
		}
		uid := pod.UID
		go func() {
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ok := false
			if kind == "http" {
				req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target, nil)
				if err == nil {
					resp, err := p.Client.Do(req)
					if err == nil {
						ok = resp.StatusCode >= 200 && resp.StatusCode < 300
						resp.Body.Close()
					}
				}
			} else {
				u, err := url.Parse(target)
				if err == nil {
					conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", u.Host)
					if err == nil {
						ok = true
						conn.Close()
					}
				}
			}
			select {
			case p.results <- probeResult{id: id, uid: uid, success: ok, at: time.Now().UTC()}:
			case <-ctx.Done():
			}
		}()
	}
	return ready
}

func (p *Probes) Status(id, uid string) *contract.ProbeStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := p.values[id]
	if h == nil || h.uid != uid || h.observedAt.IsZero() {
		return nil
	}
	ttl := max(30*time.Second, h.observedDue.Sub(h.observedAt)+h.timeout+time.Second)
	return &contract.ProbeStatus{ObservedAt: h.observedAt, DueAt: h.observedDue, ExpiresAt: h.observedAt.Add(ttl), Success: h.success, Failures: h.failures, Started: h.started}
}
