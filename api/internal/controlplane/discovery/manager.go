package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/livepeer/node/destination"
	shared "github.com/livepeer/node/discovery/shared"
)

type Manager struct {
	collector           *shared.Collector[runner]
	transport           *transport
	backend             Store
	logger              *slog.Logger
	interval            time.Duration
	selectionInterval   time.Duration
	instanceID          string
	ownHost             string
	reconcileMu         sync.Mutex
	mu                  sync.Mutex // Source selection/order and metrics indices change together.
	selected            []Source
	configured          []Source
	reconciledAt        time.Time
	reconcileFailed     bool
	refreshes, failures uint64
	refreshDuration     time.Duration
}

func New(config Config, deps Dependencies) (*Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if deps.Store == nil {
		return nil, errors.New("discovery source store is required")
	}
	policy, err := destination.New("fleet discovery", config.Grants)
	if err != nil {
		return nil, errors.New("invalid discovery destination grants")
	}
	base := deps.Transport
	if base == nil {
		base = policy.Transport(3 * time.Second)
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	t := &transport{base: base, signToken: deps.SignToken}
	f := &Manager{transport: t, backend: deps.Store, logger: logger, interval: config.RefreshInterval,
		selectionInterval: config.ReconcileInterval, instanceID: uuid.New().String()}
	if own, err := url.Parse(config.OwnURL); err == nil && own.Host != "" {
		own.Path = "/discovery"
		own.RawPath = ""
		if endpoint, err := canonicalEndpoint(own.String()); err == nil {
			f.ownHost = endpoint.Host
		}
	}
	f.collector = &shared.Collector[runner]{Client: &http.Client{Transport: t, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		MaxFailures: max(1, config.MaxFailedRefreshes), Logger: logger.With("component", "fleet_discovery"),
		Observe: func(_ int, duration time.Duration, err error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.refreshes++
			f.refreshDuration += duration
			if err != nil {
				f.failures++
			}
		}}
	return f, nil
}

// Run owns the polling worker. Run once, then Close/join before discarding it.
func (f *Manager) Run(ctx context.Context) { f.collector.Run(ctx, f.interval) }
func (f *Manager) Close()                  { f.collector.Close() }

// A raw runner preserves extension fields and the original numeric/timestamp
// tokens. Node's shared codec alone validates and merges inventory records.
type runner struct {
	URL        string `json:"url"`
	App        string `json:"app"`
	ObservedAt string `json:"observed_at"`
	Version    string `json:"version,omitempty"`
	data       json.RawMessage
}

func (r *runner) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("discovery runner must be an object")
	}
	var value runner
	fields := map[string]*string{"url": &value.URL, "app": &value.App, "observed_at": &value.ObservedAt, "version": &value.Version}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("invalid discovery runner property")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		for canonical, target := range fields {
			if !strings.EqualFold(key, canonical) {
				continue
			}
			if key != canonical || seen[canonical] {
				return errors.New("ambiguous discovery runner identity")
			}
			if err := json.Unmarshal(raw, target); err != nil {
				return err
			}
			seen[canonical] = true
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	value.data = append(json.RawMessage(nil), data...)
	*r = value
	return nil
}
func (r runner) MarshalJSON() ([]byte, error) { return r.data, nil }
func (r runner) DiscoveryIdentity() (string, string, string) {
	return r.URL, r.App, r.ObservedAt
}

type publishedRunner struct {
	runner
	nodeID    string
	queriedAt time.Time
}

// Keep membership and public responses on the same filtering and winner rules.
// Each winning record retains the source snapshot that supplied it.
func (f *Manager) publicInventory(snapshots []shared.Snapshot[runner]) []shared.Entry[publishedRunner] {
	selected := make(map[string]Source, len(f.selected))
	for _, source := range f.selected {
		selected[source.URL] = source
	}
	entries := []shared.Entry[publishedRunner]{}
	for _, snapshot := range snapshots {
		source, ok := selected[snapshot.URL]
		if !ok {
			continue
		}
		for _, entry := range snapshot.Entries {
			if !publicAddress(source, entry.Address) {
				continue
			}
			published := shared.Entry[publishedRunner]{Address: entry.Address, Runners: []publishedRunner{}}
			for _, candidate := range entry.Runners {
				if publicRunnerURL(source, candidate.URL) {
					published.Runners = append(published.Runners, publishedRunner{candidate, source.NodeID, snapshot.QueriedAt})
				}
			}
			entries = append(entries, published)
		}
	}
	return shared.Merge(entries)
}

func (f *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	entries := f.publicInventory(f.collector.Snapshots())
	f.mu.Unlock()
	result := []shared.Entry[publishedRunner]{}
	for _, entry := range entries {
		if len(entry.Runners) > 0 {
			result = append(result, entry)
		}
	}
	body, err := json.Marshal(result)
	if err != nil {
		http.Error(w, "cannot encode discovery inventory", http.StatusInternalServerError)
		return
	}
	body = append(body, '\n')
	if len(body) > shared.MaxBody {
		f.logger.WarnContext(r.Context(), "fleet discovery response exceeds client size limit", "response_bytes", len(body), "max_bytes", shared.MaxBody)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
