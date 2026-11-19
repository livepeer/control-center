package appreconciler

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	runner "github.com/livepeer/golang-runner"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/procfs"
)

const metricNamespace = "livepeer_app_reconciler"

type Metrics struct {
	registry          *prometheus.Registry
	heartbeatRequest  *prometheus.HistogramVec
	heartbeatCallback prometheus.Histogram
	heartbeatGap      prometheus.Histogram
	lastHeartbeat     prometheus.Gauge
	journalCommit     prometheus.Histogram
	heartbeatMu       sync.Mutex
	lastHeartbeatSent time.Time
}

func NewMetrics() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		heartbeatRequest: prometheus.NewHistogramVec(
			timing("heartbeat_request", "Time from SDK heartbeat attempt to callback entry."),
			[]string{"result"},
		),
		heartbeatCallback: prometheus.NewHistogram(timing("heartbeat_callback", "Time spent processing a heartbeat response in the reconciler.")),
		heartbeatGap:      prometheus.NewHistogram(timing("heartbeat_gap", "Time between sends of acknowledged heartbeats.")),
		lastHeartbeat: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricNamespace, Name: "last_heartbeat_timestamp_seconds", Help: "Send timestamp of the latest acknowledged heartbeat.",
		}),
		journalCommit: prometheus.NewHistogram(timing("journal_commit", "Time spent writing and syncing a changed app journal.")),
	}
	m.registry.MustRegister(
		m.heartbeatRequest, m.heartbeatCallback, m.heartbeatGap, m.lastHeartbeat, m.journalCommit,
		collectors.NewGoCollector(collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile(`^/(gc/heap/(live|allocs):bytes|gc/gomemlimit:bytes|cpu/classes/gc/total:cpu-seconds)$`)},
		)),
		diagnosticMetrics{
			sockets: prometheus.NewDesc(metricNamespace+"_open_sockets", "Socket descriptors open in the reconciler.", nil, nil),
			memory:  prometheus.NewDesc(metricNamespace+"_cgroup_memory_bytes", "Memory charged to the reconciler cgroup by category.", []string{"category"}, nil),
			cgroup:  ownMemoryCgroup(),
		},
	)
	return m
}

func timing(name, help string) prometheus.HistogramOpts {
	return prometheus.HistogramOpts{
		Namespace: metricNamespace,
		Name:      name + "_duration_seconds",
		Help:      help,
		Buckets:   []float64{0.001, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 8, 10, 15, 20, 25, 30, 60},
	}
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{MaxRequestsInFlight: 1})
}

func (m *Metrics) observeHeartbeatRequest(event runner.HeartbeatEvent, callbackStarted time.Time) {
	if event.At.IsZero() {
		return
	}
	if event.Err != nil {
		m.heartbeatRequest.WithLabelValues("error").Observe(callbackStarted.Sub(event.At).Seconds())
		return
	}
	m.heartbeatRequest.WithLabelValues("success").Observe(callbackStarted.Sub(event.At).Seconds())
}

func (m *Metrics) observeAcceptedHeartbeat(sent time.Time) {
	if sent.IsZero() {
		return
	}
	m.heartbeatMu.Lock()
	defer m.heartbeatMu.Unlock()
	if previous := m.lastHeartbeatSent; !previous.IsZero() {
		m.heartbeatGap.Observe(sent.Sub(previous).Seconds())
	}
	m.lastHeartbeatSent = sent
	m.lastHeartbeat.Set(float64(sent.UnixNano()) / float64(time.Second))
}

type diagnosticMetrics struct {
	sockets, memory *prometheus.Desc
	cgroup          memoryCgroup
}

func (d diagnosticMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- d.sockets
	ch <- d.memory
}

func (d diagnosticMetrics) Collect(ch chan<- prometheus.Metric) {
	const fdDirectory = "/proc/self/fd"
	if entries, err := os.ReadDir(fdDirectory); err == nil {
		count := 0
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join(fdDirectory, entry.Name()))
			if err == nil && strings.HasPrefix(target, "socket:[") {
				count++
			}
		}
		ch <- prometheus.MustNewConstMetric(d.sockets, prometheus.GaugeValue, float64(count))
	}
	dir := d.cgroup.directory
	if dir == "" {
		return
	}
	total := "memory.current"
	categories := []string{"anon", "file", "kernel", "sock", "slab_reclaimable"}
	if d.cgroup.legacy {
		total = "memory.usage_in_bytes"
		categories = []string{"total_rss", "total_cache"}
		d.emitMemoryFile(ch, "kernel", "memory.kmem.usage_in_bytes")
		d.emitMemoryFile(ch, "sock", "memory.kmem.tcp.usage_in_bytes")
	}
	d.emitMemoryFile(ch, "total", total)
	raw, err := os.ReadFile(filepath.Join(dir, "memory.stat"))
	if err != nil {
		return
	}
	for line := range strings.Lines(string(raw)) {
		category, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok && slices.Contains(categories, category) {
			d.emitMemory(ch, strings.TrimPrefix(category, "total_"), value)
		}
	}
}

func (d diagnosticMetrics) emitMemoryFile(ch chan<- prometheus.Metric, category, file string) {
	if raw, err := os.ReadFile(filepath.Join(d.cgroup.directory, file)); err == nil {
		d.emitMemory(ch, category, strings.TrimSpace(string(raw)))
	}
}

func (d diagnosticMetrics) emitMemory(ch chan<- prometheus.Metric, category, value string) {
	if bytes, err := strconv.ParseUint(value, 10, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(d.memory, prometheus.GaugeValue, float64(bytes), category)
	}
}

type memoryCgroup struct {
	directory string
	legacy    bool
}

func ownMemoryCgroup() memoryCgroup {
	process, err := procfs.Self()
	if err != nil {
		return memoryCgroup{}
	}
	groups, err := process.Cgroups()
	if err != nil {
		return memoryCgroup{}
	}
	mounts, err := process.MountInfo()
	if err != nil {
		return memoryCgroup{}
	}
	return resolveMemoryCgroup(groups, mounts)
}

func resolveMemoryCgroup(groups []procfs.Cgroup, mounts []*procfs.MountInfo) memoryCgroup {
	var groupPath string
	var legacy bool
	for _, group := range groups {
		if slices.Contains(group.Controllers, "memory") {
			groupPath, legacy = group.Path, true
			break
		}
		if group.HierarchyID == 0 {
			groupPath = group.Path
		}
	}
	// Namespace-relative ancestors can appear as /.. in procfs. Cleaning
	// them before comparing would turn them into the namespace root.
	if !filepath.IsAbs(groupPath) || filepath.Clean(groupPath) != groupPath {
		return memoryCgroup{legacy: legacy}
	}
	var directory string
	longestRoot := 0
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, mount := range mounts {
		_, hasMemory := mount.SuperOptions["memory"]
		if (legacy && (mount.FSType != "cgroup" || !hasMemory)) || (!legacy && mount.FSType != "cgroup2") {
			continue
		}
		root := unescape.Replace(mount.Root)
		if len(root) <= longestRoot || !filepath.IsAbs(root) || filepath.Clean(root) != root {
			continue
		}
		relative, err := filepath.Rel(root, groupPath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
			continue
		}
		longestRoot = len(root)
		directory = filepath.Join(unescape.Replace(mount.MountPoint), relative)
	}
	return memoryCgroup{directory: directory, legacy: legacy}
}
