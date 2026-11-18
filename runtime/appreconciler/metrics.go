package appreconciler

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	runner "github.com/livepeer/golang-runner"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const metricNamespace = "livepeer_app_reconciler"

type Metrics struct {
	registry          *prometheus.Registry
	heartbeatRequest  *prometheus.HistogramVec
	heartbeatCallback prometheus.Histogram
	heartbeatGap      prometheus.Histogram
	lastHeartbeat     prometheus.Gauge
	journalCommit     prometheus.Histogram
	lastHeartbeatNS   atomic.Int64
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

func (m *Metrics) observeHeartbeat(event runner.HeartbeatEvent, callbackStarted time.Time) {
	if event.At.IsZero() {
		return
	}
	if event.Err != nil {
		m.heartbeatRequest.WithLabelValues("error").Observe(callbackStarted.Sub(event.At).Seconds())
		return
	}
	m.heartbeatRequest.WithLabelValues("success").Observe(callbackStarted.Sub(event.At).Seconds())
	sent := event.At.UnixNano()
	if previous := m.lastHeartbeatNS.Swap(sent); previous != 0 && previous <= sent {
		m.heartbeatGap.Observe(time.Duration(sent - previous).Seconds())
	}
	m.lastHeartbeat.Set(float64(sent) / float64(time.Second))
}

type diagnosticMetrics struct {
	sockets, memory *prometheus.Desc
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
	const memoryDirectory = "/sys/fs/cgroup/"
	if raw, err := os.ReadFile(memoryDirectory + "memory.current"); err == nil {
		d.emitMemory(ch, "total", strings.TrimSpace(string(raw)))
	}
	if raw, err := os.ReadFile(memoryDirectory + "memory.stat"); err == nil {
		for line := range strings.Lines(string(raw)) {
			category, value, ok := strings.Cut(strings.TrimSpace(line), " ")
			if ok && (category == "anon" || category == "file" || category == "kernel" || category == "sock" || category == "slab_reclaimable") {
				d.emitMemory(ch, category, value)
			}
		}
	}
}

func (d diagnosticMetrics) emitMemory(ch chan<- prometheus.Metric, category, value string) {
	if bytes, err := strconv.ParseUint(value, 10, 64); err == nil {
		ch <- prometheus.MustNewConstMetric(d.memory, prometheus.GaugeValue, float64(bytes), category)
	}
}
