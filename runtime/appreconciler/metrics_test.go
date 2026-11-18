package appreconciler

import (
	"testing"
	"time"

	runner "github.com/livepeer/golang-runner"

	"github.com/prometheus/procfs"
)

func TestResolveMemoryCgroup(t *testing.T) {
	mounts := []*procfs.MountInfo{
		{FSType: "cgroup2", Root: "/", MountPoint: "/sys/fs/cgroup"},
		{FSType: "cgroup2", Root: "/..", MountPoint: "/ancestor"},
		{FSType: "cgroup2", Root: "/kubepods.slice", MountPoint: "/pod-groups"},
		{FSType: "cgroup2", Root: "/kubepods.slice-other", MountPoint: "/wrong"},
		{FSType: "cgroup", Root: "/", MountPoint: "/sys/fs/cgroup/cpu", SuperOptions: map[string]string{"cpu": ""}},
		{FSType: "cgroup", Root: "/containers", MountPoint: "/sys/fs/cgroup/memory", SuperOptions: map[string]string{"memory": ""}},
	}
	for _, tt := range []struct {
		name   string
		groups []procfs.Cgroup
		want   memoryCgroup
	}{
		{"nested v2 mount", []procfs.Cgroup{{Path: "/kubepods.slice/pod/app"}}, memoryCgroup{directory: "/pod-groups/pod/app"}},
		{"namespaced v2 root", []procfs.Cgroup{{Path: "/"}}, memoryCgroup{directory: "/sys/fs/cgroup"}},
		{"namespaced ancestor", []procfs.Cgroup{{Path: "/../app"}}, memoryCgroup{}},
		{"hybrid v1 memory", []procfs.Cgroup{{Path: "/unified"}, {HierarchyID: 3, Controllers: []string{"memory"}, Path: "/containers/pod/app"}}, memoryCgroup{directory: "/sys/fs/cgroup/memory/pod/app", legacy: true}},
		{"no visible memory cgroup", []procfs.Cgroup{{HierarchyID: 3, Controllers: []string{"memory"}, Path: "/elsewhere/pod/app"}}, memoryCgroup{legacy: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveMemoryCgroup(tt.groups, mounts); got != tt.want {
				t.Fatalf("memory cgroup = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestHeartbeatMetricsTrackAcceptedResponses(t *testing.T) {
	metrics := NewMetrics()
	owner := &SDKOwner{
		bootstrap: "bootstrap",
		hooks:     OwnerHooks{Observe: func(Observation) error { return nil }},
		Metrics:   metrics,
	}
	accepted := time.Now()
	event := runner.HeartbeatEvent{
		At: accepted, TTL: 30 * time.Second, Credential: "issued", AcceptedSeq: new(uint64),
		Response: &runner.HeartbeatResponse{RunnerID: "owner"},
	}
	owner.heartbeat(event)
	if metrics.lastHeartbeatSent != accepted {
		t.Fatal("sequenced heartbeat did not advance freshness")
	}
	event.At = event.At.Add(time.Second)
	event.TTL = 0
	owner.heartbeat(event)
	event.TTL = 30 * time.Second
	event.AcceptedSeq = nil
	event.Credential = "bootstrap"
	owner.heartbeat(event)
	event.Credential = "issued"
	event.AcceptedSeq = new(uint64)
	owner.hooks.Observe = func(Observation) error { return ErrSuperseded }
	owner.heartbeat(event)
	if metrics.lastHeartbeatSent != accepted {
		t.Fatal("rejected or unsequenced heartbeat advanced freshness")
	}
}
