package appreconciler

import (
	"testing"

	"github.com/prometheus/procfs"
)

func TestResolveMemoryCgroup(t *testing.T) {
	mounts := []*procfs.MountInfo{
		{FSType: "cgroup2", Root: "/", MountPoint: "/sys/fs/cgroup"},
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
