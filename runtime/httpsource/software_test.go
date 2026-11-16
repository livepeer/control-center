package httpsource

import "testing"

func TestTraefikChartLabelsIdentifyRunningController(t *testing.T) {
	labels := map[string]string{"app.kubernetes.io/name": "traefik", "app.kubernetes.io/instance": "traefik-kube-system"}
	if got := systemWorkload("kube-system", labels); got != "traefik" {
		t.Fatalf("chart pod identified as %q", got)
	}
	if got := systemWorkload("livepeer", labels); got != "" {
		t.Fatalf("unexpected namespace identified as %q", got)
	}
}
