package transport

import "context"

type KubernetesReader interface {
	Request(context.Context, string, string, any, any) error
}

type NodePod struct {
	UID, ConfigDigest string
	Ready, Absent     bool
}

// ObserveNode identifies a unique live Pod. Deleting Pods still prevent absence.
func ObserveNode(ctx context.Context, k KubernetesReader) (NodePod, error) {
	var pods struct {
		Items []struct {
			Metadata struct {
				UID               string            `json:"uid"`
				DeletionTimestamp *string           `json:"deletionTimestamp"`
				Annotations       map[string]string `json:"annotations"`
			} `json:"metadata"`
			Status struct {
				Conditions []Condition `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := k.Request(ctx, "GET", "/api/v1/namespaces/livepeer/pods?labelSelector=app%3Dorchestrator", nil, &pods); err != nil {
		return NodePod{}, err
	}
	o := NodePod{Absent: len(pods.Items) == 0}
	live := 0
	for _, p := range pods.Items {
		if p.Metadata.DeletionTimestamp != nil {
			continue
		}
		live++
		o.UID, o.ConfigDigest = p.Metadata.UID, p.Metadata.Annotations["livepeer.io/config-sha256"]
		for _, c := range p.Status.Conditions {
			o.Ready = o.Ready || c.Type == "Ready" && c.Status == "True"
		}
	}
	if live != 1 {
		o.UID, o.ConfigDigest, o.Ready = "", "", false
	}
	return o, nil
}
