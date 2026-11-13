package transport

import "context"

type KubernetesReader interface {
	Request(context.Context, string, string, any, any) error
}

type NodePod struct {
	UID, ConfigDigest string
	Ready, Absent     bool

	IP, NodeName, ContainerID string
}

type Pod struct {
	Metadata struct {
		UID               string            `json:"uid"`
		DeletionTimestamp *string           `json:"deletionTimestamp"`
		Annotations       map[string]string `json:"annotations"`
		Labels            map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		PodIP             string      `json:"podIP"`
		Conditions        []Condition `json:"conditions"`
		ContainerStatuses []struct {
			Name        string `json:"name"`
			ImageID     string `json:"imageID"`
			ContainerID string `json:"containerID"`
			State       struct {
				Running *struct{} `json:"running"`
			} `json:"state"`
		} `json:"containerStatuses"`
	} `json:"status"`
}

type PodList struct {
	Items []Pod `json:"items"`
}

// ObserveNode identifies a unique live Pod. Deleting Pods still prevent absence.
func ObserveNode(ctx context.Context, k KubernetesReader) (NodePod, error) {
	var pods PodList
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
		o.IP, o.NodeName = p.Status.PodIP, p.Spec.NodeName
		for _, c := range p.Status.ContainerStatuses {
			if c.Name == "orchestrator" && c.State.Running != nil {
				o.ContainerID = c.ContainerID
			}
		}
		for _, c := range p.Status.Conditions {
			o.Ready = o.Ready || c.Type == "Ready" && c.Status == "True"
		}
	}
	if live != 1 {
		return NodePod{Absent: o.Absent}, nil
	}
	return o, nil
}
