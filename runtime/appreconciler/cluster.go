package appreconciler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/transport"
)

type Pod struct {
	UID, ResourceVersion, Phase string
	Reason                      string
	Deleting                    bool
	Finalizers                  []string
	StopSignal                  string
}
type View struct {
	Pods      map[string]Pod
	Services  map[string]bool
	Endpoints map[string]map[string]bool
	Artifact  string
	Applied   string
	Failed    string
	Inventory map[string]bool
	Budget    Resources
}
type Cluster interface {
	Read(context.Context) (View, error)
	Publish(context.Context, *transport.Artifact) error
	Release(context.Context, string, Pod) error
}
type Kubernetes struct {
	Client *transport.Kube
	NodeID string
}

const appsKustomization = "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-system/kustomizations/livepeer-apps"

func (k Kubernetes) Read(ctx context.Context) (View, error) {
	v := View{Pods: map[string]Pod{}, Services: map[string]bool{}, Endpoints: map[string]map[string]bool{}, Inventory: map[string]bool{}}
	var nodes struct {
		Items []struct {
			Status struct {
				Allocatable map[string]string `json:"allocatable"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := k.Client.Request(ctx, http.MethodGet, "/api/v1/nodes?labelSelector="+url.QueryEscape("livepeer.io/node-id="+k.NodeID), nil, &nodes); err != nil {
		return v, err
	}
	if len(nodes.Items) != 1 {
		return v, errors.New("node_allocation_unknown")
	}
	q := nodes.Items[0].Status.Allocatable
	var err error
	if v.Budget.CPU, err = quantity(q["cpu"], true); err != nil {
		return v, err
	}
	if v.Budget.Memory, err = quantity(q["memory"], false); err != nil {
		return v, err
	}
	if v.Budget.Storage, err = quantity(q["ephemeral-storage"], false); err != nil {
		return v, err
	}
	// Reserve one core and 1 GiB each of memory/storage for management and host services.
	v.Budget.CPU -= 1000
	v.Budget.Memory -= 1 << 30
	v.Budget.Storage -= 1 << 30
	var pods struct {
		Items []struct {
			Metadata struct {
				Name              string     `json:"name"`
				UID               string     `json:"uid"`
				ResourceVersion   string     `json:"resourceVersion"`
				DeletionTimestamp *time.Time `json:"deletionTimestamp"`
				Finalizers        []string   `json:"finalizers"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Lifecycle struct {
						StopSignal string `json:"stopSignal"`
					} `json:"lifecycle"`
				} `json:"containers"`
			} `json:"spec"`
			Status struct {
				Phase      string `json:"phase"`
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
					Reason string `json:"reason"`
				} `json:"conditions"`
				ContainerStatuses []struct {
					State struct {
						Waiting *struct {
							Reason string `json:"reason"`
						} `json:"waiting"`
						Terminated *struct {
							Reason string `json:"reason"`
						} `json:"terminated"`
					} `json:"state"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := k.Client.Request(ctx, http.MethodGet, "/api/v1/namespaces/livepeer-apps/pods", nil, &pods); err != nil {
		return v, err
	}
	for _, p := range pods.Items {
		value := Pod{UID: p.Metadata.UID, ResourceVersion: p.Metadata.ResourceVersion, Phase: p.Status.Phase, Deleting: p.Metadata.DeletionTimestamp != nil, Finalizers: p.Metadata.Finalizers}
		if len(p.Spec.Containers) == 1 {
			value.StopSignal = p.Spec.Containers[0].Lifecycle.StopSignal
		}
		for _, condition := range p.Status.Conditions {
			if condition.Status == "False" {
				if condition.Type == "PodReadyToStartContainers" && value.Reason == "" {
					value.Reason = "sandbox_pending"
				}
				if reason := workloadReason(condition.Reason); reason != "" {
					value.Reason = reason
				}
			}
		}
		for _, container := range p.Status.ContainerStatuses {
			if container.State.Waiting != nil {
				if reason := workloadReason(container.State.Waiting.Reason); reason != "" {
					value.Reason = reason
				}
			}
			if container.State.Terminated != nil {
				if reason := workloadReason(container.State.Terminated.Reason); reason != "" {
					value.Reason = reason
				}
			}
		}
		v.Pods[p.Metadata.Name] = value
	}
	var services struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := k.Client.Request(ctx, http.MethodGet, "/api/v1/namespaces/livepeer-apps/services", nil, &services); err != nil {
		return v, err
	}
	for _, service := range services.Items {
		v.Services[service.Metadata.Name] = true
	}
	var slices struct {
		Items []struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Endpoints []struct {
				TargetRef struct {
					UID string `json:"uid"`
				} `json:"targetRef"`
			} `json:"endpoints"`
		} `json:"items"`
	}
	if err := k.Client.Request(ctx, http.MethodGet, "/apis/discovery.k8s.io/v1/namespaces/livepeer-apps/endpointslices", nil, &slices); err != nil {
		return v, err
	}
	for _, slice := range slices.Items {
		name := slice.Metadata.Labels["kubernetes.io/service-name"]
		if v.Endpoints[name] == nil {
			v.Endpoints[name] = map[string]bool{}
		}
		for _, ep := range slice.Endpoints {
			if ep.TargetRef.UID != "" {
				v.Endpoints[name][ep.TargetRef.UID] = true
			}
		}
	}
	var external transport.External
	if err := k.Client.Request(ctx, http.MethodGet, transport.ExternalPath("livepeer-apps"), nil, &external); err != nil {
		return v, err
	}
	if external.Status.Artifact != nil {
		v.Artifact = external.Status.Artifact.Digest
	}
	var kust struct {
		Metadata struct {
			Generation int64 `json:"generation"`
		} `json:"metadata"`
		Status struct {
			ObservedGeneration    int64                 `json:"observedGeneration"`
			LastAppliedRevision   string                `json:"lastAppliedRevision"`
			LastAttemptedRevision string                `json:"lastAttemptedRevision"`
			Conditions            []transport.Condition `json:"conditions"`
			Inventory             struct {
				Entries []struct {
					ID string `json:"id"`
				} `json:"entries"`
			} `json:"inventory"`
		} `json:"status"`
	}
	if err := k.Client.Request(ctx, http.MethodGet, appsKustomization, nil, &kust); err != nil {
		return v, err
	}
	for _, c := range kust.Status.Conditions {
		if c.Type == "Ready" && c.Status == "True" && c.ObservedGeneration == kust.Metadata.Generation && kust.Status.ObservedGeneration == kust.Metadata.Generation {
			v.Applied = strings.TrimPrefix(kust.Status.LastAppliedRevision, "apps@")
		}
		if c.Type == "Ready" && c.Status == "False" && c.ObservedGeneration == kust.Metadata.Generation && kust.Status.ObservedGeneration == kust.Metadata.Generation {
			v.Failed = strings.TrimPrefix(kust.Status.LastAttemptedRevision, "apps@")
		}
	}
	for _, e := range kust.Status.Inventory.Entries {
		v.Inventory[e.ID] = true
	}
	return v, nil
}
func inventoryID(name, kind string) string {
	return fmt.Sprintf("%s_%s__%s", appbundle.Namespace, name, kind)
}
func (k Kubernetes) Publish(ctx context.Context, value *transport.Artifact) error {
	return k.Client.Publish(ctx, "livepeer-apps", value, true, "ArtifactStored")
}
func (k Kubernetes) Release(ctx context.Context, name string, pod Pod) error {
	if !pod.Deleting || pod.UID == "" || pod.ResourceVersion == "" {
		return errors.New("finalizer_precondition")
	}
	index := -1
	for i, f := range pod.Finalizers {
		if f == appbundle.Finalizer {
			index = i
		}
	}
	if index < 0 {
		return nil
	}
	patch := []map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": pod.UID},
		{"op": "test", "path": "/metadata/resourceVersion", "value": pod.ResourceVersion},
		{"op": "test", "path": fmt.Sprintf("/metadata/finalizers/%d", index), "value": appbundle.Finalizer},
		{"op": "remove", "path": fmt.Sprintf("/metadata/finalizers/%d", index)},
	}
	err := k.Client.PatchType(ctx, http.MethodPatch, "/api/v1/namespaces/livepeer-apps/pods/"+url.PathEscape(name), patch, nil, "application/json-patch+json")
	if transport.IsStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

func workloadReason(reason string) string {
	switch reason {
	case "ImagePullBackOff", "ErrImagePull", "InvalidImageName":
		return "image_pull_failed"
	case "CreateContainerConfigError", "CreateContainerError", "RunContainerError":
		return "container_start_failed"
	case "CrashLoopBackOff", "Error":
		return "process_failed"
	case "OOMKilled":
		return "memory_limit"
	case "Unschedulable":
		return "scheduling_refused"
	}
	return ""
}
