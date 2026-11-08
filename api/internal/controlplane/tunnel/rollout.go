package tunnel

import (
	"context"
	"github.com/livepeer/control-center/api/internal/controlplane/machineconfig"
)

func (l *tunnelLease) desired(state Snapshot) machineconfig.Desired {
	exposure := &machineconfig.Exposure{TunnelID: state.TunnelID, ServiceURL: state.ServiceURL, ProxyURLTemplate: state.ProxyURLTemplate, DiscoveryURL: state.DiscoveryURL, IngressDigest: state.IngressDigest, CredentialGeneration: state.CredentialGeneration, ProviderVersion: state.ProviderVersion}
	return l.s.rollout.Desired(l.Machine, state.State, exposure)
}
func (l *tunnelLease) desiredDigest() string { return machineconfig.Digest(l.desired(l.state)) }

func (l *tunnelLease) gateNodeConfiguration(ctx context.Context) (bool, error) {
	before := l.state.State
	waiting, err := l.s.rollout.Gate(ctx, l.Machine, &l.state.State, l.desired(l.state))
	if l.state.State != before {
		l.state.Ready = false
		if l.state.RolloutReason != "" {
			l.state.Reason = l.state.RolloutReason
		}
		if e := l.save(ctx); e != nil {
			return waiting, e
		}
	}
	return waiting, err
}

func (l *tunnelLease) stageEndpoints(ctx context.Context, desired Snapshot) (bool, error) {
	if l.state.Target != "" && l.state.Target != desired.ServiceURL {
		l.state.State.CancelTarget()
		l.state.Ready = false
		if err := l.save(ctx); err != nil {
			return false, err
		}
	}
	if desired.ServiceURL == l.state.ServiceURL {
		return false, nil
	}
	candidate := l.state
	candidate.ServiceURL = desired.ServiceURL
	candidate.ProxyURLTemplate = desired.ProxyURLTemplate
	waiting, err := l.s.rollout.StageTarget(ctx, l.Machine, &l.state.State, l.desired(candidate), desired.ServiceURL)
	l.state.Ready = false
	if l.state.RolloutReason != "" {
		l.state.Reason = l.state.RolloutReason
	}
	if e := l.save(ctx); e != nil {
		return false, e
	}
	if err != nil || waiting {
		return waiting, err
	}
	l.state.ServiceURL = desired.ServiceURL
	l.state.ProxyURLTemplate = desired.ProxyURLTemplate
	l.state.DiscoveryURL = desired.DiscoveryURL
	l.state.SourceGeneration++
	l.state.EndpointGeneration++
	return false, l.save(ctx)
}
