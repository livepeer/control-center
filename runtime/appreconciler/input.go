package appreconciler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/livepeer/control-center/runtime/appbundle"
	"github.com/livepeer/control-center/runtime/artifact"
	"github.com/livepeer/control-center/runtime/contract"
	"github.com/livepeer/control-center/runtime/transport"
)

type Input struct {
	Metadata contract.Metadata
	Payload  appbundle.Payload
	Digest   string
}
type Inputs interface {
	Read(context.Context) (Input, error)
}
type Source struct {
	Kube                              *transport.Kube
	Client                            *http.Client
	ArtifactURL, IdentityFile, NodeID string
}

func (s Source) Read(ctx context.Context) (Input, error) {
	var input Input
	var external transport.External
	if err := s.Kube.Request(ctx, http.MethodGet, transport.ExternalPath("livepeer-service"), nil, &external); err != nil {
		return input, err
	}
	a := external.Status.Artifact
	if a == nil || !artifact.HashPattern.MatchString(a.Digest) {
		return input, errors.New("management_artifact_missing")
	}
	expected := strings.TrimRight(s.ArtifactURL, "/") + "/artifacts/" + strings.TrimPrefix(a.Digest, "sha256:") + ".tar.gz"
	if a.URL != expected {
		return input, errors.New("management_artifact_origin")
	}
	u, err := url.Parse(expected)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return input, errors.New("management_artifact_url")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, expected, nil)
	resp, err := s.Client.Do(req)
	if err != nil {
		return input, errors.New("management_artifact_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return input, errors.New("management_artifact_unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, artifact.MaxArchive+1))
	if err != nil || len(data) > artifact.MaxArchive || artifact.Digest(data) != a.Digest {
		return input, errors.New("management_artifact_digest")
	}
	files, err := artifact.Read(data)
	if err != nil {
		return input, err
	}
	m, err := transport.ReadMetadata(files["runtime.json"])
	if err != nil || m.NodeID != s.NodeID || m.BundleFormat < contract.BundleFormat || m.BundleFormat > contract.SystemBundleFormat {
		return input, errors.New("management_enrollment")
	}
	identity, err := transport.ReadIdentity(s.IdentityFile)
	if err != nil || identity.Epoch != m.Epoch || identity.CredentialVersion != m.CredentialVersion {
		return input, errors.New("management_enrollment")
	}
	p, err := appbundle.Read(files, m)
	if err != nil {
		// Whole-archive/enrollment checks already succeeded. An invalid app payload
		// cannot suppress a safe machine withdrawal or erase the accepted app intent.
		m.AppsError = "invalid_app_payload"
		return Input{Metadata: m, Payload: appbundle.Unavailable(), Digest: a.Digest}, nil
	}
	return Input{Metadata: m, Payload: p, Digest: a.Digest}, nil
}
