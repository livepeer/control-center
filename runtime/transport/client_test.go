package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlOriginsCredentialsAndRedirects(t *testing.T) {
	node := "lp-" + strings.Repeat("a", 16)
	file := filepath.Join(t.TempDir(), "token")
	os.WriteFile(file, []byte(strings.Repeat("b", 64)), 0600)
	for _, origin := range []string{"http://example/v1/nodes/" + node + "/config", "https://user:password@example/v1/nodes/" + node + "/config", "https://example/v1/nodes/" + node + "/config?token=secret", "https://example/v1/nodes/" + node + "/%63onfig"} {
		if _, err := NewControl(origin, file, false); err == nil {
			t.Fatal("accepted origin", origin)
		}
	}
	calls := 0
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
	defer receiver.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("b", 64) {
			t.Error("credential mapping")
		}
		http.Redirect(w, r, receiver.URL, 302)
	}))
	defer server.Close()
	c, err := NewControl(server.URL+"/v1/nodes/"+node+"/config", file, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = c.Request(context.Background(), "config", nil, 1024); !IsStatus(err, 302) || calls != 0 {
		t.Fatal("redirect leaked request", err, calls)
	}
	c.ConfigURL = receiver.URL
	if _, _, err = c.Request(context.Background(), "config", nil, 1024); err == nil || calls != 0 {
		t.Fatal("origin mutated")
	}
	c.ConfigURL = c.approvedURL
	os.WriteFile(file, []byte(strings.Repeat("b", 64)+"\n"), 0600)
	if _, _, err = c.Request(context.Background(), "config", nil, 1024); err == nil {
		t.Fatal("accepted malformed credential")
	}
}

func TestPublicationSkipsUnchangedStatusAndRepairsReadiness(t *testing.T) {
	var current External
	current.Metadata.Generation = 1
	patches := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			var update External
			if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
				t.Error(err)
			}
			if update.Status.Artifact != nil {
				current.Status.Artifact = update.Status.Artifact
			}
			current.Status.Conditions = update.Status.Conditions
			patches++
		}
		json.NewEncoder(w).Encode(current)
	}))
	defer server.Close()
	k := Kube{Base: server.URL, Client: HTTPClient()}
	a := &Artifact{Digest: "sha256:" + strings.Repeat("a", 64), Revision: "one", URL: server.URL + "/archive", Size: 10, LastUpdateTime: "2026-11-08T00:00:00Z"}
	publish := func(artifact *Artifact, ready bool, reason string) {
		t.Helper()
		if err := k.Publish(t.Context(), "livepeer-apps", artifact, ready, reason); err != nil {
			t.Fatal(err)
		}
	}
	publish(a, true, "ArtifactStored")
	publish(a, true, "ArtifactStored")
	if patches != 1 {
		t.Fatal("unchanged artifact caused status writes", patches)
	}
	current.Status.Conditions[0].Status = "False"
	publish(a, true, "ArtifactStored")
	if patches != 2 {
		t.Fatal("did not restore artifact readiness")
	}
	current.Status.Artifact = nil
	publish(a, true, "ArtifactStored")
	if patches != 3 || current.Status.Artifact == nil {
		t.Fatal("did not repair missing publication")
	}
	publish(nil, false, "FetchFailed")
	publish(nil, false, "FetchFailed")
	if patches != 4 || current.Status.Artifact.Digest != a.Digest {
		t.Fatal("failure rewrote status or discarded last valid artifact")
	}
}
func TestDecodeAndIdentityCompatibility(t *testing.T) {
	var value map[string]any
	if Decode([]byte(`{"id":1,"id":2}`), &value) == nil {
		t.Fatal("accepted duplicate JSON key")
	}
	file := filepath.Join(t.TempDir(), "identity")
	for _, b := range []string{`{"epoch":"epoch","credential_version":"2"}`, `{"epoch":"epoch","credential_version":2}`} {
		os.WriteFile(file, []byte(b), 0600)
		i, err := ReadIdentity(file)
		if err != nil || i.CredentialVersion != 2 {
			t.Fatal(i, err)
		}
	}
}
