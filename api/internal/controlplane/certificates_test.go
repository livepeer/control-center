package controlplane

import (
	"context"
	"github.com/livepeer/control-center/api/internal/controlplane/tunnel"
	"strings"
	"testing"
	"time"
	"uuid"
)

func (f *simulatedCloudflare) Zone(context.Context) (tunnel.ZoneDetails, error) {
	z := tunnel.ZoneDetails{ID: strings.Repeat("b", 32), Name: "example.invalid", Type: "full", Status: "active"}
	z.Account.ID = strings.Repeat("a", 32)
	return z, nil
}
func (f *simulatedCloudflare) ListCertificatePacks(context.Context) ([]tunnel.CertificatePack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var all []tunnel.CertificatePack
	for _, pack := range f.certificatePacks {
		all = append(all, pack)
	}
	return all, nil
}
func (f *simulatedCloudflare) CertificatePack(_ context.Context, id string) (tunnel.CertificatePack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.certificatePacks[id], nil
}
func (f *simulatedCloudflare) OrderCertificate(_ context.Context, hosts []string) (tunnel.CertificatePack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pack := tunnel.CertificatePack{ID: uuid.New().String(), Type: "advanced", Hosts: hosts, Status: "active", Certificates: []tunnel.Certificate{{Hosts: hosts, Status: "active", ExpiresOn: time.Now().Add(24 * time.Hour)}}}
	if f.certificateStatus != "" {
		pack.Status = f.certificateStatus
	}
	f.certificatePacks[pack.ID] = pack
	return pack, nil
}
func (f *simulatedCloudflare) RestartCertificateValidation(context.Context, string) error { return nil }
func (f *simulatedCloudflare) DeleteCertificate(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.certificatePacks, id)
	return nil
}

func TestReenrollmentReplacesSuffixWithoutCrossEnrollmentCertificateDeletion(t *testing.T) {
	s, f := tunnelTestServer(t)
	fingerprint := strings.Repeat("a", 64)
	first := enroll(t, s, ownerA, fingerprint)
	before := readyTunnel(t, s, first)
	oldPack := f.certificatePacks[before.CertificatePackID]
	if err := s.RetireMachine(t.Context(), first["node_id"]); err != nil {
		t.Fatal(err)
	}
	driveTunnels(t, s)
	second := enroll(t, s, ownerA, fingerprint)
	after := readyTunnel(t, s, second)
	if before.EndpointSuffix == after.EndpointSuffix || before.ServiceURL == after.ServiceURL || first["epoch"] == second["epoch"] {
		t.Fatal("re-enrollment reused endpoint identity")
	}
	if before.ProxyURLTemplate != after.ProxyURLTemplate {
		t.Fatal("stable proxy namespace changed")
	}
	if len(f.certificatePacks) != 1 || after.CertificatePackID == oldPack.ID {
		t.Fatal("replacement certificate not isolated")
	}
	f.certificatePacks[oldPack.ID] = oldPack
	execSQL(t, s.db, `UPDATE lpcc.machine_certificates SET state=jsonb_set(state,'{audit_after}','"2000-01-01T00:00:00Z"')`)
	driveTunnels(t, s)
	if _, ok := f.certificatePacks[after.CertificatePackID]; !ok {
		t.Fatal("old enrollment deleted replacement certificate")
	}
	if _, ok := f.certificatePacks[oldPack.ID]; ok {
		t.Fatal("late predecessor result retained")
	}
}

func TestLegacyEndpointsDoNotBlockFreshEnrollmentOrCertificateCleanup(t *testing.T) {
	s, f := tunnelTestServer(t)
	legacy := enroll(t, s, ownerA, strings.Repeat("c", 64))
	readyTunnel(t, s, legacy)
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=state-'endpoint_suffix' WHERE node_id=$1`, legacy["node_id"])
	wildcard := "*.orphan.fleet.example.invalid"
	pack, err := f.OrderCertificate(t.Context(), []string{"example.invalid", wildcard})
	if err != nil {
		t.Fatal(err)
	}
	execSQL(t, s.db, `INSERT INTO lpcc.machine_certificates(zone_id,wildcard_host,account_id) VALUES($1,$2,$3)`, s.params.CloudflareZoneID, wildcard, s.params.CloudflareAccountID)
	fresh := enroll(t, s, ownerA, strings.Repeat("d", 64))
	readyTunnel(t, s, fresh)
	state, _, err := s.loadTunnel(t.Context(), legacy["node_id"], legacy["epoch"])
	if err != nil || state.Ready || state.Reason != "legacy_endpoints_require_retirement" || state.EndpointSuffix != "" {
		t.Fatal("legacy enrollment was not excluded with a durable reason", state, err)
	}
	if _, exists := f.certificatePacks[pack.ID]; exists {
		t.Fatal("legacy enrollment blocked unused certificate cleanup")
	}
	adminA(t, s)
	for _, kind := range []string{"access", "connector"} {
		for _, compromised := range []bool{false, true} {
			requireStatus(t, request(t, s, "POST", "/api/admin/machines/"+legacy["node_id"]+"/tunnel/rotate", "session-a", map[string]any{"epoch": legacy["epoch"], "kind": kind, "compromised": compromised}), 409)
		}
	}
}

func TestDomainCertificatePrecedesDrainAndReleasesAbandonedCandidates(t *testing.T) {
	s, f := tunnelTestServer(t)
	c := enroll(t, s, ownerA, strings.Repeat("e", 64))
	initial := readyTunnel(t, s, c)
	f.certificateStatus = "pending_validation"
	s.params.CloudflareBaseDomain = "replacement.example.invalid"
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	pending, _, err := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if err != nil || pending.DrainRequested || pending.Target != "" || pending.ServiceURL != initial.ServiceURL || pending.ProxyURLTemplate != initial.ProxyURLTemplate {
		t.Fatal("certificate issuance changed endpoints or started a drain", pending, err)
	}
	files := archiveFiles(t, request(t, s, "GET", "/v1/nodes/"+c["node_id"]+"/config", c["token"], nil).Body.Bytes())
	if !strings.Contains(files["tunnel.yaml"], initial.ProxyURLTemplate) {
		t.Fatal("pending certificate changed the proxy template")
	}
	pack := f.certificatePacks[pending.CertificatePackID]
	pack.Status = "active"
	f.certificatePacks[pack.ID] = pack
	driveTunnels(t, s)
	draining, _, err := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if err != nil || !draining.DrainRequested || draining.Target == "" {
		t.Fatal("usable certificate did not release endpoint staging", draining, err)
	}
	s.params.CloudflareBaseDomain = "another.example.invalid"
	configureTestTunnels(t, s)
	driveTunnels(t, s)
	canceled, _, err := s.loadTunnel(t.Context(), c["node_id"], c["epoch"])
	if err != nil || canceled.DrainRequested || canceled.Target != "" || canceled.HeldOrchestrator != "" || canceled.ServiceURL != initial.ServiceURL {
		t.Fatal("new pending certificate delayed obsolete drain cancellation", canceled, err)
	}
	if _, exists := f.certificatePacks[pack.ID]; exists {
		t.Fatal("abandoned candidate certificate retained")
	}
	s.params.CloudflareBaseDomain = "fleet.example.invalid"
	configureTestTunnels(t, s)
	readyTunnel(t, s, c)
	if len(f.certificatePacks) != 1 || f.certificatePacks[initial.CertificatePackID].ID == "" || count(t, s, `SELECT count(*) FROM lpcc.machine_certificate_refs`) != 1 {
		t.Fatal("canceled certificate candidates retained references or deleted current coverage")
	}
}
