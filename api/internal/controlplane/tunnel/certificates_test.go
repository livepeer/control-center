package tunnel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"testing"
	"time"
	"uuid"
)

type certificateFixture struct {
	TunnelProvider
	zone                     ZoneDetails
	packs                    map[string]CertificatePack
	orders, restarts         int
	lostOrder, delayedDelete bool
	orderStatus              string
}

func (f *certificateFixture) Zone(context.Context) (ZoneDetails, error) { return f.zone, nil }
func (f *certificateFixture) ListCertificatePacks(context.Context) ([]CertificatePack, error) {
	var all []CertificatePack
	for _, p := range f.packs {
		all = append(all, p)
	}
	return all, nil
}
func (f *certificateFixture) CertificatePack(_ context.Context, id string) (CertificatePack, error) {
	p, ok := f.packs[id]
	if !ok {
		return p, &ProviderError{Status: 404}
	}
	return p, nil
}
func (f *certificateFixture) OrderCertificate(_ context.Context, hosts []string) (CertificatePack, error) {
	f.orders++
	p := CertificatePack{ID: uuid.New().String(), Type: "advanced", Hosts: slices.Clone(hosts), Status: f.orderStatus, Certificates: []Certificate{{Hosts: slices.Clone(hosts), Status: "active", ExpiresOn: time.Now().Add(time.Hour)}}}
	f.packs[p.ID] = p
	if f.lostOrder {
		f.lostOrder = false
		return CertificatePack{}, &ProviderError{Status: 503, Ambiguous: true}
	}
	return p, nil
}
func (f *certificateFixture) RestartCertificateValidation(_ context.Context, id string) error {
	f.restarts++
	return nil
}
func (f *certificateFixture) DeleteCertificate(_ context.Context, id string) error {
	if f.delayedDelete {
		p := f.packs[id]
		p.Status = "pending_deletion"
		f.packs[id] = p
	} else {
		delete(f.packs, id)
	}
	return nil
}
func certificateTestLease(t *testing.T) (*Manager, *certificateFixture, *tunnelLease) {
	t.Helper()
	s, base, l := claimTestTunnel(t)
	f := &certificateFixture{TunnelProvider: base, packs: map[string]CertificatePack{}, orderStatus: "active", zone: ZoneDetails{ID: "zone", Name: "example.invalid", Status: "active", Type: "full"}}
	f.zone.Account.ID = "account"
	s.provider = f
	l.provider = f
	l.state.AccountID = "account"
	l.state.ZoneID = "zone"
	if err := l.save(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Lease.Release(context.Background()) })
	return s, f, l
}
func TestEndpointSuffixPersistenceAndRandomFailure(t *testing.T) {
	s, _, l := claimTestTunnel(t)
	if !regexp.MustCompile(`^[a-z2-7]{7}$`).MatchString(l.state.EndpointSuffix) {
		t.Fatal("invalid base32 suffix")
	}
	first := l.state.EndpointSuffix
	s.endpointRandom = bytes.NewReader(nil)
	if _, err := s.claimTunnel(t.Context(), l.Machine); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("concurrent worker acquired enrollment", err)
	}
	l.Lease.Release(t.Context())
	next, err := s.claimTunnel(t.Context(), l.Machine)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Lease.Release(t.Context())
	if next.state.EndpointSuffix != first || next.state.ServiceURL != l.state.ServiceURL {
		t.Fatal("retry changed endpoint identity")
	}
	m := l.Machine
	m.Epoch = uuid.New().String()
	if _, err = s.newEndpointSuffix(t.Context(), m); err == nil {
		t.Fatal("randomness failure ignored")
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_states SET state=jsonb_set(state,'{endpoint_suffix}','"aaaaaaa"') WHERE node_id=$1`, m.NodeID)
	s.endpointRandom = bytes.NewReader([]byte{0, 0, 0, 0, 255, 255, 255, 255})
	suffix, err := s.newEndpointSuffix(t.Context(), m)
	if err != nil || suffix != "777777y" {
		t.Fatal("previous enrollment suffix was not resampled", suffix, err)
	}
}
func TestCertificateLostOrderPendingValidationAndCoverage(t *testing.T) {
	s, f, l := certificateTestLease(t)
	f.lostOrder = true
	f.orderStatus = "pending_validation"
	if _, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err == nil {
		t.Fatal("lost response ignored")
	}
	if ready, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil || ready || f.orders != 1 {
		t.Fatal("lost order was not recovered", ready, err, f.orders)
	}
	id := l.state.CertificatePackID
	for range 2 {
		if ready, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil || ready || f.orders != 1 {
			t.Fatal("pending pack reordered", ready, err)
		}
	}
	p := f.packs[id]
	p.Status = "validation_timed_out"
	f.packs[id] = p
	for range 2 {
		if _, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil {
			t.Fatal(err)
		}
	}
	if f.restarts != 1 {
		t.Fatal("validation restart lacked backoff", f.restarts)
	}
	p.Status = "active"
	f.packs[id] = p
	if ready, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil || !ready {
		t.Fatal("active coverage not admitted", ready, err)
	}
	p.Certificates[0].ExpiresOn = time.Now().Add(-time.Minute)
	f.packs[id] = p
	if ready, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil || ready {
		t.Fatal("expired certificate admitted", ready, err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machine_certificate_refs`) != 1 {
		t.Fatal("duplicate enrollment references")
	}
}
func TestCertificateOwnershipCleanupAndLateResults(t *testing.T) {
	s, f, l := certificateTestLease(t)
	if ready, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil || !ready {
		t.Fatal(ready, err)
	}
	selected := l.state.CertificatePackID
	original := f.packs[selected]
	broad := original
	broad.ID = "unrelated"
	broad.Hosts = append(slices.Clone(broad.Hosts), "extra.example.invalid")
	f.packs[broad.ID] = broad
	duplicate := original
	duplicate.ID = "duplicate"
	f.packs[duplicate.ID] = duplicate
	if ready, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil || ready {
		t.Fatal("duplicate absence was not observed", ready, err)
	}
	if _, ok := f.packs[duplicate.ID]; ok {
		t.Fatal("owned duplicate retained")
	}
	if _, ok := f.packs[broad.ID]; !ok {
		t.Fatal("broader certificate deleted")
	}
	f.delayedDelete = true
	if err := l.releaseCertificates(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if count(t, s, `SELECT count(*) FROM lpcc.machine_certificate_refs`) != 0 {
		t.Fatal("reference retained")
	}
	// A new enrollment wants the same namespace while an older DELETE is pending.
	if ready, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil || ready {
		t.Fatal("deleting pack reused", ready, err)
	}
	delete(f.packs, selected)
	f.delayedDelete = false
	if ready, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil || !ready {
		t.Fatal("replacement certificate unavailable", ready, err)
	}
	if l.state.CertificatePackID == selected {
		t.Fatal("retired pack selected")
	}
	current := l.state.CertificatePackID
	// A very late create from the earlier intent is an owned duplicate, not a
	// replacement for the enrollment's selected pack.
	late := original
	late.ID = "late"
	f.packs[late.ID] = late
	if _, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.packs[current]; !ok {
		t.Fatal("late cleanup deleted active certificate")
	}
	if err := l.releaseCertificates(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s.reconcileUnusedCertificates(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(f.packs) != 1 {
		t.Fatal("owned certificates orphaned", len(f.packs))
	}
	// The retained namespace watch also removes creates appearing after absence.
	late.ID = "after-cleanup"
	f.packs[late.ID] = late
	execSQL(t, s.db, `UPDATE lpcc.machine_certificates SET state=jsonb_set(state,'{audit_after}','"2000-01-01T00:00:00Z"')`)
	if err := s.reconcileUnusedCertificates(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.packs[late.ID]; ok {
		t.Fatal("late certificate was not cleaned")
	}
}
func TestCertificateNamespaceLeaseAndZoneValidation(t *testing.T) {
	s, f, l := certificateTestLease(t)
	wildcard := "*." + l.Machine.NodeID + ".fleet.example.invalid"
	cert, err := s.claimCertificate(t.Context(), "zone", wildcard, "account")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.claimCertificate(t.Context(), "zone", wildcard, "account"); !errors.Is(err, ErrPending) {
		t.Fatal("concurrent namespace owner", err)
	}
	execSQL(t, s.db, `UPDATE lpcc.machine_certificates SET lease_until=now()-interval '1 second'`)
	replacement, err := s.claimCertificate(t.Context(), "zone", wildcard, "account")
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.save(t.Context()); !errors.Is(err, errTunnelFenced) {
		t.Fatal("superseded certificate worker wrote state", err)
	}
	cert.close()
	if _, err := s.claimCertificate(t.Context(), "zone", wildcard, "account"); !errors.Is(err, ErrPending) {
		t.Fatal("old release cleared replacement lease", err)
	}
	replacement.close()
	f.zone.Type = "partial"
	if ready, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err == nil || ready || f.orders != 0 {
		t.Fatal("partial zone was provisioned", ready, err)
	}
	f.zone.Type = "full"
	f.zone.Name = "other.invalid"
	if _, err := l.ensureCertificate(t.Context(), l.state.ProxyURLTemplate); err == nil || f.orders != 0 {
		t.Fatal("outside zone was provisioned", err)
	}
	var raw []byte
	if err := s.db.QueryRow(`SELECT state FROM lpcc.machine_certificates`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored certificateState
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.PackID != "" {
		t.Fatal("zone validation ordered a pack")
	}
}
