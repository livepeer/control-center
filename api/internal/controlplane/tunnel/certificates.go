package tunnel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
	"uuid"
)

type certificateState struct {
	PackID             string    `json:"pack_id,omitempty"`
	Status             string    `json:"status,omitempty"`
	Pending            bool      `json:"pending,omitempty"`
	Attempts           int       `json:"attempts,omitempty"`
	AttemptAt          time.Time `json:"attempt_at,omitempty"`
	ValidationAttempts int       `json:"validation_attempts,omitempty"`
	ValidationAt       time.Time `json:"validation_at,omitempty"`
	ObservedAt         time.Time `json:"observed_at,omitempty"`
	AuditAfter         time.Time `json:"audit_after,omitempty"`
	// Never adopt a pack whose deletion was requested, even after a new
	// enrollment acquires this namespace and an old DELETE arrives late.
	RetiredIDs []string `json:"retired_ids,omitempty"`
}

type certificateLease struct {
	s                           *Manager
	zone, wildcard, account, id string
	state                       certificateState
	provider                    TunnelProvider
}

func (s *Manager) claimCertificate(ctx context.Context, zone, wildcard, account string) (*certificateLease, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO lpcc.machine_certificates(zone_id,wildcard_host,account_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, zone, wildcard, account)
	if err != nil {
		return nil, err
	}
	l := &certificateLease{s: s, zone: zone, wildcard: wildcard, account: account, id: uuid.New().String()}
	var raw []byte
	err = s.db.QueryRowContext(ctx, `UPDATE lpcc.machine_certificates SET lease_id=$4,lease_until=now()+interval '90 seconds' WHERE zone_id=$1 AND wildcard_host=$2 AND account_id=$3 AND (lease_until IS NULL OR lease_until<now()) RETURNING state`, zone, wildcard, account, l.id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPending
	}
	if err != nil {
		return nil, err
	}
	l.provider = s.providerFor(RoutingState{AccountID: account, ZoneID: zone})
	if err = json.Unmarshal(raw, &l.state); err != nil {
		l.close()
		return nil, err
	}
	return l, nil
}
func (l *certificateLease) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = l.s.db.ExecContext(ctx, `UPDATE lpcc.machine_certificates SET lease_id=NULL,lease_until=NULL WHERE zone_id=$1 AND wildcard_host=$2 AND lease_id=$3`, l.zone, l.wildcard, l.id)
}
func (l *certificateLease) save(ctx context.Context) error {
	raw, err := json.Marshal(l.state)
	if err != nil {
		return err
	}
	result, err := l.s.db.ExecContext(ctx, `UPDATE lpcc.machine_certificates SET state=$4,lease_until=now()+interval '90 seconds' WHERE zone_id=$1 AND wildcard_host=$2 AND lease_id=$3 AND lease_until>now()`, l.zone, l.wildcard, l.id, string(raw))
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return errTunnelFenced
	}
	return nil
}
func certificateHosts(zone ZoneDetails, wildcard string) []string {
	return []string{zone.Name, wildcard}
}
func managedCertificate(pack CertificatePack, hosts []string) bool {
	return pack.ID != "" && pack.Type == "advanced" && sameHosts(pack.Hosts, hosts)
}
func usableCertificate(pack CertificatePack, hosts []string) bool {
	if pack.Status != "active" {
		return false
	}
	for _, host := range hosts {
		covered := false
		for _, cert := range pack.Certificates {
			covered = covered || cert.Status == "active" && cert.ExpiresOn.After(time.Now()) && slices.Contains(cert.Hosts, host)
		}
		if !covered {
			return false
		}
	}
	return true
}
func certificateStatus(status string) string {
	switch status {
	case "initializing", "pending_validation", "pending_issuance", "pending_deployment", "pending_deletion", "pending_expiration", "expired", "active", "initializing_timed_out", "validation_timed_out", "issuance_timed_out", "deployment_timed_out", "deletion_timed_out", "pending_cleanup", "deleted":
		return status
	default:
		return "unknown"
	}
}

func (l *certificateLease) reconcile(ctx context.Context) (bool, error) {
	var wanted bool
	if err := l.s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM lpcc.machine_certificate_refs WHERE zone_id=$1 AND wildcard_host=$2)`, l.zone, l.wildcard).Scan(&wanted); err != nil {
		return false, err
	}
	if !wanted && time.Now().Before(l.state.AuditAfter) {
		return l.state.Status == "deleted", nil
	}
	zone, err := l.provider.Zone(ctx)
	if err != nil {
		return false, err
	}
	if zone.ID != l.zone || zone.Account.ID != l.account || zone.Status != "active" || zone.Type != "full" || !domainPattern.MatchString(zone.Name) || !(strings.TrimPrefix(l.wildcard, "*.") == zone.Name || strings.HasSuffix(strings.TrimPrefix(l.wildcard, "*."), "."+zone.Name)) {
		return false, errors.New("certificate requires an active authoritative zone in the configured account")
	}
	hosts := certificateHosts(zone, l.wildcard)
	packs, err := l.provider.ListCertificatePacks(ctx)
	if err != nil {
		return false, err
	}
	owned := []CertificatePack{}
	for _, pack := range packs {
		if managedCertificate(pack, hosts) && pack.Status != "deleted" {
			owned = append(owned, pack)
		}
	}
	sort.Slice(owned, func(i, j int) bool { return owned[i].ID < owned[j].ID })
	if wanted && l.state.PackID == "" {
		for _, pack := range owned {
			if !slices.Contains(l.state.RetiredIDs, pack.ID) && pack.Status != "pending_deletion" && pack.Status != "deletion_timed_out" {
				l.state.PackID = pack.ID
				l.state.Pending = false
				if err := l.save(ctx); err != nil {
					return false, err
				}
				break
			}
		}
	}
	deleted := false
	for _, pack := range owned {
		if wanted && pack.ID == l.state.PackID && !slices.Contains(l.state.RetiredIDs, pack.ID) {
			continue
		}
		if !slices.Contains(l.state.RetiredIDs, pack.ID) {
			l.state.RetiredIDs = append(l.state.RetiredIDs, pack.ID)
		}
		l.state.AuditAfter = time.Time{}
		if err := l.save(ctx); err != nil {
			return false, err
		}
		if err := l.provider.DeleteCertificate(ctx, pack.ID); err != nil {
			return false, err
		}
		deleted = true
	}
	if deleted {
		l.state.Status = "pending_deletion"
		return false, l.save(ctx) // Absence must be observed in a later inventory.
	}
	if !wanted {
		l.state.PackID = ""
		l.state.Status = "deleted"
		l.state.ObservedAt = time.Now().UTC()
		l.state.AuditAfter = time.Now().UTC().Add(5 * time.Minute)
		return true, l.save(ctx)
	}
	if slices.Contains(l.state.RetiredIDs, l.state.PackID) {
		l.state.PackID = ""
	}
	if l.state.PackID == "" {
		if l.state.Pending && time.Since(l.state.AttemptAt) < createBackoff(l.state.Attempts) {
			return false, nil
		}
		l.state.Pending = true
		l.state.Attempts++
		l.state.AttemptAt = time.Now().UTC()
		l.state.Status = "initializing"
		if err := l.save(ctx); err != nil {
			return false, err
		}
		pack, err := l.provider.OrderCertificate(ctx, hosts)
		if err != nil {
			return false, err
		}
		if !managedCertificate(pack, hosts) {
			return false, errAmbiguousCreate
		}
		l.state.PackID = pack.ID
		l.state.Pending = false
		if err := l.save(ctx); err != nil {
			return false, err
		}
	}
	pack, err := l.provider.CertificatePack(ctx, l.state.PackID)
	if err != nil {
		return false, err
	}
	if pack.ID != l.state.PackID || !managedCertificate(pack, hosts) || slices.Contains(l.state.RetiredIDs, pack.ID) {
		return false, ErrResourceConflict
	}
	l.state.Status = certificateStatus(pack.Status)
	l.state.ObservedAt = time.Now().UTC()
	if pack.Status == "validation_timed_out" && time.Since(l.state.ValidationAt) >= createBackoff(l.state.ValidationAttempts) {
		l.state.ValidationAttempts++
		l.state.ValidationAt = time.Now().UTC()
		if err := l.save(ctx); err != nil {
			return false, err
		}
		if err := l.provider.RestartCertificateValidation(ctx, pack.ID); err != nil {
			return false, err
		}
	}
	return usableCertificate(pack, hosts), l.save(ctx)
}

func (l *tunnelLease) ensureCertificate(ctx context.Context, template string) (bool, error) {
	wildcard := wildcardHost(template)
	cert, err := l.s.claimCertificate(ctx, l.state.ZoneID, wildcard, l.state.AccountID)
	if err != nil {
		return false, err
	}
	defer cert.close()
	// Fence acquisition against machine retirement and superseded workers.
	var node string
	err = l.s.db.QueryRowContext(ctx, `INSERT INTO lpcc.machine_certificate_refs(zone_id,wildcard_host,node_id) SELECT $1,$2,$3 WHERE EXISTS(SELECT FROM lpcc.machine_states s JOIN lpcc.enrollments e USING(node_id) WHERE s.node_id=$3 AND s.lease_id=$4 AND s.revision=$5 AND s.lease_until>now() AND e.retired_at IS NULL) ON CONFLICT(zone_id,wildcard_host,node_id) DO UPDATE SET node_id=EXCLUDED.node_id RETURNING node_id`, l.state.ZoneID, wildcard, l.Machine.NodeID, l.Lease.ID, l.Revision).Scan(&node)
	if errors.Is(err, sql.ErrNoRows) {
		return false, errTunnelFenced
	}
	if err != nil {
		return false, err
	}
	ready, err := cert.reconcile(ctx)
	l.state.CertificatePackID = cert.state.PackID
	l.state.CertificateStatus = cert.state.Status
	if err != nil {
		l.state.CertificateStatus = "provider_error"
	}
	return ready, err
}

// Release only this enrollment's references. Namespace reconciliation, rather
// than an enrollment's resource sweep, owns every certificate DELETE.
func (l *tunnelLease) releaseCertificates(ctx context.Context, keep ...string) error {
	rows, err := l.s.db.QueryContext(ctx, `SELECT r.zone_id,r.wildcard_host,c.account_id FROM lpcc.machine_certificate_refs r JOIN lpcc.machine_certificates c USING(zone_id,wildcard_host) WHERE r.node_id=$1`, l.Machine.NodeID)
	if err != nil {
		return err
	}
	type namespace struct{ zone, host, account string }
	var all []namespace
	for rows.Next() {
		var n namespace
		if err = rows.Scan(&n.zone, &n.host, &n.account); err != nil {
			rows.Close()
			return err
		}
		all = append(all, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, n := range all {
		if slices.Contains(keep, n.host) {
			continue
		}
		cert, err := l.s.claimCertificate(ctx, n.zone, n.host, n.account)
		if err != nil {
			return err
		}
		_, err = l.s.db.ExecContext(ctx, `DELETE FROM lpcc.machine_certificate_refs WHERE zone_id=$1 AND wildcard_host=$2 AND node_id=$3 AND EXISTS(SELECT FROM lpcc.machine_states WHERE node_id=$3 AND lease_id=$4 AND revision=$5 AND lease_until>now())`, n.zone, n.host, l.Machine.NodeID, l.Lease.ID, l.Revision)
		if err == nil {
			_, err = cert.reconcile(ctx)
		}
		cert.close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Manager) reconcileUnusedCertificates(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT zone_id,wildcard_host,account_id FROM lpcc.machine_certificates c WHERE NOT EXISTS(SELECT FROM lpcc.machine_certificate_refs r WHERE r.zone_id=c.zone_id AND r.wildcard_host=c.wildcard_host)`)
	if err != nil {
		return err
	}
	type namespace struct{ zone, host, account string }
	var all []namespace
	for rows.Next() {
		var n namespace
		if err = rows.Scan(&n.zone, &n.host, &n.account); err != nil {
			rows.Close()
			return err
		}
		all = append(all, n)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var firstError error
	for _, n := range all {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pass, cancel := context.WithTimeout(ctx, 60*time.Second)
		cert, err := s.claimCertificate(pass, n.zone, n.host, n.account)
		if errors.Is(err, ErrPending) {
			cancel()
			continue
		}
		if err != nil {
			cancel()
			if firstError == nil {
				firstError = err
			}
			continue
		}
		_, err = cert.reconcile(pass)
		cert.close()
		cancel()
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	return firstError
}
