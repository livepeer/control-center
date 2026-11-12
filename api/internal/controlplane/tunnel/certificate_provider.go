package tunnel

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"time"
)

type ZoneDetails struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Type    string `json:"type"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
}

type Certificate struct {
	Hosts     []string  `json:"hosts"`
	Status    string    `json:"status"`
	ExpiresOn time.Time `json:"expires_on"`
}

type CertificatePack struct {
	ID           string        `json:"id"`
	Type         string        `json:"type"`
	Hosts        []string      `json:"hosts"`
	Status       string        `json:"status"`
	Certificates []Certificate `json:"certificates"`
}

type CertificateProvider interface {
	Zone(context.Context) (ZoneDetails, error)
	ListCertificatePacks(context.Context) ([]CertificatePack, error)
	CertificatePack(context.Context, string) (CertificatePack, error)
	OrderCertificate(context.Context, []string) (CertificatePack, error)
	RestartCertificateValidation(context.Context, string) error
	DeleteCertificate(context.Context, string) error
}

func (c *cloudflareHTTP) certificatePath() string {
	return "/zones/" + c.params.CloudflareZoneID + "/ssl/certificate_packs"
}
func (c *cloudflareHTTP) Zone(ctx context.Context) (ZoneDetails, error) {
	var zone ZoneDetails
	_, err := c.call(ctx, "GET", "/zones/"+c.params.CloudflareZoneID, nil, &zone)
	return zone, err
}
func (c *cloudflareHTTP) ListCertificatePacks(ctx context.Context) ([]CertificatePack, error) {
	var result []CertificatePack
	for page := 1; page <= 100; page++ {
		var packs []CertificatePack
		pages, err := c.call(ctx, "GET", c.certificatePath()+"?status=all&per_page=50&page="+strconv.Itoa(page), nil, &packs)
		if err != nil {
			return nil, err
		}
		result = append(result, packs...)
		if pages > 0 && page >= pages || pages == 0 && len(packs) < 50 {
			return result, nil
		}
	}
	return nil, errors.New("certificate listing from Cloudflare exceeds limit")
}
func (c *cloudflareHTTP) CertificatePack(ctx context.Context, id string) (CertificatePack, error) {
	var pack CertificatePack
	_, err := c.call(ctx, "GET", c.certificatePath()+"/"+url.PathEscape(id), nil, &pack)
	return pack, err
}
func (c *cloudflareHTTP) OrderCertificate(ctx context.Context, hosts []string) (CertificatePack, error) {
	var pack CertificatePack
	_, err := c.call(ctx, "POST", c.certificatePath()+"/order", map[string]any{"type": "advanced", "hosts": hosts, "certificate_authority": "google", "validation_method": "txt", "validity_days": 90}, &pack)
	return pack, err
}
func (c *cloudflareHTTP) RestartCertificateValidation(ctx context.Context, id string) error {
	_, err := c.call(ctx, "PATCH", c.certificatePath()+"/"+url.PathEscape(id), map[string]any{}, nil)
	return err
}
func (c *cloudflareHTTP) DeleteCertificate(ctx context.Context, id string) error {
	_, err := c.call(ctx, "DELETE", c.certificatePath()+"/"+url.PathEscape(id), nil, nil)
	return err
}
