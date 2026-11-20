package tunnel

import (
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Live provisioning has no account, domain, lifetime or image defaults.
type Config struct {
	CloudflareEnabled         bool          `env:"CLOUDFLARE_ENABLED" default:"false" descr:"Enable managed machine tunnels after infrastructure preflight"`
	CloudflareIngressApproved bool          `env:"CLOUDFLARE_INGRESS_APPROVED" default:"false" descr:"Advertise only after the real ingress/direct-origin release gates pass"`
	CloudflareAccountID       string        `env:"CLOUDFLARE_ACCOUNT_ID" optional:"true" descr:"Cloudflare account owning tunnels"`
	CloudflareZoneID          string        `env:"CLOUDFLARE_ZONE_ID" optional:"true" descr:"Cloudflare DNS zone ID"`
	CloudflareBaseDomain      string        `env:"CLOUDFLARE_BASE_DOMAIN" optional:"true" descr:"Dedicated managed hostname namespace"`
	CloudflareAPIToken        string        `env:"CLOUDFLARE_API_TOKEN" secret:"true" optional:"true" descr:"Backend-only Cloudflare provisioning token"`
	CloudflareAPITokenFile    string        `env:"CLOUDFLARE_API_TOKEN_FILE" secretfor:"CloudflareAPIToken" basepath:"source" descr:"Private provisioning credential file"`
	TunnelStatusTTL           time.Duration `env:"TUNNEL_STATUS_TTL" optional:"true" descr:"Maximum age of Runtime readiness observations"`
	TunnelNodeAddresses       []string      `env:"TUNNEL_NODE_ADDRESSES" optional:"true" descr:"Node/management addresses excluded from connector public egress"`
}

var cfIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

func (p Config) Validate(api string) error {
	if !p.CloudflareEnabled {
		return nil
	}
	if !cfIDPattern.MatchString(p.CloudflareAccountID) || !cfIDPattern.MatchString(p.CloudflareZoneID) || !domainPattern.MatchString(p.CloudflareBaseDomain) || !strings.Contains(p.CloudflareBaseDomain, ".") {
		return errors.New("configure Cloudflare account, zone and base domain before enabling tunnels")
	}
	u, e := url.Parse(api)
	if e != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("tunnel-enabled PublicAPIURL requires verified HTTPS")
	}
	if p.TunnelStatusTTL < 2*time.Minute {
		return errors.New("configure tunnel status TTL of at least two minutes")
	}
	for _, raw := range p.TunnelNodeAddresses {
		if _, e := netip.ParsePrefix(raw); e != nil {
			return errors.New("tunnel network exceptions/exclusions require literal CIDRs")
		}
	}
	if len(p.TunnelNodeAddresses) == 0 {
		return errors.New("configure the fleet node/management address exclusions before enabling tunnels")
	}
	return nil
}
