// Package onchain defines the nonsecret managed Node onchain contract.
package onchain

import (
	"errors"
	"math/big"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/livepeer/control-center/schema"
)

type Config struct {
	Version                int      `json:"version"`
	Generation             int64    `json:"generation"`
	CredentialRevision     uint64   `json:"credential_revision,omitempty"`
	Mode                   string   `json:"mode"`
	Network                string   `json:"network,omitempty"`
	ChainID                uint64   `json:"chain_id,omitempty"`
	Controller             string   `json:"controller,omitempty"`
	Recipient              string   `json:"recipient,omitempty"`
	RPCSecret              string   `json:"rpc_secret,omitempty"`
	RPCGrants              []string `json:"rpc_grants,omitempty"`
	RedeemerURL            string   `json:"redeemer_url,omitempty"`
	RedeemerGrants         []string `json:"redeemer_grants,omitempty"`
	WeiPerUSD              string   `json:"wei_per_usd,omitempty"`
	ETHUSDFeed             string   `json:"eth_usd_feed,omitempty"`
	PriceMaxAge            string   `json:"price_max_age,omitempty"`
	TicketFaceValue        string   `json:"ticket_face_value,omitempty"`
	TicketWinProb          string   `json:"ticket_win_prob,omitempty"`
	MaxPendingTickets      int      `json:"max_pending_tickets,omitempty"`
	MaxTicketsPerRecipient int      `json:"max_tickets_per_recipient,omitempty"`
}

func Offchain() Config         { return Config{Version: 1, Mode: "offchain"} }
func (c Config) Onchain() bool { return c.Mode == "onchain" }

var Address = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
var SecretRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$`)

func validAddress(s string) bool { return Address.MatchString(s) && strings.Trim(s[2:], "0") != "" }

func (c Config) Validate() error {
	bad := errors.New("invalid onchain infrastructure settings")
	if c.Version != 1 || c.Generation < 0 {
		return bad
	}
	if c.Mode == "offchain" {
		d := c
		d.Generation = 0
		if d.CredentialRevision != 0 || d.Network != "" || d.Recipient != "" || d.ChainID != 0 || d.Controller != "" || d.RPCSecret != "" || d.RedeemerURL != "" || d.WeiPerUSD != "" || d.ETHUSDFeed != "" || d.TicketFaceValue != "" || d.TicketWinProb != "" || len(d.RPCGrants)+len(d.RedeemerGrants) > 0 || d.PriceMaxAge != "" || d.MaxPendingTickets != 0 || d.MaxTicketsPerRecipient != 0 {
			return bad
		}
		return nil
	}
	if c.CredentialRevision == 0 || c.ChainID > uint64(^uint64(0)>>1) || !c.Onchain() || (c.Network != "arbitrum-one-mainnet" && c.Network != "custom") || c.ChainID == 0 || (c.Network == "arbitrum-one-mainnet" && c.ChainID != 42161) || !validAddress(c.Controller) || !validAddress(c.Recipient) || !SecretRef.MatchString(c.RPCSecret) {
		return errors.New("onchain mode requires a supported network, chain/controller, recipient, versioned RPC secret, and positive credential_revision")
	}
	u, e := url.Parse(c.RedeemerURL)
	if len(c.RedeemerURL) > 2048 || e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return errors.New("redeemer_url must be HTTPS without credentials, query, or fragment")
	}
	if e := ValidateEndpoint(c.RedeemerURL, c.RedeemerGrants); e != nil {
		return e
	}
	if (c.WeiPerUSD == "") == (c.ETHUSDFeed == "") {
		return errors.New("choose exactly one of wei_per_usd and eth_usd_feed")
	}
	if c.Network == "arbitrum-one-mainnet" && !strings.EqualFold(c.Controller, "0xD8E8328501E9645d16Cf49539efC04f734606ee4") {
		return errors.New("mainnet requires the released Node mainnet controller")
	}
	if c.WeiPerUSD != "" {
		r, ok := new(big.Rat).SetString(c.WeiPerUSD)
		if !ok || r.Sign() <= 0 || len(c.WeiPerUSD) > 128 || c.PriceMaxAge != "" {
			return errors.New("wei_per_usd must be a positive exact rate without price_max_age")
		}
	} else {
		d, e := time.ParseDuration(c.PriceMaxAge)
		if !validAddress(c.ETHUSDFeed) || e != nil || d <= 0 || d > 24*time.Hour {
			return errors.New("eth_usd_feed requires an address and price_max_age between zero and 24h")
		}
	}
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	for _, s := range []string{c.TicketFaceValue, c.TicketWinProb} {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok || n.Sign() <= 0 || n.Cmp(max) > 0 || n.String() != s {
			return bad
		}
	}
	w, _ := new(big.Int).SetString(c.TicketWinProb, 10)
	if w.Cmp(max) == 0 || c.MaxPendingTickets < 1 || c.MaxPendingTickets > 1000000 || c.MaxTicketsPerRecipient < 1 || c.MaxTicketsPerRecipient > c.MaxPendingTickets {
		return bad
	}
	for _, grants := range [][]string{c.RPCGrants, c.RedeemerGrants} {
		if len(grants) > 16 {
			return bad
		}
		for _, g := range grants {
			if _, _, e := Grant(g); e != nil {
				return errors.New("onchain grants must be explicit non-loopback IP:port destinations")
			}
		}
	}
	return nil
}

// Grant is an explicit IP and TCP port. DNS names and broad networks cannot
// silently expand the Kubernetes exception for a private destination.
func Grant(s string) (netip.Addr, uint16, error) {
	a, e := netip.ParseAddrPort(s)
	if e != nil || a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().IsMulticast() || a.Addr().IsLoopback() || a.Addr().Zone() != "" {
		return netip.Addr{}, 0, errors.New("onchain grants require IP:port")
	}
	return a.Addr().Unmap(), a.Port(), nil
}

func (c Config) Compatible(d schema.DefinitionV1) error {
	mode := schema.Offchain
	if c.Onchain() {
		mode = schema.Onchain
	}
	return schema.ValidatePolicy(d, mode)
}

// Observation never contains credentials or individual ticket data.
type Observation struct {
	Generation int64  `json:"generation"`
	Mode       string `json:"mode"`
	PodUID     string `json:"pod_uid"`
	GrantID    string `json:"grant_id,omitempty"`
	Applied    bool   `json:"applied"`
	Ready      bool   `json:"ready"`
	Handoff    string `json:"handoff"`
}

// ValidateEndpoint rejects destinations the rendered egress policy cannot reach.
// Private DNS addresses still require exact grants at the Node/Kubernetes boundary.
func ValidateEndpoint(raw string, grants []string) error {
	bad := errors.New("private or nonstandard-port onchain destinations require matching IP:port grants")
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return errors.New("onchain destinations require HTTPS")
	}
	port := uint64(443)
	if u.Port() != "" {
		port, e = strconv.ParseUint(u.Port(), 10, 16)
		if e != nil || port == 0 {
			return bad
		}
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
			return bad
		}
		if !ip.IsPrivate() && port == 443 {
			return nil
		}
	} else if port == 443 {
		return nil
	}
	for _, g := range grants {
		a, p, e := Grant(g)
		if e == nil && uint64(p) == port && (ip == netip.Addr{} || a == ip) {
			return nil
		}
	}
	return bad
}
