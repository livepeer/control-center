package onchain

import (
	"net"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{Version: 1, CredentialRevision: 1, Mode: "onchain", Network: "custom", ChainID: 123, Controller: "0x" + strings.Repeat("1", 40), Recipient: "0x" + strings.Repeat("2", 40), RPCSecret: strings.Repeat("c", 64), RedeemerURL: "https://redeemer.example", WeiPerUSD: "100", TicketFaceValue: "100", TicketWinProb: "1", MaxPendingTickets: 100, MaxTicketsPerRecipient: 10}
}
func TestCompleteOnchainConfigurationAndExplicitOffchain(t *testing.T) {
	if e := validConfig().Validate(); e != nil {
		t.Fatal(e)
	}
	if e := Offchain().Validate(); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*Config){"missing recipient": func(c *Config) { c.Recipient = "" }, "mode only": func(c *Config) { *c = Config{Version: 1, Mode: "onchain"} }, "empty destination query": func(c *Config) { c.RedeemerURL += "?" }, "insecure destination": func(c *Config) { c.RedeemerURL = "http://redeemer.example" }, "inline destination secret": func(c *Config) { c.RedeemerURL = "https://secret@redeemer.example" }, "invalid winning probability": func(c *Config) { c.TicketWinProb = "0" }, "two rate policies": func(c *Config) { c.ETHUSDFeed = c.Controller; c.PriceMaxAge = "1h" }, "broad network": func(c *Config) { c.RedeemerGrants = []string{"10.0.0.0/8"} }, "wrong chain": func(c *Config) { c.Network = "arbitrum-one-mainnet" }, "offchain retains onchain inputs": func(c *Config) { c.Mode = "offchain" }, "overflow": func(c *Config) { c.ChainID = ^uint64(0) }} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("accepted invalid onchain configuration")
			}
		})
	}
}

func TestEndpointPolicyMatchesNodeAndKeepsMetadataPrivate(t *testing.T) {
	for _, ip := range []string{"100.64.0.1", "192.0.2.1", "198.18.0.1", "240.0.0.1", "2001:db8::1"} {
		endpoint := "https://" + net.JoinHostPort(ip, "443")
		if ValidateEndpoint(endpoint, nil) == nil || ValidateEndpoint(endpoint, []string{net.JoinHostPort(ip, "443")}) != nil {
			t.Fatal("reserved destination did not require an exact grant", ip)
		}
	}
	for _, ip := range []string{"169.254.169.254", "fe80::1", "127.0.0.1", "0.0.0.0", "ff02::1"} {
		if _, _, err := Grant(net.JoinHostPort(ip, "443")); err == nil {
			t.Fatal("unsafe network exception accepted", ip)
		}
	}
}
