package tunnel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloudflareConfigurationPreservesOriginHost(t *testing.T) {
	rules := []IngressRule{{Hostname: "api.example.invalid", Service: PrivateOrchestrator, OriginRequest: &OriginRequest{HTTPHostHeader: endpointHost(PrivateOrchestrator)}}, {Service: "http_status:404"}}
	puts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			puts++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"version": 3, "config": map[string]any{"ingress": rules}}})
	}))
	defer server.Close()
	provider := &cloudflareHTTP{client: server.Client(), base: server.URL}
	for range 2 {
		if version, err := provider.Configure(t.Context(), "tunnel", rules); err != nil || version != 3 {
			t.Fatal(version, err)
		}
	}
	if puts != 0 {
		t.Fatal("origin Host readback caused configuration churn", puts)
	}
}

func TestCertificateProviderWireContract(t *testing.T) {
	hosts := []string{"example.invalid", "*.lp-a.fleet.example.invalid"}
	pack := CertificatePack{ID: "pack", Type: "advanced", Hosts: hosts, Status: "pending_validation"}
	methods := map[string]int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods[r.Method+" "+r.URL.Path]++
		var result any = pack
		switch {
		case r.URL.Path == "/zones/zone":
			result = ZoneDetails{ID: "zone", Name: "example.invalid", Type: "full", Status: "active"}
		case r.Method == "POST":
			var in struct {
				Type       string   `json:"type"`
				Hosts      []string `json:"hosts"`
				CA         string   `json:"certificate_authority"`
				Validation string   `json:"validation_method"`
				Days       int      `json:"validity_days"`
			}
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				t.Error(err)
			}
			if in.Type != "advanced" || !sameHosts(in.Hosts, hosts) || in.CA != "google" || in.Validation != "txt" || in.Days != 90 {
				t.Error("incorrect certificate order", in)
			}
		case r.Method == "GET" && r.URL.Path == "/zones/zone/ssl/certificate_packs":
			if r.URL.Query().Get("status") != "all" || r.URL.Query().Get("per_page") != "50" {
				t.Error("incomplete certificate inventory")
			}
			result = []CertificatePack{pack}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer server.Close()
	provider := &cloudflareHTTP{client: server.Client(), base: server.URL, params: Config{CloudflareZoneID: "zone"}}
	if zone, err := provider.Zone(t.Context()); err != nil || zone.Name != "example.invalid" {
		t.Fatal(zone, err)
	}
	if _, err := provider.OrderCertificate(t.Context(), hosts); err != nil {
		t.Fatal(err)
	}
	if packs, err := provider.ListCertificatePacks(t.Context()); err != nil || len(packs) != 1 {
		t.Fatal(packs, err)
	}
	if _, err := provider.CertificatePack(t.Context(), "pack"); err != nil {
		t.Fatal(err)
	}
	if err := provider.RestartCertificateValidation(t.Context(), "pack"); err != nil {
		t.Fatal(err)
	}
	if err := provider.DeleteCertificate(t.Context(), "pack"); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"PATCH", "DELETE"} {
		if methods[method+" /zones/zone/ssl/certificate_packs/pack"] != 1 {
			t.Fatal("missing certificate operation", method)
		}
	}
}
