package tunnel

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestSharedAccessApplicationReadbackAndConflicts(t *testing.T) {
	state := RoutingFor("vkvkvkvkvkvkuaaaaaaaaaaaaa", "example.invalid")
	want := CFResource{Kind: "app", Name: "owned", Host: endpointHost(state.DiscoveryURL), Hosts: []string{endpointHost(state.ServiceURL), endpointHost(state.DiscoveryURL)}}
	var current cfObject
	var foreign *cfObject
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result any
		if r.Method == "POST" {
			if err := json.NewDecoder(r.Body).Decode(&current); err != nil {
				t.Error(err)
			}
			if !safeApplication(want, current) {
				t.Error("create omitted shared protection")
			}
			current.ID = "app"
			current.Audience = "shared-audience"
			result = current
		} else if r.URL.Path == "/accounts/account/access/apps/app" {
			result = current
		} else {
			all := []cfObject{current}
			if foreign != nil {
				all = append(all, *foreign)
			}
			result = all
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer server.Close()
	provider := &cloudflareHTTP{client: server.Client(), base: server.URL, params: Config{CloudflareAccountID: "account"}}
	created, _, _, err := provider.Create(t.Context(), want, "")
	if err != nil || created.Audience != "shared-audience" {
		t.Fatal(created, err)
	}
	slices.Reverse(current.Destinations)
	if found, err := provider.Find(t.Context(), created); err != nil || len(found) != 1 {
		t.Fatal("order-sensitive destination comparison", found, err)
	}
	current.Destinations[0].Overrides = []json.RawMessage{json.RawMessage(`{"behavior":"public","path_pattern":"/*"}`)}
	if _, err := provider.Find(t.Context(), created); !errors.Is(err, ErrUnsafeProtection) {
		t.Fatal("public override accepted", err)
	}
	current.Destinations[0].Overrides = nil
	current.Destinations = append(current.Destinations, accessDestination{Type: "public", URI: "*.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid"})
	if _, err := provider.Find(t.Context(), created); !errors.Is(err, ErrUnsafeProtection) {
		t.Fatal("wildcard protection accepted", err)
	}
	current.Destinations = current.Destinations[:2]
	foreign = &cfObject{ID: "foreign", Name: "foreign", Domain: "unrelated.example.invalid", Type: "self_hosted", Destinations: []accessDestination{{Type: "public", URI: want.Hosts[0] + "/apps"}}}
	if _, err := provider.Find(t.Context(), created); !errors.Is(err, ErrResourceConflict) {
		t.Fatal("API-only overlap was not detected", err)
	}
	if found, err := provider.FindOwned(t.Context(), created); err != nil || len(found) != 1 {
		t.Fatal("foreign conflict prevented owned cleanup", found, err)
	}
	for _, hostname := range []string{"ap*.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "discover*.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "a*.vkvkvkvkvkvkuaaaaaaaaaaaaa.example.invalid", "ap*.*.example.invalid"} {
		foreign.Destinations[0].URI = hostname + "/apps"
		if _, err := provider.Find(t.Context(), created); !errors.Is(err, ErrResourceConflict) {
			t.Fatal("partial-label overlap missed", hostname, err)
		}
	}
	foreign.Destinations[0].URI = "*.example.invalid"
	if _, err := provider.Find(t.Context(), created); err != nil {
		t.Fatal("Access wildcard crossed DNS labels", err)
	}
}

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

func TestSharedAccessPolicyRejectsBypassesAndPagedConflicts(t *testing.T) {
	mode := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result any = map[string]any{}
		pages := 1
		if r.Method == "GET" && r.URL.Path == "/accounts/account/access/apps/app/policies" {
			result = []map[string]string{{"id": "policy"}}
			if mode == "paged conflict" {
				pages = 2
				if r.URL.Query().Get("page") == "2" {
					result = []map[string]string{{"id": "foreign"}}
				}
			}
		} else if r.Method == "GET" {
			selector := map[string]any{"service_token": map[string]string{"token_id": "allowed"}}
			read := map[string]any{"decision": "non_identity", "include": []any{selector}}
			switch mode {
			case "extra selector":
				selector["everyone"] = map[string]any{}
			case "wrong token":
				selector["service_token"] = map[string]string{"token_id": "foreign"}
			case "bypass":
				read["decision"] = "bypass"
			case "unexpected requirement":
				read["require"] = []any{map[string]any{"everyone": map[string]any{}}}
			}
			result = read
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result, "result_info": map[string]int{"total_pages": pages}})
	}))
	defer server.Close()
	provider := &cloudflareHTTP{client: server.Client(), base: server.URL, params: Config{CloudflareAccountID: "account"}}
	policy := CFResource{Kind: "policy", Host: "app", ID: "policy", Name: "owned"}
	if err := provider.Protect(t.Context(), policy, []string{"allowed"}); err != nil {
		t.Fatal(err)
	}
	for _, testMode := range []string{"extra selector", "wrong token", "bypass", "unexpected requirement", "paged conflict"} {
		mode = testMode
		err := provider.Protect(t.Context(), policy, []string{"allowed"})
		if !errors.Is(err, ErrUnsafeProtection) && !errors.Is(err, ErrResourceConflict) {
			t.Fatal("unsafe shared policy accepted", mode, err)
		}
	}
}
