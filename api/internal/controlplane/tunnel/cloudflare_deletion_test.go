package tunnel

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDeletedTunnelTombstoneAllowsEnrollmentRecovery(t *testing.T) {
	now := time.Now().UTC()
	want := CFResource{Kind: "tunnel", ID: "old", Name: "owned-enrollment-tunnel", Watch: true}
	object := cfObject{ID: want.ID, Name: want.Name, DeletedAt: &now}
	var listed []cfObject
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result any = object
		if r.URL.Query().Get("is_deleted") == "false" {
			result = listed
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer server.Close()
	provider := &cloudflareHTTP{client: server.Client(), base: server.URL}
	if found, err := provider.FindOwned(t.Context(), want); err != nil || len(found) != 0 {
		t.Fatal("provider tombstone blocked predecessor cleanup", found, err)
	}
	listed = []cfObject{{ID: "late", Name: want.Name, ConfigSrc: "cloudflare"}}
	if found, err := provider.FindOwned(t.Context(), want); err != nil || len(found) != 1 || found[0].ID != "late" {
		t.Fatal("tombstone hid a late active resource", found, err)
	}
	object.Name = "foreign"
	if _, err := provider.FindOwned(t.Context(), want); !errors.Is(err, ErrResourceConflict) {
		t.Fatal("foreign tombstone accepted", err)
	}
	object.Name, object.DeletedAt = want.Name, nil
	if _, err := provider.FindOwned(t.Context(), want); !errors.Is(err, ErrResourceConflict) {
		t.Fatal("active tunnel lost ownership protection", err)
	}
}
