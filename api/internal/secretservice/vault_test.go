package secretservice

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
)

func TestRealVaultTransit(t *testing.T) {
	addr := os.Getenv("TEST_VAULT_URL")
	if addr == "" {
		t.Skip("set TEST_VAULT_URL to an isolated dev Vault")
	}
	token := "cc-disposable-test"
	req, _ := http.NewRequest("POST", addr+"/v1/sys/mounts/transit", bytes.NewBufferString(`{"type":"transit"}`))
	req.Header.Set("X-Vault-Token", token)
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 204 && res.StatusCode != 400 {
		t.Fatal(res.StatusCode)
	}
	s := New(nil, Config{VaultURL: addr, VaultToken: token})
	key := bytes.Repeat([]byte{17}, 32)
	wrapped, e := s.Transit.Wrap(context.Background(), testOwner, key)
	if e != nil {
		t.Fatal(e)
	}
	plain, e := s.Transit.Unwrap(context.Background(), testOwner, wrapped)
	if e != nil || !bytes.Equal(plain, key) {
		t.Fatal(e)
	}
	if _, e = s.Transit.Unwrap(context.Background(), "22222222-2222-4222-8222-222222222222", wrapped); e == nil {
		t.Fatal("cross-owner unwrap accepted")
	}
	req, _ = http.NewRequest("GET", addr+"/v1/transit/keys/operator-"+testOwner, nil)
	req.Header.Set("X-Vault-Token", token)
	res, e = http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	var v struct {
		Data struct {
			Type       string `json:"type"`
			Exportable bool   `json:"exportable"`
			Derived    bool   `json:"derived"`
			Convergent bool   `json:"convergent_encryption"`
		} `json:"data"`
	}
	if json.NewDecoder(res.Body).Decode(&v) != nil || v.Data.Type != "aes256-gcm96" || v.Data.Exportable || v.Data.Derived || v.Data.Convergent {
		t.Fatal("unexpected key configuration", v.Data)
	}
}
