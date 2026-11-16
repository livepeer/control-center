package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIngressAuthCommandKeepsServingUntilShutdown(t *testing.T) {
	file := filepath.Join(t.TempDir(), "public.json")
	if err := os.WriteFile(file, []byte(`{"test":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`), 0600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"ingress-auth", "--listen", address, "--public-keys-file", file, "--node-id", "vkvkvkvkvkvkuaaaaaaaaaaaaa"})
	}()
	t.Cleanup(cancel)
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Timeout: time.Second, Transport: transport}
	for deadline := time.Now().Add(3 * time.Second); ; {
		res, err := client.Get("http://" + address + "/readyz")
		if err == nil {
			res.Body.Close()
			if res.StatusCode != 204 {
				t.Fatal(res.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener did not start", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for range 3 {
		res, err := client.Get("http://" + address + "/authorize")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Fatal("missing bearer accepted", res.StatusCode)
		}
		select {
		case err := <-done:
			t.Fatal("service exited between requests", err)
		default:
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener failed to shut down")
	}
}
