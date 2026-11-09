package nodeproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/livepeer/control-center/runtime/contract"
)

const template = "https://{proxy}.lp-aaaaaaaaaaaaaaaa.example.invalid"

func TestAuthorityAndCredentialBoundary(t *testing.T) {
	var forwarded *http.Request
	handler, err := Handler(template, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = r; w.WriteHeader(204) }))
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{
		"app-valid.lp-aaaaaaaaaaaaaaaa.example.invalid", "APP-VALID.lp-aaaaaaaaaaaaaaaa.example.invalid",
		strings.TrimPrefix(contract.PrivateOrchestrator, "http://"),
		"api.lp-aaaaaaaaaaaaaaaa.example.invalid", "discovery.lp-aaaaaaaaaaaaaaaa.example.invalid",
		"api-wrong.lp-aaaaaaaaaaaaaaaa.example.invalid:443", "discovery-wrong.lp-aaaaaaaaaaaaaaaa.example.invalid",
		"app-valid.lp-aaaaaaaaaaaaaaaa.example.invalid:443", "app-valid.lp-aaaaaaaaaaaaaaaa.example.invalid.",
		"nested.app-valid.lp-aaaaaaaaaaaaaaaa.example.invalid", "-invalid.lp-aaaaaaaaaaaaaaaa.example.invalid", "foreign.invalid",
	} {
		forwarded = nil
		req := httptest.NewRequest("GET", "https://"+host+"/apps/app/app/a%2Fb?value=1%202&value=3", nil)
		req.Header = http.Header{"cf-access-client-secret": {"secret"}, "Cf-Access-Jwt-Assertion": {"jwt"}, "Authorization": {"Bearer app"}, "X-Livepeer-Payment": {"payment"}, "Cookie": {"CF_Authorization=edge; session=app; cf_authorization=duplicate"}}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		allowed := strings.HasPrefix(strings.ToLower(host), "app-valid.") && !strings.Contains(host, ":") && !strings.HasSuffix(host, ".") || host == strings.TrimPrefix(contract.PrivateOrchestrator, "http://")
		if !allowed {
			if forwarded != nil || w.Code != 404 {
				t.Fatal("unsafe authority forwarded", host, w.Code)
			}
			continue
		}
		if forwarded == nil || forwarded.Host != strings.ToLower(host) || forwarded.URL.RawPath != "/apps/app/app/a%2Fb" || forwarded.URL.RawQuery != "value=1%202&value=3" {
			t.Fatal("routing changed", host, forwarded)
		}
		for name := range forwarded.Header {
			if strings.HasPrefix(strings.ToLower(name), "cf-access-") {
				t.Fatal("Access header leaked", name)
			}
		}
		if strings.TrimSpace(forwarded.Header.Get("Cookie")) != "session=app" || forwarded.Header.Get("Authorization") != "Bearer app" || forwarded.Header.Get("X-Livepeer-Payment") != "payment" {
			t.Fatal("application credentials changed", forwarded.Header)
		}
		if req.Header.Get("Cookie") != "CF_Authorization=edge; session=app; cf_authorization=duplicate" {
			t.Fatal("handler mutated original headers")
		}
	}
}

func TestApplicationCookiesRemainVerbatim(t *testing.T) {
	unusual := `a[b]=1; json={"a":1}; utf8=é; spaces=a b; commas=a,b`
	many := strings.Repeat("app=value;", 4000)
	for _, check := range []struct{ input, want []string }{
		{[]string{unusual, many}, []string{unusual, many}},
		{[]string{"CF_Authorization=edge; " + unusual, "app=one; cf_authorization=second; other=two"}, []string{" " + unusual, "app=one; other=two"}},
		{[]string{"CF_Authorization=edge", "cf_authorization=second"}, nil},
	} {
		var received []string
		handler, err := Handler(template, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { received = r.Header.Values("Cookie") }))
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", "https://app-valid.lp-aaaaaaaaaaaaaaaa.example.invalid/", nil)
		req.Header["Cookie"] = check.input
		handler.ServeHTTP(httptest.NewRecorder(), req)
		if !reflect.DeepEqual(received, check.want) || !reflect.DeepEqual(req.Header.Values("Cookie"), check.input) {
			t.Fatal("application cookie bytes changed or original headers were mutated")
		}
	}
}

func TestReverseProxyStreamingAndUpgrade(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/discovery" {
			if r.Host != strings.TrimPrefix(contract.PrivateOrchestrator, "http://") {
				t.Error("identity check used public Host")
			}
			_ = json.NewEncoder(w).Encode([]map[string]string{{"address": "https://api-aaaaaaa.lp-aaaaaaaaaaaaaaaa.example.invalid"}})
			return
		}
		if r.Host != "app-valid.lp-aaaaaaaaaaaaaaaa.example.invalid" {
			t.Error("proxy Host was not preserved", r.Host)
		}
		switch r.URL.Path {
		case "/stream":
			_, _ = io.WriteString(w, "first\n")
			w.(http.Flusher).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			_, _ = io.WriteString(w, "last\n")
		case "/upgrade":
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			_ = rw.Flush()
			data := make([]byte, 4)
			if _, err := io.ReadFull(rw, data); err != nil {
				t.Error(err)
				return
			}
			_, _ = rw.Write(data)
			_ = rw.Flush()
		default:
			_, _ = io.WriteString(w, r.RequestURI)
		}
	}))
	defer upstream.Close()
	transport := nodeTransport("https://api-aaaaaaa.lp-aaaaaaaaaaaaaaaa.example.invalid", func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != strings.TrimPrefix(contract.PrivateOrchestrator, "http://") {
			t.Error("unexpected upstream", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(upstream.URL, "http://"))
	})
	defer transport.CloseIdleConnections()
	handler, err := Handler(template, reverseProxy(transport))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Timeout: 3 * time.Second}
	request := func(path string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("GET", server.URL+path, nil)
		req.Host = "app-valid.lp-aaaaaaaaaaaaaaaa.example.invalid"
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response := request("/a%2Fb?value=1%202&value=3")
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(data) != "/a%2Fb?value=1%202&value=3" {
		t.Fatal("request target changed", string(data))
	}
	response = request("/stream")
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	close(release)
	_ = response.Body.Close()
	if err != nil || line != "first\n" {
		t.Fatal("stream was buffered", line, err)
	}
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(conn, "GET /upgrade HTTP/1.1\r\nHost: app-valid.lp-aaaaaaaaaaaaaaaa.example.invalid\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	reader := bufio.NewReader(conn)
	upgraded, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil || upgraded.StatusCode != 101 {
		t.Fatal("upgrade failed", upgraded, err)
	}
	_, _ = io.WriteString(conn, "ping")
	data = make([]byte, 4)
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "ping" {
		t.Fatal("upgraded stream failed", string(data), err)
	}
}

func TestNodeIdentityVerifiedOnEveryConnection(t *testing.T) {
	for _, expected := range []string{"a", "b"} {
		t.Run(expected, func(t *testing.T) {
			var callsA, callsB atomic.Int32
			upstream := func(id string, calls *atomic.Int32) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/discovery" {
						_ = json.NewEncoder(w).Encode([]map[string]string{{"address": "https://api-aaaaaaa.lp-node." + id + ".invalid"}})
						return
					}
					calls.Add(1)
					w.WriteHeader(204)
				}))
			}
			a, b := upstream("a", &callsA), upstream("b", &callsB)
			defer a.Close()
			defer b.Close()
			matching, other := a, b
			if expected == "b" {
				matching, other = b, a
			}
			var destination atomic.Value
			destination.Store(other.URL)
			transport := nodeTransport("https://api-aaaaaaa.lp-node."+expected+".invalid", func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(destination.Load().(string), "http://"))
			})
			defer transport.CloseIdleConnections()
			handler, err := Handler("https://{proxy}.lp-node."+expected+".invalid", reverseProxy(transport))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			call := func(want int) {
				t.Helper()
				req, _ := http.NewRequestWithContext(t.Context(), "POST", server.URL+"/apps/app-fixture/session", nil)
				req.Host = "app-fixture.lp-node." + expected + ".invalid"
				response, err := server.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != want {
					t.Fatal("unexpected routing result", response.StatusCode, want)
				}
			}
			call(502)
			if callsA.Load()+callsB.Load() != 0 {
				t.Fatal("application bytes reached mismatched Node")
			}
			destination.Store(matching.URL)
			call(204)
			matching.CloseClientConnections()
			transport.CloseIdleConnections()
			destination.Store(other.URL)
			call(502)
			if callsA.Load()+callsB.Load() != 1 {
				t.Fatal("replacement connection skipped identity verification")
			}
		})
	}
}

func TestPrivateHeldConfigurationRejectsApplicationHosts(t *testing.T) {
	handler, err := Handler("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"app-valid.lp-node.example.invalid", strings.TrimPrefix(contract.PrivateOrchestrator, "http://")} {
		req := httptest.NewRequest("GET", "http://"+host+"/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		want := 404
		if host == strings.TrimPrefix(contract.PrivateOrchestrator, "http://") {
			want = 204
		}
		if w.Code != want {
			t.Fatal("private-only guard admitted application traffic", host, w.Code)
		}
	}
}

func TestNodeHandshakeRejectsInvalidOrUnboundedResponses(t *testing.T) {
	for _, body := range []string{"[]", `[{"address":"wrong"}]`, `[{"address":"expected"},{"address":"expected"}]`, `[{"address":`, strings.Repeat(" ", 1<<20) + "[]"} {
		var calls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/discovery" {
				_, _ = io.WriteString(w, body)
				return
			}
			calls.Add(1)
		}))
		transport := nodeTransport("expected", func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(upstream.URL, "http://"))
		})
		req, _ := http.NewRequestWithContext(t.Context(), "POST", contract.PrivateOrchestrator+"/apps/app/session", nil)
		response, err := transport.RoundTrip(req)
		if response != nil {
			_ = response.Body.Close()
		}
		transport.CloseIdleConnections()
		upstream.Close()
		if err == nil || calls.Load() != 0 {
			t.Fatal("invalid identity response allowed application bytes")
		}
	}
	client, server := net.Pipe()
	defer server.Close()
	transport := nodeTransport("expected", func(context.Context, string, string) (net.Conn, error) { return client, nil })
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := transport.DialContext(ctx, "tcp", "node.invalid:8935")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("stalled identity check exceeded its deadline", err)
	}
}
