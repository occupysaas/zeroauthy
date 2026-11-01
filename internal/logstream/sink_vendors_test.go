package logstream

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestVendorSinkShapes(t *testing.T) {
	items := []Item{{LogID: "123", Data: json.RawMessage(`{"type":"s","date":"2026-01-02T03:04:05Z","user_id":"u"}`)}, {LogID: "124", Data: json.RawMessage(`{"type":"f","date":"2026-01-02T03:04:05Z"}`)}}
	for _, typ := range []string{"datadog", "splunk", "sumo", "segment", "mixpanel"} {
		t.Run(typ, func(t *testing.T) {
			called := false
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				called = true
				b, _ := io.ReadAll(r.Body)
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
					t.Fatal(r)
				}
				switch typ {
				case "datadog":
					if r.URL.String() != "https://http-intake.logs.datadoghq.eu/api/v2/logs" || r.Header.Get("DD-API-KEY") != "dd-secret" {
						t.Fatal(r.URL, r.Header)
					}
					var rows []struct {
						Message string `json:"message"`
						Source  string `json:"ddsource"`
						Service string `json:"service"`
					}
					if json.Unmarshal(b, &rows) != nil || len(rows) != 2 || rows[0].Source != "auth0" || rows[0].Service != "zeroauthy" {
						t.Fatal(string(b))
					}
					var item Item
					if json.Unmarshal([]byte(rows[0].Message), &item) != nil || item.LogID != "123" {
						t.Fatal(rows)
					}
				case "splunk":
					if r.URL.String() != "https://splunk.example:8088/services/collector/event" || r.Header.Get("Authorization") != "Splunk splunk-secret" {
						t.Fatal(r.URL, r.Header)
					}
					d := json.NewDecoder(strings.NewReader(string(b)))
					for range 2 {
						var row struct {
							Event Item  `json:"event"`
							Time  int64 `json:"time"`
						}
						if d.Decode(&row) != nil || row.Time != 1767323045 || row.Event.LogID == "" {
							t.Fatal(string(b))
						}
					}
				case "sumo":
					if r.URL.String() != "https://sumo.example/secret-source" || strings.Count(string(b), "\n") != 2 {
						t.Fatal(r.URL, string(b))
					}
				case "segment":
					u, p, ok := r.BasicAuth()
					if r.URL.String() != "https://api.segment.io/v1/batch" || !ok || u != "write-secret" || p != "" {
						t.Fatal(r.URL, r.Header)
					}
					var row struct {
						Batch []map[string]any `json:"batch"`
					}
					if json.Unmarshal(b, &row) != nil || len(row.Batch) != 2 || row.Batch[0]["type"] != "track" || row.Batch[0]["event"] != "s" || row.Batch[0]["messageId"] != "123" || row.Batch[0]["timestamp"] != "2026-01-02T03:04:05Z" || row.Batch[0]["userId"] != "u" || row.Batch[1]["anonymousId"] != "124" {
						t.Fatal(string(b))
					}
				case "mixpanel":
					u, p, ok := r.BasicAuth()
					if r.URL.Host != "api-eu.mixpanel.com" || r.URL.Path != "/import" || r.URL.Query().Get("strict") != "1" || r.URL.Query().Get("project_id") != "42" || !ok || u != "account" || p != "mix-secret" {
						t.Fatal(r.URL, r.Header)
					}
					var rows []struct {
						Event      string         `json:"event"`
						Properties map[string]any `json:"properties"`
					}
					if json.Unmarshal(b, &rows) != nil || len(rows) != 2 || rows[0].Event != "s" || rows[0].Properties["distinct_id"] != "u" || rows[1].Properties["distinct_id"] != "124" || rows[0].Properties["$insert_id"] != "123" || rows[0].Properties["time"] != float64(1767323045) || rows[0].Properties["log_id"] != "123" {
						t.Fatal(string(b))
					}
				}
				return &http.Response{StatusCode: 202, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
			})}
			s := &store.LogStream{Type: typ, Sink: map[string]any{"datadogRegion": "eu", "splunkDomain": "splunk.example", "splunkPort": "8088", "splunkSecure": true, "mixpanelRegion": "eu", "mixpanelProjectId": "42", "mixpanelServiceAccountUsername": "account"}}
			secrets := map[string]any{"datadogApiKey": "dd-secret", "splunkToken": "splunk-secret", "sumoSourceAddress": "https://sumo.example/secret-source", "segmentWriteKey": "write-secret", "mixpanelServiceAccountPassword": "mix-secret"}
			if e := newHTTPSink(logs.StreamsConfig{}, client).Send(context.Background(), s, secrets, items); e != nil {
				t.Fatal(e)
			}
			if !called {
				t.Fatal("no vendor request")
			}
		})
	}
}

func TestHTTPSinkPolicyAndClasses(t *testing.T) {
	for _, code := range []int{200, 204, 299, 301, 400, 401, 429, 500, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "http://127.0.0.1/escape?secret=SENTINEL")
				w.WriteHeader(code)
				w.Write([]byte("SENTINEL_RESPONSE_SECRET"))
			}))
			defer server.Close()
			sink := newHTTPSink(logs.StreamsConfig{AllowInsecureHTTP: true, AllowPrivateNetworks: true}, nil)
			e := sink.Send(context.Background(), &store.LogStream{Type: "http", Sink: map[string]any{"httpEndpoint": server.URL + "/?key=SENTINEL_URL_SECRET"}}, nil, []Item{{LogID: "1", Data: json.RawMessage(`{}`)}})
			if code < 300 {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				want := "http_4xx"
				if code >= 500 {
					want = "http_5xx"
				}
				if code == 301 {
					want = "blocked_address"
				}
				if e == nil || e.Error() != want {
					t.Fatal(e)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("redirect followed", calls.Load())
			}
		})
	}
	// A private HTTPS endpoint is blocked even with trusted fixture roots. An
	// explicit private-network opt-in still verifies TLS against those roots.
	var calls atomic.Int32
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer secure.Close()
	endpoint := &store.LogStream{Type: "http", Sink: map[string]any{"httpEndpoint": secure.URL}}
	items := []Item{{LogID: "1", Data: json.RawMessage(`{}`)}}
	if e := newHTTPSink(logs.StreamsConfig{}, secure.Client()).Send(context.Background(), endpoint, nil, items); e == nil || e.Error() != "blocked_address" || calls.Load() != 0 {
		t.Fatal(e)
	}
	if e := newHTTPSink(logs.StreamsConfig{AllowPrivateNetworks: true}, secure.Client()).Send(context.Background(), endpoint, nil, items); e != nil || calls.Load() != 1 {
		t.Fatal(e)
	}
	if e := newHTTPSink(logs.StreamsConfig{AllowPrivateNetworks: true}, nil).Send(context.Background(), endpoint, nil, items); e == nil || e.Error() != "tls" {
		t.Fatal(e)
	}
	// The configured HTTP transport's proxy cannot route a nominally public
	// endpoint around the address policy.
	proxyCalled := false
	client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { proxyCalled = true; return url.Parse(secure.URL) }}}
	sink := newHTTPSink(logs.StreamsConfig{}, client)
	transport := sink.client.Transport.(*http.Transport)
	if transport.Proxy != nil || proxyCalled {
		t.Fatal("proxy retained")
	}
	for _, raw := range []string{"http://public.example/", "https://127.0.0.1/", "https://10.0.0.1/", "https://100.64.0.1/", "https://user:secret@example.com/", "https://example.com/#fragment", "https://[::1]/"} {
		if e := sink.checkURL(raw); e == nil || e.Error() != "blocked_address" {
			t.Fatal(raw, e)
		}
	}
}
func TestDeliveryErrorClasses(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "timeout"}, {&net.DNSError{Err: "SENTINEL_DNS", Name: "secret.example"}, "dns"}, {syscall.ECONNREFUSED, "refused"}, {httpx.ErrBlockedAddress, "blocked_address"}, {tls.RecordHeaderError{}, "tls"}, {errors.New("https://secret.example/?key=SENTINEL"), "refused"},
	} {
		if got := errorClass(tc.err); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
}
