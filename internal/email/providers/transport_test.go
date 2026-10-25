package providers

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProviderProtocols(t *testing.T) {
	cases := []string{"smtp", "sendgrid", "mailgun", "mandrill", "sparkpost", "ses", "azure_cs", "ms365", "resend"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := (&Factory{}).New(context.Background(), "tenant-a", 1, Config{Name: name}); err == nil {
				t.Fatal("incomplete provider credentials accepted")
			}
		})
	}
	if _, err := (&Factory{}).New(context.Background(), "tenant-a", 1, Config{Name: "custom"}); err == nil {
		t.Fatal("custom provider is stored-only")
	}
	for _, cfg := range []Config{{Name: "mailgun", Credentials: map[string]any{"api_key": "k", "domain": "mg.example.test/path"}}, {Name: "mailgun", Credentials: map[string]any{"api_key": "k", "domain": "mg.example.test", "region": "us"}}, {Name: "sparkpost", Credentials: map[string]any{"api_key": "k", "region": "eu.attacker"}}, {Name: "azure_cs", Credentials: map[string]any{"connectionString": "Endpoint=https://attacker.invalid;AccessKey=YQ=="}}} {
		if _, err := (&Factory{}).New(context.Background(), "tenant", 1, cfg); err == nil {
			t.Errorf("unsafe config accepted: %+v", cfg)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func protocolConfig(name string) Config {
	c := Config{Name: name, Credentials: map[string]any{}, Settings: map[string]any{}}
	switch name {
	case "smtp":
		c.Credentials = map[string]any{"smtp_host": "smtp.example.test", "smtp_port": 587, "smtp_user": "user", "smtp_pass": "pw"}
	case "sendgrid", "mandrill", "resend":
		c.Credentials["api_key"] = "api-key"
	case "sparkpost":
		c.Credentials = map[string]any{"api_key": "api-key", "region": "eu"}
	case "mailgun":
		c.Credentials = map[string]any{"api_key": "api-key", "domain": "mg.example.test", "region": "eu"}
	case "ses":
		c.Credentials = map[string]any{"accessKeyId": "AKIDEXAMPLE", "secretAccessKey": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "region": "us-east-1"}
	case "azure_cs":
		c.Credentials["connectionString"] = "endpoint=https://resource.communication.azure.com;accesskey=" + base64.StdEncoding.EncodeToString([]byte("azure-key"))
	case "ms365":
		c.Credentials = map[string]any{"tenantId": "11111111-1111-1111-1111-111111111111", "clientId": "22222222-2222-2222-2222-222222222222", "clientSecret": "secret"}
	}
	return c
}
func TestProviderHTTPProtocols(t *testing.T) {
	names := []string{"sendgrid", "mailgun", "mandrill", "sparkpost", "resend", "ses", "azure_cs", "ms365"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var requests []*http.Request
			var bodies [][]byte
			tokenRequests := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				raw, _ := io.ReadAll(req.Body)
				mu.Lock()
				defer mu.Unlock()
				requests = append(requests, req.Clone(req.Context()))
				bodies = append(bodies, raw)
				if strings.Contains(req.URL.Host, "login.microsoftonline.com") {
					tokenRequests++
					return response(200, `{"access_token":"token-1","expires_in":3600}`), nil
				}
				switch name {
				case "sendgrid", "azure_cs", "ms365":
					return response(202, ""), nil
				case "ses":
					return response(200, "{}"), nil
				case "mandrill":
					return response(200, `[{"status":"sent"}]`), nil
				case "sparkpost":
					return response(200, `{"results":{"total_accepted_recipients":1}}`), nil
				default:
					return response(200, `{"id":"accepted"}`), nil
				}
			})}
			f := &Factory{HTTPClient: client, Now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }}
			tr, err := f.New(context.Background(), "tenant-a", 1, protocolConfig(name))
			if err != nil {
				t.Fatal(err)
			}
			msg := Message{From: "sender@example.test", To: "person@example.test", Subject: "Hello", Text: "plain", HTML: "<b>html</b>"}
			if err = tr.Send(context.Background(), msg); err != nil {
				t.Fatal(err)
			}
			if name == "ms365" {
				if len(requests) != 2 || tokenRequests != 1 {
					t.Fatalf("requests=%d tokenRequests=%d", len(requests), tokenRequests)
				}
				if requests[1].URL.Host != "graph.microsoft.com" || requests[1].Header.Get("Authorization") != "Bearer token-1" || !strings.Contains(requests[1].URL.Path, "sender@example.test") {
					t.Fatalf("Graph request=%v", requests[1])
				}
				for _, want := range []string{"person@example.test", "Hello", "html"} {
					if !strings.Contains(string(bodies[1]), want) {
						t.Errorf("Graph payload missing %q: %s", want, bodies[1])
					}
				}
				return
			}
			if len(requests) != 1 {
				t.Fatalf("requests=%d", len(requests))
			}
			req := requests[0]
			for _, want := range []string{"sender@example.test", "person@example.test", "Hello", "plain", "html"} {
				if !strings.Contains(string(bodies[0]), want) {
					t.Errorf("%s payload does not contain %q: %s", name, want, bodies[0])
				}
			}
			var payload map[string]any
			_ = json.Unmarshal(bodies[0], &payload)
			switch name {
			case "sendgrid":
				if req.Header.Get("Authorization") != "Bearer api-key" || req.URL.Path != "/v3/mail/send" || payload["personalizations"] == nil || payload["content"] == nil {
					t.Fatalf("SendGrid wire=%v %s", req.Header, payload)
				}
			case "mailgun":
				u, p, ok := req.BasicAuth()
				if u != "api" || p != "api-key" || !ok || req.URL.Host != "api.eu.mailgun.net" || !strings.Contains(string(bodies[0]), `name="subject"`) || !strings.Contains(string(bodies[0]), "Hello") {
					t.Fatalf("Mailgun wire %v %q", req, u)
				}
			case "mandrill":
				if req.URL.Path != "/api/1.0/messages/send.json" || payload["key"] != "api-key" || payload["message"] == nil {
					t.Fatalf("Mandrill wire %q %v", req.URL.Path, payload)
				}
			case "sparkpost":
				if req.Header.Get("Authorization") != "api-key" || req.URL.Host != "api.eu.sparkpost.com" || payload["recipients"] == nil {
					t.Fatalf("SparkPost wire %v %v", req.Header, payload)
				}
			case "resend":
				if req.Header.Get("Authorization") != "Bearer api-key" || req.URL.Path != "/emails" || payload["to"] == nil {
					t.Fatalf("Resend wire %v %v", req.Header, payload)
				}
			case "ses":
				if !strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") || req.Header.Get("X-Amz-Date") != "20260102T030405Z" || payload["Destination"] == nil {
					t.Fatalf("SES signing/payload=%v %v", req.Header, payload)
				}
			case "azure_cs":
				hash := sha256.Sum256(bodies[0])
				contentHash := base64.StdEncoding.EncodeToString(hash[:])
				signing := "POST\n" + req.URL.EscapedPath() + "?" + req.URL.RawQuery + "\n" + req.Header.Get("x-ms-date") + ";" + req.URL.Host + ";" + contentHash
				key, _ := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString([]byte("azure-key")))
				mac := hmac.New(sha256.New, key)
				_, _ = mac.Write([]byte(signing))
				expected := "HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
				if req.Header.Get("Authorization") != expected || req.URL.Path != "/emails:send" || req.URL.Query().Get("api-version") != "2023-03-31" || payload["senderAddress"] != "sender@example.test" {
					t.Fatalf("Azure wire %v %v", req.URL, payload)
				}
			}
		})
	}
}

func TestSESSigV4ReferenceVector(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	const stringToSign = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
	date := signHMAC([]byte("AWS4"+secret), "20150830")
	region := signHMAC(date, "us-east-1")
	service := signHMAC(region, "iam")
	key := signHMAC(service, "aws4_request")
	signature := hex.EncodeToString(signHMAC(key, stringToSign))
	if signature != "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7" {
		t.Fatalf("SigV4 reference signature=%s", signature)
	}
}

func TestOutboundPolicy(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "localhost"} {
		if isPublicAddress(host) {
			t.Errorf("private or metadata address accepted: %s", host)
		}
	}
	for _, host := range []string{"192.0.2.1", "2001:db8::1"} {
		if isPublicAddress(host) {
			t.Errorf("documentation-only address accepted as routable: %s", host)
		}
	}
	if resolvedAddressesAllowed([]net.IPAddr{{IP: netip.MustParseAddr("1.1.1.1").AsSlice()}, {IP: netip.MustParseAddr("127.0.0.1").AsSlice()}}, false) {
		t.Fatal("mixed public/private DNS answers passed (rebinding risk)")
	}
	if !resolvedAddressesAllowed([]net.IPAddr{{IP: netip.MustParseAddr("127.0.0.1").AsSlice()}}, true) {
		t.Fatal("explicit local relay exception not honored")
	}
}

func TestProviderAcceptanceAndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{{"mandrill", `[{"status":"rejected"}]`, false}, {"mandrill", `[{"status":"sent"}]`, true}, {"sparkpost", `{"results":{"total_accepted_recipients":0}}`, false}, {"sparkpost", `{"results":{"total_accepted_recipients":1}}`, true}} {
		if got := acceptedResponse(tc.name, 200, []byte(tc.body)); got != tc.want {
			t.Errorf("%s accepted=%v, want %v", tc.name, got, tc.want)
		}
	}
	secret := "SENTINEL_API_SECRET"
	f := &Factory{HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(401, strings.Repeat(secret, 10000)), nil })}}
	tr, err := f.New(context.Background(), "t", 1, Config{Name: "sendgrid", Credentials: map[string]any{"api_key": secret}})
	if err != nil {
		t.Fatal(err)
	}
	err = tr.Send(context.Background(), Message{From: "a@example.test", To: "b@example.test", Subject: "x", Text: "body"})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("secret leaked in error %v", err)
	}
	tooLarge := &Factory{HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(400, strings.Repeat("x", responseLimit+1)), nil
	})}}
	tr, _ = tooLarge.New(context.Background(), "t", 1, Config{Name: "sendgrid", Credentials: map[string]any{"api_key": "secret"}})
	if err = tr.Send(context.Background(), Message{From: "a@example.test", To: "b@example.test", Subject: "x", Text: "body"}); err == nil || !strings.Contains(err.Error(), "response exceeded limit") {
		t.Fatalf("oversized response error=%v", err)
	}
}

func TestProviderNoRetryOrRedirect(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://attacker.invalid/collect"}}, Body: io.NopCloser(strings.NewReader("SENTINEL"))}, nil
	})}
	tr, err := (&Factory{HTTPClient: client}).New(context.Background(), "tenant", 1, Config{Name: "resend", Credentials: map[string]any{"api_key": "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	err = tr.Send(context.Background(), Message{From: "from@example.test", To: "to@example.test", Subject: "test", Text: "body"})
	if err == nil || calls != 1 || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("redirect behavior calls=%d err=%v", calls, err)
	}
	calls = 0
	client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return response(500, "failed"), nil })}
	tr, _ = (&Factory{HTTPClient: client}).New(context.Background(), "tenant", 1, Config{Name: "resend", Credentials: map[string]any{"api_key": "secret"}})
	_ = tr.Send(context.Background(), Message{From: "from@example.test", To: "to@example.test", Subject: "test", Text: "body"})
	if calls != 1 {
		t.Fatalf("transport retried uncertain request %d times", calls)
	}
	calls = 0
	client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, io.ErrUnexpectedEOF })}
	tr, _ = (&Factory{HTTPClient: client}).New(context.Background(), "tenant", 1, Config{Name: "resend", Credentials: map[string]any{"api_key": "secret"}})
	_ = tr.Send(context.Background(), Message{From: "from@example.test", To: "to@example.test", Subject: "test", Text: "body"})
	if calls != 1 {
		t.Fatalf("transport retried uncertain disconnect %d times", calls)
	}
}

func TestSlowCancelledAndTLSMismatch(t *testing.T) {
	waiter := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })}
	tr, _ := (&Factory{HTTPClient: waiter}).New(context.Background(), "t", 1, Config{Name: "resend", Credentials: map[string]any{"api_key": "secret"}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := tr.Send(ctx, Message{From: "a@example.test", To: "b@example.test", Subject: "x", Text: "body"})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("cancelled request error=%v", err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dialer := &net.Dialer{}
	httpTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}}
	client := &http.Client{Transport: httpTransport}
	tr, _ = (&Factory{HTTPClient: client}).New(context.Background(), "t", 1, Config{Name: "resend", Credentials: map[string]any{"api_key": "secret"}})
	err = tr.Send(context.Background(), Message{From: "a@example.test", To: "b@example.test", Subject: "x", Text: "body"})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("TLS mismatch error=%v", err)
	}
}

func TestMS365TokenCacheIdentity(t *testing.T) {
	var mu sync.Mutex
	tokens := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if strings.Contains(r.URL.Host, "login.microsoftonline.com") {
			tokens++
			return response(200, `{"access_token":"token","expires_in":3600}`), nil
		}
		return response(202, ""), nil
	})}
	f := &Factory{HTTPClient: client}
	cfg := protocolConfig("ms365")
	m := Message{From: "sender@example.test", To: "to@example.test", Subject: "x", Text: "body"}
	for _, id := range []struct {
		tenant string
		rev    int64
	}{{"t", 1}, {"t", 1}, {"t", 2}, {"other", 1}} {
		tr, err := f.New(context.Background(), id.tenant, id.rev, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err = tr.Send(context.Background(), m); err != nil {
			t.Fatal(err)
		}
	}
	cfg.Credentials["clientSecret"] = "rotated-secret"
	tr, err := f.New(context.Background(), "t", 1, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if tokens != 4 {
		t.Fatalf("token requests=%d, want 4 isolated identities", tokens)
	}
}

func TestSMTPRequiresTLSAndExplicitLocalAllowlist(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "220 local test\r\n")
		line, _ := bufio.NewReader(conn).ReadString('\n')
		if strings.HasPrefix(strings.ToUpper(line), "EHLO ") {
			_, _ = io.WriteString(conn, "250 local test\r\n")
			time.Sleep(100 * time.Millisecond)
		}
	}()
	addr := listener.Addr().String()
	target, err := (&Factory{}).New(context.Background(), "tenant", 1, Config{Name: "smtp", Credentials: map[string]any{"smtp_host": "127.0.0.1", "smtp_port": mustPort(t, addr)}})
	if err != nil {
		t.Fatal(err)
	}
	msg := Message{From: "from@example.test", To: "to@example.test", Subject: "test", Text: "body"}
	err = target.Send(context.Background(), msg)
	if err == nil {
		t.Fatalf("public default SMTP policy error=%v", err)
	}
	target, err = (&Factory{LocalSMTPAllowlist: []string{addr}}).New(context.Background(), "tenant", 1, Config{Name: "smtp", Credentials: map[string]any{"smtp_host": "127.0.0.1", "smtp_port": mustPort(t, addr)}})
	if err != nil {
		t.Fatal(err)
	}
	err = target.Send(context.Background(), msg)
	if err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Fatalf("allowlisted SMTP without TLS error=%v", err)
	}
	<-done
}
func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
