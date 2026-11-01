package eventstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func webhookClient(cfg events.Config, supplied *http.Client) *http.Client {
	var client http.Client
	if supplied != nil {
		client = *supplied
	}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if t, ok := transport.(*http.Transport); ok {
		t = t.Clone()
		// Proxies and custom TLS dialers must not bypass the resolved-address guard.
		t.Proxy = nil
		t.DialContext = httpx.GuardedDialer(cfg.AllowPrivateNetworks)
		t.DialTLSContext = nil
		t.DialTLS = nil
		t.TLSHandshakeTimeout = 10 * time.Second
		transport = t
	}
	client.Transport = transport
	client.Timeout = 10 * time.Second
	client.Jar = nil
	// Even same-host redirects can forward custom credentials to another path;
	// refusing every redirect also removes redirect-based SSRF.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

func (w *Worker) webhook(ctx context.Context, s *store.EventStream, private map[string]any, body []byte) (string, bool) {
	endpoint, _ := s.Config["webhook_endpoint"].(string)
	if !validEndpoint(endpoint, w.cfg.AllowInsecureHTTP) {
		return "connection_error", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "connection_error", false
	}
	req.Header.Set("Content-Type", "application/json")
	auth, _ := s.Config["webhook_authorization"].(map[string]any)
	method, _ := auth["method"].(string)
	switch method {
	case "basic":
		username, _ := auth["username"].(string)
		password, _ := private["password"].(string)
		req.SetBasicAuth(username, password)
	case "bearer":
		token, _ := private["token"].(string)
		req.Header.Set("Authorization", "Bearer "+token)
	case "custom_header":
		key, _ := auth["header_key"].(string)
		value, _ := private["header_value"].(string)
		if key == "" || reservedHeader(key) {
			return "connection_error", false
		}
		req.Header.Set(key, value)
	default:
		return "connection_error", false
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return transportError(err), false
	}
	// Do not read response bodies: neither unbounded bodies nor receiver secrets
	// belong in delivery diagnostics. Closing also interrupts a streaming body.
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return "", true
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return fmt.Sprintf("http_4xx: %d", resp.StatusCode), true
	case resp.StatusCode >= 500 && resp.StatusCode < 600:
		return fmt.Sprintf("http_5xx: %d", resp.StatusCode), false
	default:
		return "connection_error", false
	}
}

func transportError(err error) string {
	if errors.Is(err, httpx.ErrBlockedAddress) {
		return "blocked_address"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	var header tls.RecordHeaderError
	if errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &verification) || errors.As(err, &header) {
		return "tls"
	}
	return "connection_error"
}
