package logstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type deliveryError string

func (e deliveryError) Error() string { return string(e) }
func errorClass(err error) string {
	var classified deliveryError
	if errors.As(err, &classified) {
		return string(classified)
	}
	if errors.Is(err, httpx.ErrBlockedAddress) {
		return "blocked_address"
	}
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return "timeout"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns"
	}
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	if errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid) || errors.As(err, &record) {
		return "tls"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	return "refused"
}

type httpSink struct {
	cfg    logs.StreamsConfig
	client *http.Client
}

func newHTTPSink(cfg logs.StreamsConfig, client *http.Client) *httpSink {
	c := http.Client{}
	if client != nil {
		c = *client
	}
	var tr *http.Transport
	if c.Transport == nil {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	} else if existing, ok := c.Transport.(*http.Transport); ok {
		tr = existing.Clone()
	}
	if tr != nil {
		tr.Proxy = nil
		tr.DialContext = httpx.GuardedDialer(cfg.AllowPrivateNetworks)
		tr.DialTLS = nil
		tr.DialTLSContext = nil
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		tr.TLSClientConfig.InsecureSkipVerify = false
		tr.TLSClientConfig.ServerName = ""
		tr.TLSClientConfig.MinVersion = tls.VersionTLS12
		tr.TLSHandshakeTimeout = 10 * time.Second
		tr.ResponseHeaderTimeout = 10 * time.Second
		c.Transport = tr
	}
	// Non-Transport RoundTrippers are trusted constructor injections for tests.
	// Application wiring passes nil; environment proxy settings never apply.
	c.Timeout = 10 * time.Second
	c.Jar = nil
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &httpSink{cfg: cfg, client: &c}
}
func (s *httpSink) checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(s.cfg.AllowInsecureHTTP && u.Scheme == "http")) {
		return deliveryError("blocked_address")
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !s.cfg.AllowPrivateNetworks && !rules.PublicAddr(ip) {
		return deliveryError("blocked_address")
	}
	return nil
}
func (s *httpSink) post(ctx context.Context, endpoint string, headers http.Header, body []byte) error {
	if err := s.checkURL(endpoint); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return deliveryError("blocked_address")
	}
	req.Header = headers.Clone()
	resp, err := s.client.Do(req)
	if err != nil {
		return deliveryError(errorClass(err))
	}
	defer resp.Body.Close()
	// Neither read nor retain response bodies: they may echo credentials.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if resp.StatusCode >= 500 {
		return deliveryError("http_5xx")
	}
	if resp.StatusCode >= 400 {
		return deliveryError("http_4xx")
	}
	return deliveryError("blocked_address")
}
func (s *httpSink) Send(ctx context.Context, stream *store.LogStream, private map[string]any, items []Item) error {
	if len(items) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Scrub again at the final boundary, including registered sink credentials.
	var credentials []string
	var collect func(any)
	collect = func(v any) {
		switch x := v.(type) {
		case string:
			if x != "" {
				credentials = append(credentials, x)
			}
		case map[string]any:
			for _, v := range x {
				collect(v)
			}
		case []any:
			for _, v := range x {
				collect(v)
			}
		}
	}
	collect(private)
	scrubCtx := logscrub.WithCredentials(ctx, credentials...)
	clean := make([]Item, len(items))
	for i, item := range items {
		data, err := outgoing(scrubCtx, item.Data, nil)
		if err != nil {
			return deliveryError("refused")
		}
		clean[i] = Item{LogID: item.LogID, Data: data}
	}
	items = clean
	if stream.Type != "http" {
		return s.sendVendor(ctx, stream, private, items)
	}
	headers := http.Header{"Content-Type": []string{value(stream.Sink, "httpContentType")}}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/json")
	}
	if auth := value(private, "httpAuthorization"); auth != "" {
		headers.Set("Authorization", auth)
	}
	var custom []struct{ Header, Value string }
	raw, _ := json.Marshal(private["httpCustomHeaders"])
	if json.Unmarshal(raw, &custom) != nil {
		return deliveryError("refused")
	}
	for _, h := range custom {
		headers.Set(h.Header, h.Value)
	}
	endpoint := value(stream.Sink, "httpEndpoint")
	format := value(stream.Sink, "httpContentFormat")
	switch format {
	case "JSONARRAY":
		body, err := json.Marshal(items)
		if err != nil {
			return deliveryError("refused")
		}
		return s.post(ctx, endpoint, headers, body)
	case "JSONOBJECT":
		for _, item := range items {
			body, err := json.Marshal(item)
			if err != nil {
				return deliveryError("refused")
			}
			if err = s.post(ctx, endpoint, headers, body); err != nil {
				return err
			}
		}
		return nil
	case "", "JSONLINES":
		body, err := jsonLines(items)
		if err != nil {
			return deliveryError("refused")
		}
		return s.post(ctx, endpoint, headers, body)
	default:
		return deliveryError("refused")
	}
}
func value(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func jsonLines[T any](rows []T) ([]byte, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}
