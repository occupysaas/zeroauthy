package customdomain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

const (
	probeDeadline = 10 * time.Second
	probeMaxBytes = 64 << 10
	probeMaxAddrs = 2
)

// ErrDiagnosticUnavailable is an infrastructure failure (503), as opposed to
// an observed failure, which is a Diagnostic with Success false.
var ErrDiagnosticUnavailable = errors.New("customdomain: the domain test could not run")

// Diagnostic is the outcome of the bounded discovery probe. Success means this
// probe passed, not that every proxy or SDK configuration works.
type Diagnostic struct {
	Success bool
	Message string
}

// ProbeDeps are constructor dependencies of the probe. Production leaves them
// zero (system roots, a plain dialer, ten seconds); tests inject a dialer that
// maps a validated public address to a local fixture. There is no
// deployment or tenant option that disables address validation.
type ProbeDeps struct {
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	RootCAs *x509.CertPool
	Timeout time.Duration
}

// NewServiceWithProbe is NewService with explicit probe dependencies.
func NewServiceWithProbe(st store.Store, resolver DNSResolver, cfg ServiceConfig, clock func() time.Time, random io.Reader, probe ProbeDeps) *Service {
	s := NewService(st, resolver, cfg, clock, random)
	s.probe = probe
	return s
}

// Test diagnoses a ready domain without changing ownership, default or key
// state. It shares the verification attempt budget.
func (s *Service) Test(ctx context.Context, tenantID, id string) (Diagnostic, error) {
	d, err := s.st.CustomDomains().Get(ctx, tenantID, id)
	if err != nil {
		return Diagnostic{}, err
	}
	usable, err := ServingUsable(ctx, s.st, d, s.clock())
	if err != nil {
		return Diagnostic{}, err
	}
	if !usable {
		return Diagnostic{}, ErrNotReady
	}
	retry, err := s.st.CustomDomains().AdmitAttempt(ctx, tenantID, id)
	if err != nil {
		return Diagnostic{}, err
	}
	if retry > 0 {
		return Diagnostic{}, &RateLimitError{RetryAfter: retry}
	}
	timeout := s.probe.Timeout
	if timeout <= 0 {
		timeout = probeDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := s.resolver.LookupNetIP(ctx, "ip", d.Domain)
	switch {
	case errors.Is(err, ErrDNSNotFound) || errors.Is(err, ErrDNSLimit):
		return failed("the domain has no usable address records"), nil
	case err != nil:
		return Diagnostic{}, fmt.Errorf("%w: %v", ErrDiagnosticUnavailable, err)
	case len(addrs) > probeMaxAddrs:
		return failed("the domain resolves to more than two addresses"), nil
	}
	for _, a := range addrs {
		if !globallyRoutable(a) {
			return failed("the domain resolves to an address that is not publicly routable"), nil
		}
	}
	var last string
	for _, a := range addrs {
		diag := s.fetch(ctx, d.Domain, a)
		if diag.Success {
			return diag, nil
		}
		last = diag.Message
	}
	return failed(last), nil
}

func failed(msg string) Diagnostic { return Diagnostic{Message: msg} }

// fetch requests discovery over a connection pinned to addr, with the domain
// as SNI and Host, no proxy and no redirects.
func (s *Service) fetch(ctx context.Context, domain string, addr netip.Addr) Diagnostic {
	pinned := net.JoinHostPort(addr.String(), "443")
	dial := s.probe.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, network, pinned)
		},
		TLSClientConfig:        &tls.Config{ServerName: domain, RootCAs: s.probe.RootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: probeMaxBytes,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	origin := "https://" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/.well-known/openid-configuration", nil)
	if err != nil {
		return failed("the discovery request could not be built")
	}
	resp, err := client.Do(req)
	if err != nil {
		var certErr *tls.CertificateVerificationError
		switch {
		case errors.As(err, &certErr):
			return failed("the domain's TLS certificate is not trusted for this name")
		case errors.Is(err, context.DeadlineExceeded):
			return failed("the discovery request timed out")
		}
		return failed("the domain could not be reached over HTTPS")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return failed(fmt.Sprintf("discovery answered HTTP %d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, probeMaxBytes+1))
	if err != nil {
		return failed("the discovery response could not be read")
	}
	if len(body) > probeMaxBytes {
		return failed("the discovery response is larger than 64 KiB")
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return failed("the discovery response is not JSON")
	}
	if iss, _ := doc["issuer"].(string); iss != origin+"/" {
		return failed("the discovery issuer does not match the domain")
	}
	for _, field := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		raw, _ := doc[field].(string)
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host != domain {
			return failed("the discovery " + field + " is not on the domain")
		}
	}
	return Diagnostic{Success: true, Message: "the domain served discovery for its issuer"}
}

var reserved = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// globallyRoutable rejects private, loopback, link-local, multicast,
// unspecified, documentation and translation ranges, including IPv4-mapped
// forms of any of them.
func globallyRoutable(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.Zone() != "" || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() ||
		a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
