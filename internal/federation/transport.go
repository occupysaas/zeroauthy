package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// Network limits (spec §5).
const (
	requestTimeout   = 10 * time.Second
	maxResponseBytes = 1 << 20
)

var (
	// ErrNetworkPolicy reports a request the outbound policy refuses: a
	// non-HTTPS or credential-bearing URL, a non-public address (on any
	// resolved answer, at every dial), or a redirect.
	ErrNetworkPolicy = errors.New("federation: outbound request refused by network policy")
	// ErrResponseTooLarge reports a decoded response over the limit.
	ErrResponseTooLarge = errors.New("federation: provider response too large")
)

// Resolver resolves host names; net.DefaultResolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// NetworkPolicy configures the outbound transport. It is fixed when the
// transport is constructed; no API option or environment variable relaxes it.
// The zero value is the production policy.
type NetworkPolicy struct {
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// AllowAddr decides which resolved addresses may be dialed; it defaults
	// to rules.PublicAddr. Only FixturePolicy widens it.
	AllowAddr func(netip.Addr) bool
	// AllowHTTP permits plain http URLs (fixtures only).
	AllowHTTP bool
	// RootCAs replaces the system roots (fixtures only).
	RootCAs *x509.CertPool
	// DialContext is the final dial of a pinned address (tests only).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// RequestTimeout and MaxResponseBytes default to 10 s and 1 MiB.
	RequestTimeout   time.Duration
	MaxResponseBytes int64
}

// FixturePolicy is the policy of local provider harnesses: loopback
// addresses and the given roots are allowed. It exists for constructor
// injection in tests and the E2E harness only.
func FixturePolicy(roots *x509.CertPool) NetworkPolicy {
	return NetworkPolicy{
		RootCAs:   roots,
		AllowAddr: func(a netip.Addr) bool { return a.Unmap().IsLoopback() || rules.PublicAddr(a) },
	}
}

func (p NetworkPolicy) allow(a netip.Addr) bool {
	if p.AllowAddr != nil {
		return p.AllowAddr(a)
	}
	return rules.PublicAddr(a)
}

func (p NetworkPolicy) timeout() time.Duration {
	if p.RequestTimeout > 0 {
		return p.RequestTimeout
	}
	return requestTimeout
}

func (p NetworkPolicy) limit() int64 {
	if p.MaxResponseBytes > 0 {
		return p.MaxResponseBytes
	}
	return maxResponseBytes
}

// checkURL applies the URL half of the policy.
func (p NetworkPolicy) checkURL(u *url.URL) error {
	if u == nil || u.Host == "" || (u.Scheme != "https" && !(p.AllowHTTP && u.Scheme == "http")) {
		return fmt.Errorf("%w: URL must be absolute https", ErrNetworkPolicy)
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: URL must not carry credentials or a fragment", ErrNetworkPolicy)
	}
	if a, err := netip.ParseAddr(u.Hostname()); err == nil && !p.allow(a) {
		return fmt.Errorf("%w: address not allowed", ErrNetworkPolicy)
	}
	return nil
}

// CheckEndpoint validates a provider endpoint URL string under the policy.
func (p NetworkPolicy) CheckEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: invalid URL", ErrNetworkPolicy)
	}
	return p.checkURL(u)
}

type policyTransport struct {
	p    NetworkPolicy
	base *http.Transport
}

// NewTransport returns a RoundTripper that enforces policy: HTTPS only, no
// redirects, no environment proxy, every dial pinned to a resolved address
// that passes the address check (all answers must pass), a per-request
// deadline covering the body, and a decoded-size limit.
func NewTransport(policy NetworkPolicy) http.RoundTripper {
	pt := &policyTransport{p: policy}
	pt.base = &http.Transport{
		Proxy:                 nil,
		DialContext:           pt.dial,
		TLSClientConfig:       &tls.Config{RootCAs: policy.RootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   policy.timeout(),
		ResponseHeaderTimeout: policy.timeout(),
	}
	return pt
}

func (t *policyTransport) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: bad address", ErrNetworkPolicy)
	}
	var answers []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		answers = []netip.Addr{a}
	} else {
		r := t.p.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		if answers, err = r.LookupNetIP(ctx, "ip", host); err != nil || len(answers) == 0 {
			return nil, fmt.Errorf("federation: resolve provider host: %w", errors.Join(err, errors.New("no address")))
		}
	}
	for _, a := range answers {
		if !t.p.allow(a) {
			return nil, fmt.Errorf("%w: address not allowed", ErrNetworkPolicy)
		}
	}
	dial := t.p.DialContext
	if dial == nil {
		d := &net.Dialer{Timeout: t.p.timeout()}
		dial = d.DialContext
	}
	var lastErr error
	for _, a := range answers {
		conn, err := dial(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.p.checkURL(req.URL); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(req.Context(), t.p.timeout())
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("%w: redirect refused", ErrNetworkPolicy)
	}
	resp.Body = &limitedBody{r: resp.Body, left: t.p.limit(), cancel: cancel}
	return resp, nil
}

// limitedBody fails, rather than truncates, past the limit, and releases the
// request deadline when closed.
type limitedBody struct {
	r      io.ReadCloser
	left   int64
	cancel context.CancelFunc
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, ErrResponseTooLarge
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, ErrResponseTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error {
	defer b.cancel()
	return b.r.Close()
}

// readAll reads a bounded body; errors keep their cause classes.
func readAll(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
