package certificates

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// handshakeBudget bounds the store reads of one certificate selection.
const handshakeBudget = 2 * time.Second

// maxCached bounds parsed certificates kept in memory.
const maxCached = 4096

// ErrNoCertificate aborts a handshake for a name this deployment does not
// currently serve. There is no default certificate.
var ErrNoCertificate = errors.New("certificates: no certificate for this server name")

type staticCert struct {
	cert *tls.Certificate
	leaf *x509.Certificate
}

type cached struct {
	revision int64
	cert     *tls.Certificate
	leaf     *x509.Certificate
}

func parseStatic(c *tls.Certificate) (staticCert, error) {
	if len(c.Certificate) == 0 {
		return staticCert{}, errors.New("certificates: empty static certificate")
	}
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return staticCert{}, fmt.Errorf("certificates: static certificate: %w", err)
		}
	}
	return staticCert{cert: c, leaf: leaf}, nil
}

func validAt(leaf *x509.Certificate, now time.Time) bool {
	return !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}

// TLSConfig is the listener configuration: TLS 1.2 or later, certificates
// only through GetCertificate.
func (m *Manager) TLSConfig() (*tls.Config, error) {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", ALPNProto},
	}, nil
}

// GetCertificate selects a certificate for a currently eligible registered
// host, rechecking the registry on every handshake so a parsed cache entry
// never outlives deletion, suspension or expiry. Precedence: exact static
// identity, exact managed certificate, static wildcard, hosted wildcard.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	ctx := hello.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeBudget)
	defer cancel()
	if hello.ServerName == "" {
		return nil, ErrNoCertificate
	}
	if isALPNChallenge(hello) {
		return m.alpnChallenge(ctx, hello)
	}
	host, err := hostname.NormalizeDNSName(hello.ServerName)
	if err != nil {
		return nil, ErrNoCertificate
	}
	b, err := m.st.CustomDomains().GetHost(ctx, host)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoCertificate
	}
	if err != nil {
		return nil, fmt.Errorf("certificates: registry unavailable: %w", err)
	}
	if !b.Active {
		return nil, ErrNoCertificate
	}
	var managed string
	var d *store.CustomDomain
	if b.Kind == store.HostPublic || b.Kind == store.HostOrigin {
		if d, err = m.st.CustomDomains().Get(ctx, b.TenantID, b.DomainID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, ErrNoCertificate
			}
			return nil, fmt.Errorf("certificates: registry unavailable: %w", err)
		}
		if d.Generation != b.Generation || !customdomain.Usable(d) {
			return nil, ErrNoCertificate
		}
		switch {
		case b.Kind == store.HostOrigin && d.Type != customdomain.TypeSelfManaged:
			return nil, ErrNoCertificate
		case b.Kind == store.HostPublic && d.Type == customdomain.TypeManaged:
			managed = d.ActiveCertificateKey
		}
	}
	now := m.clock()
	for _, s := range m.static {
		if slices.Contains(s.leaf.DNSNames, host) && validAt(s.leaf, now) {
			return s.cert, nil
		}
	}
	if managed != "" {
		c, err := m.load(ctx, managed, d, now)
		if err != nil {
			return nil, err
		}
		if c != nil {
			return c, nil
		}
	}
	for _, s := range m.static {
		if s.leaf.VerifyHostname(host) == nil && validAt(s.leaf, now) {
			return s.cert, nil
		}
	}
	if m.cfg.HostedWildcard && m.hostedEligible(host) {
		c, err := m.load(ctx, HostedWildcardKey, nil, now)
		if err != nil {
			return nil, err
		}
		if c != nil {
			return c, nil
		}
	}
	return nil, ErrNoCertificate
}

// hostedEligible: base_domain itself or exactly one label below it.
func (m *Manager) hostedEligible(host string) bool {
	base, err := hostname.NormalizeDNSName(m.cfg.BaseDomain)
	if err != nil || base == "" {
		return false
	}
	if host == base {
		return true
	}
	label, ok := strings.CutSuffix(host, "."+base)
	return ok && label != "" && !strings.Contains(label, ".")
}

// load returns the parsed certificate asset when it is owned by d (nil d:
// deployment-owned), currently valid and covers no less than it should; nil
// without error means "not eligible". Parsed results are cached by revision.
func (m *Manager) load(ctx context.Context, key string, d *store.CustomDomain, now time.Time) (*tls.Certificate, error) {
	row, err := m.st.TLSAssets().Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("certificates: asset store unavailable: %w", err)
	}
	if row.Kind != store.TLSAssetCertificate || row.PublicData.Version != PublicDataVersion {
		return nil, nil
	}
	if d != nil && (row.TenantID != d.TenantID || row.DomainID != d.ID || row.Generation != d.Generation) {
		return nil, nil
	}
	if d == nil && (row.TenantID != "" || row.DomainID != "") {
		return nil, nil
	}
	m.mu.Lock()
	c, ok := m.cache[key]
	m.mu.Unlock()
	if !ok || c.revision != row.Revision {
		keyPEM, err := m.Open(row.Kind, row.Key, row.TenantID, row.DomainID, row.Generation, row.Ciphertext)
		if err != nil {
			return nil, err
		}
		pair, err := tls.X509KeyPair(row.PublicData.CertificateChainPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("certificates: stored certificate %q: %w", key, err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("certificates: stored certificate %q: %w", key, err)
		}
		pair.Leaf = leaf
		c = cached{revision: row.Revision, cert: &pair, leaf: leaf}
		m.mu.Lock()
		if len(m.cache) >= maxCached {
			clear(m.cache)
		}
		m.cache[key] = c
		m.mu.Unlock()
	}
	if !validAt(c.leaf, now) {
		return nil, nil
	}
	return c.cert, nil
}

// ValidateCertificate checks a chain and key before publication or use: the
// key matches the leaf, the leaf is valid at now, is for server use and covers
// every name. With roots, the chain must also verify to them; operator static
// certificates are checked without roots, since their trust is the operator's.
func ValidateCertificate(chainPEM, keyPEM []byte, names []string, now time.Time, roots *x509.CertPool) error {
	pair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("certificates: chain and key do not form a key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("certificates: leaf: %w", err)
	}
	if !validAt(leaf, now) {
		return fmt.Errorf("certificates: certificate is not valid at %s (%s to %s)", now.UTC().Format(time.RFC3339), leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return errors.New("certificates: certificate is not for server authentication")
	}
	for _, n := range names {
		if err := leaf.VerifyHostname(n); err != nil {
			return fmt.Errorf("certificates: certificate does not cover %q", n)
		}
	}
	if roots == nil {
		return nil
	}
	inter := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("certificates: intermediate: %w", err)
		}
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("certificates: chain is not trusted: %w", err)
	}
	return nil
}

// covers reports whether a static certificate or the hosted wildcard can
// serve host (configuration only: the wildcard may not be issued yet).
func (m *Manager) covers(host string) bool {
	for _, s := range m.static {
		if s.leaf.VerifyHostname(host) == nil {
			return true
		}
	}
	return m.cfg.HostedWildcard && m.hostedEligible(host)
}

// CoversOrigin reports whether private origin aliases under suffix can be
// served, the prerequisite for self-managed domains.
func (m *Manager) CoversOrigin(suffix string) bool {
	s, err := hostname.NormalizeDNSName(suffix)
	return err == nil && m.covers("cd-0."+s)
}

// ValidateCoverage checks at startup that every pinned canonical host (the
// system host included) that is a DNS name is covered: these identities are
// never issued implicitly. Legacy local hosts with ports or IPs are skipped.
func (m *Manager) ValidateCoverage(ctx context.Context) error {
	tenants, err := m.st.Tenants().List(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tenants {
		host, err := hostname.NormalizeDNSName(t.CanonicalHost)
		if t.CanonicalHost == "" || err != nil {
			continue
		}
		if !m.covers(host) {
			errs = append(errs, fmt.Errorf("tenant %q canonical host %q is covered by no static certificate or hosted wildcard", t.Name, host))
		}
	}
	return errors.Join(errs...)
}
