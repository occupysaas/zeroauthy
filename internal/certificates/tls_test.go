package certificates_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/certificates"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

var now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newCA(t *testing.T) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &ca{cert, key, pool}
}

// issue returns a leaf chain and key PEM for names.
func (c *ca) issue(t *testing.T, names []string, from, to time.Time, eku ...x509.ExtKeyUsage) (chain, keyPEM []byte) {
	t.Helper()
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: from, NotAfter: to, ExtKeyUsage: eku, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
}

func wrapper(t *testing.T, b byte) keys.Wrapper {
	t.Helper()
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func manager(t *testing.T, st store.Store, w keys.Wrapper, cfg certificates.Config) *certificates.Manager {
	t.Helper()
	if cfg.DeploymentID == "" {
		cfg.DeploymentID = "prod-1"
	}
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = "https://ca.test/directory"
	}
	m, err := certificates.NewManager(st, w, cfg, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTLSAssetAAD(t *testing.T) {
	st := memory.New()
	m := manager(t, st, wrapper(t, 1), certificates.Config{})
	sealed, err := m.Seal(store.TLSAssetCertificate, "cert/acme/cd_1", "acme", "cd_1", 3, []byte("private"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("private")) {
		t.Fatal("plaintext visible")
	}
	if got, err := m.Open(store.TLSAssetCertificate, "cert/acme/cd_1", "acme", "cd_1", 3, sealed); err != nil || string(got) != "private" {
		t.Fatalf("open = %q, %v", got, err)
	}
	for name, open := range map[string]func() error{
		"kind": func() error {
			_, err := m.Open(store.TLSAssetOrder, "cert/acme/cd_1", "acme", "cd_1", 3, sealed)
			return err
		},
		"key swap": func() error {
			_, err := m.Open(store.TLSAssetCertificate, "cert/acme/cd_2", "acme", "cd_1", 3, sealed)
			return err
		},
		"tenant": func() error {
			_, err := m.Open(store.TLSAssetCertificate, "cert/acme/cd_1", "globex", "cd_1", 3, sealed)
			return err
		},
		"domain": func() error {
			_, err := m.Open(store.TLSAssetCertificate, "cert/acme/cd_1", "acme", "cd_2", 3, sealed)
			return err
		},
		"generation": func() error {
			_, err := m.Open(store.TLSAssetCertificate, "cert/acme/cd_1", "acme", "cd_1", 4, sealed)
			return err
		},
		"deployment": func() error {
			_, err := manager(t, st, wrapper(t, 1), certificates.Config{DeploymentID: "prod-2"}).Open(store.TLSAssetCertificate, "cert/acme/cd_1", "acme", "cd_1", 3, sealed)
			return err
		},
		"directory": func() error {
			_, err := manager(t, st, wrapper(t, 1), certificates.Config{DirectoryURL: "https://staging.ca.test/directory"}).Open(store.TLSAssetCertificate, "cert/acme/cd_1", "acme", "cd_1", 3, sealed)
			return err
		},
		"master key": func() error {
			_, err := manager(t, st, wrapper(t, 2), certificates.Config{}).Open(store.TLSAssetCertificate, "cert/acme/cd_1", "acme", "cd_1", 3, sealed)
			return err
		},
	} {
		if err := open(); err == nil {
			t.Errorf("%s mismatch opened", name)
		}
	}
	if _, err := certificates.NewManager(st, wrapper(t, 1), certificates.Config{DirectoryURL: "https://ca.test/d"}, time.Now); err == nil {
		t.Error("manager without deployment ID")
	}
}

type world struct {
	st   *memory.Store
	m    *certificates.Manager
	ca   *ca
	w    keys.Wrapper
	reqs int
}

// newWorld: tenants acme/globex on base auth.example.test; a static cert for
// the system host and acme's canonical name; a hosted wildcard asset; and
// an active managed domain login.acme.test with its certificate.
func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	st := memory.New()
	for _, n := range []string{"acme", "globex"} {
		if err := st.Tenants().Create(ctx, &store.Tenant{ID: n, Name: n, CanonicalHost: n + ".auth.example.test"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "sys", Name: "system", Reserved: true, CanonicalHost: "system.auth.example.test"}); err != nil {
		t.Fatal(err)
	}
	c := newCA(t)
	staticChain, staticKey := c.issue(t, []string{"system.auth.example.test", "acme.auth.example.test"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	static, err := tls.X509KeyPair(staticChain, staticKey)
	if err != nil {
		t.Fatal(err)
	}
	// An operator certificate with an exact name and a wildcard over customer
	// names: exact static beats managed, managed beats static wildcard.
	opChain, opKey := c.issue(t, []string{"id.acme.test", "*.acme.test"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	op, err := tls.X509KeyPair(opChain, opKey)
	if err != nil {
		t.Fatal(err)
	}
	w := wrapper(t, 1)
	m := manager(t, st, w, certificates.Config{BaseDomain: "auth.example.test", HostedWildcard: true, Static: []tls.Certificate{static, op}})
	wl := &world{st: st, m: m, ca: c, w: w}
	chain, key := c.issue(t, []string{"auth.example.test", "*.auth.example.test"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	wl.put(t, certificates.HostedWildcardKey, "", "", 0, chain, key)
	wl.managed(t, "login.acme.test", now.Add(90*24*time.Hour))
	wl.managed(t, "id.acme.test", now.Add(90*24*time.Hour))
	return wl
}

func (w *world) put(t *testing.T, key, tenantID, domainID string, gen int64, chain, keyPEM []byte) {
	t.Helper()
	ctx := context.Background()
	sealed, err := w.m.Seal(store.TLSAssetCertificate, key, tenantID, domainID, gen, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := pem.Decode(chain)
	leaf, _ := x509.ParseCertificate(cert.Bytes)
	row := &store.TLSAsset{Key: key, Kind: store.TLSAssetCertificate, TenantID: tenantID, DomainID: domainID, Generation: gen, Ciphertext: sealed,
		PublicData: store.TLSPublicData{Version: certificates.PublicDataVersion, CertificateChainPEM: chain, SANs: leaf.DNSNames, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}}
	var rev int64
	if old, err := w.st.TLSAssets().Get(ctx, key); err == nil {
		rev = old.Revision
	}
	if err := w.st.TLSAssets().Put(ctx, row, rev); err != nil {
		t.Fatal(err)
	}
}

// managed creates an active managed domain whose certificate expires at to.
func (w *world) managed(t *testing.T, host string, to time.Time) *store.CustomDomain {
	t.Helper()
	ctx := context.Background()
	id := "cd_" + host[:3]
	key := "cert/acme/" + id
	d := &store.CustomDomain{TenantID: "acme", ID: id, Domain: host, Type: customdomain.TypeManaged, Generation: 1,
		Lifecycle: customdomain.LifecycleActive, Status: customdomain.StatusReady, ActiveCertificateKey: key}
	if err := w.st.CustomDomains().Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := w.st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: host, TenantID: "acme", DomainID: id, Generation: 1, Kind: store.HostPublic, Active: true}); err != nil {
		t.Fatal(err)
	}
	chain, keyPEM := w.ca.issue(t, []string{host}, now.Add(-time.Hour), to)
	w.put(t, key, "acme", id, 1, chain, keyPEM)
	return d
}

func served(t *testing.T, m *certificates.Manager, sni string) (*x509.Certificate, error) {
	t.Helper()
	c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: sni, SupportedProtos: []string{"h2"}})
	if err != nil {
		return nil, err
	}
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

func TestDomainCertificateSelection(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	for _, tc := range []struct{ sni, want string }{
		{"acme.auth.example.test", "system.auth.example.test"}, // static exact beats hosted wildcard
		{"system.auth.example.test", "system.auth.example.test"},
		{"GLOBEX.auth.example.test.", "auth.example.test"}, // hosted wildcard
		{"login.acme.test", "login.acme.test"},             // exact managed beats static wildcard
		{"id.acme.test", "id.acme.test"},                   // exact static beats managed
	} {
		leaf, err := served(t, w.m, tc.sni)
		if err != nil || leaf.Subject.CommonName != tc.want {
			t.Errorf("%s: %v, %v", tc.sni, leaf, err)
		}
	}
	if leaf, _ := served(t, w.m, "id.acme.test"); leaf == nil || len(leaf.DNSNames) != 2 {
		t.Errorf("id.acme.test not served by the static certificate: %v", leaf)
	}
	// An active claim on a domain that is no longer usable is not served.
	sus, _ := w.st.CustomDomains().Get(ctx, "acme", "cd_log")
	sus.Lifecycle, sus.Status = customdomain.LifecycleSuspended, customdomain.StatusPending
	if err := w.st.CustomDomains().Update(ctx, sus, sus.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := served(t, w.m, "login.acme.test"); err == nil {
		t.Error("suspended domain served")
	}
	sus.Lifecycle, sus.Status = customdomain.LifecycleActive, customdomain.StatusReady
	if err := w.st.CustomDomains().Update(ctx, sus, sus.Revision); err != nil {
		t.Fatal(err)
	}
	// Unknown, empty and two-label-deep names get no certificate at all.
	if err := w.st.Tenants().Update(ctx, &store.Tenant{ID: "globex", Name: "globex", CanonicalHost: "globex.auth.example.test", Domains: []string{"a.b.auth.example.test"}}); err != nil {
		t.Fatal(err)
	}
	for _, sni := range []string{"unknown.test", "", "a.b.auth.example.test", "localhost"} {
		if _, err := served(t, w.m, sni); err == nil {
			t.Errorf("%q got a certificate", sni)
		}
	}
	// Pending and expired managed domains are not served.
	pending := w.managed(t, "pending.acme.test", now.Add(90*24*time.Hour))
	h, _ := w.st.CustomDomains().GetHost(ctx, pending.Domain)
	h.Active = false
	if err := w.st.CustomDomains().PutHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := served(t, w.m, pending.Domain); err == nil {
		t.Error("pending domain served")
	}
	w.managed(t, "old.example.org", now.Add(-time.Minute))
	if _, err := served(t, w.m, "old.example.org"); err == nil {
		t.Error("expired certificate served")
	}
	// A warm cache cannot resurrect a deleted domain.
	if _, err := served(t, w.m, "login.acme.test"); err != nil {
		t.Fatal(err)
	}
	d, _ := w.st.CustomDomains().Get(ctx, "acme", "cd_log")
	if err := w.st.CustomDomains().Delete(ctx, "acme", d.ID, d.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := served(t, w.m, "login.acme.test"); err == nil {
		t.Error("deleted domain served from cache")
	}
	// Store failures abort the handshake.
	broken := manager(t, failingStore{w.st}, w.w, certificates.Config{BaseDomain: "auth.example.test", HostedWildcard: true})
	if _, err := served(t, broken, "globex.auth.example.test"); err == nil {
		t.Error("store failure served a certificate")
	}
}

type failingStore struct{ *memory.Store }
type failingDomains struct{ store.CustomDomains }

func (s failingStore) CustomDomains() store.CustomDomains {
	return failingDomains{s.Store.CustomDomains()}
}
func (failingDomains) GetHost(context.Context, string) (*store.HostBinding, error) {
	return nil, errors.New("database down")
}

// The listener refuses TLS 1.0 and 1.1 and serves eligible names.
func TestTLSConfigHandshake(t *testing.T) {
	w := newWorld(t)
	cfg, err := w.m.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("min version = %x", cfg.MinVersion)
	}
	handshake := func(client *tls.Config) error {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		srv := tls.Server(a, cfg)
		go func() { _ = srv.Handshake(); a.Close() }()
		return tls.Client(b, client).Handshake()
	}
	if err := handshake(&tls.Config{ServerName: "globex.auth.example.test", RootCAs: w.ca.pool}); err != nil {
		t.Fatalf("TLS 1.2+: %v", err)
	}
	if err := handshake(&tls.Config{ServerName: "globex.auth.example.test", RootCAs: w.ca.pool, MaxVersion: tls.VersionTLS11}); err == nil {
		t.Fatal("TLS 1.1 accepted")
	}
	if err := handshake(&tls.Config{ServerName: "unknown.test", InsecureSkipVerify: true}); err == nil {
		t.Fatal("unknown SNI completed a handshake")
	}
}

func TestTLSConfigValidation(t *testing.T) {
	c := newCA(t)
	names := []string{"login.acme.test"}
	good, goodKey := c.issue(t, names, now.Add(-time.Hour), now.Add(time.Hour))
	if err := certificates.ValidateCertificate(good, goodKey, names, now, c.pool); err != nil {
		t.Fatalf("valid = %v", err)
	}
	_, otherKey := c.issue(t, names, now.Add(-time.Hour), now.Add(time.Hour))
	wrongSAN, wrongSANKey := c.issue(t, []string{"other.acme.test"}, now.Add(-time.Hour), now.Add(time.Hour))
	expired, expiredKey := c.issue(t, names, now.Add(-2*time.Hour), now.Add(-time.Hour))
	future, futureKey := c.issue(t, names, now.Add(time.Hour), now.Add(2*time.Hour))
	client, clientKey := c.issue(t, names, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	for name, tc := range map[string]struct {
		chain, key []byte
		roots      *x509.CertPool
	}{
		"key mismatch": {good, otherKey, c.pool},
		"missing SAN":  {wrongSAN, wrongSANKey, c.pool},
		"expired":      {expired, expiredKey, c.pool},
		"not yet":      {future, futureKey, c.pool},
		"client EKU":   {client, clientKey, c.pool},
		"untrusted":    {good, goodKey, newCA(t).pool},
		"garbage":      {[]byte("junk"), goodKey, c.pool},
	} {
		if err := certificates.ValidateCertificate(tc.chain, tc.key, names, now, tc.roots); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Startup refuses to serve canonical or system names that no static
// certificate covers and the hosted wildcard cannot cover.
func TestTLSCoverage(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	if err := w.m.ValidateCoverage(ctx); err != nil {
		t.Fatalf("covered = %v", err)
	}
	if !w.m.CoversOrigin("auth.example.test") || w.m.CoversOrigin("origin.example.org") {
		t.Fatal("origin coverage")
	}
	noWild := manager(t, w.st, w.w, certificates.Config{BaseDomain: "auth.example.test", Static: []tls.Certificate{}})
	if err := noWild.ValidateCoverage(ctx); err == nil {
		t.Fatal("uncovered canonical hosts accepted")
	}
	// Legacy local operator hosts (ports, IPs) are not TLS names here.
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "a", Name: "a", CanonicalHost: "localhost:8443"}); err != nil {
		t.Fatal(err)
	}
	if err := manager(t, st, w.w, certificates.Config{}).ValidateCoverage(ctx); err != nil {
		t.Fatalf("local host = %v", err)
	}
}
