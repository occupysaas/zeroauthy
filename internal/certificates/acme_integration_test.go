//go:build domainintegration

package certificates_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"golang.org/x/crypto/acme"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/zeroauthy/zeroauthy/internal/certificates"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/tests/e2e/domains/dns"
	"github.com/zeroauthy/zeroauthy/tests/e2e/domains/provider"
)

// The local fixture (tests/e2e/domains/run-acme.sh) runs Pebble with this
// process's DNS server (8053) as its only resolver, and validates against
// this process's challenge listeners (5002 HTTP-01, 5001 TLS-ALPN-01).

// authDNS answers A 127.0.0.1 for every name and TXT from its table.
type authDNS struct {
	mu  sync.Mutex
	txt map[string]string
}

func (a *authDNS) set(name, value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.txt[strings.ToLower(strings.TrimSuffix(name, "."))+"."] = value
}

func (a *authDNS) serve(t *testing.T) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:8053")
	if err != nil {
		t.Fatalf("DNS fixture port: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			qq := q.Questions[0]
			resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true}, Questions: q.Questions}
			hdr := dnsmessage.ResourceHeader{Name: qq.Name, Type: qq.Type, Class: dnsmessage.ClassINET, TTL: 1}
			switch qq.Type {
			case dnsmessage.TypeA:
				resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
			case dnsmessage.TypeTXT:
				a.mu.Lock()
				v, ok := a.txt[strings.ToLower(qq.Name.String())]
				a.mu.Unlock()
				if ok {
					resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.TXTResource{TXT: []string{v}}})
				} else {
					resp.RCode = dnsmessage.RCodeNameError
				}
			}
			if out, err := resp.Pack(); err == nil {
				_, _ = pc.WriteTo(out, addr)
			}
		}
	}()
}

func pebbleEnv(t *testing.T) (directory string, dirRoots, issuedRoots *x509.CertPool) {
	t.Helper()
	directory = os.Getenv("ZA_ACME_DIRECTORY")
	caFile := os.Getenv("ZA_ACME_CA_FILE")
	mgmt := os.Getenv("ZA_ACME_MANAGEMENT")
	if directory == "" || caFile == "" || mgmt == "" {
		t.Fatal("run through tests/e2e/domains/run-acme.sh: the local CA fixture is not configured")
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	dirRoots = x509.NewCertPool()
	dirRoots.AppendCertsFromPEM(pemBytes)
	client := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: dirRoots}}, Timeout: 10 * time.Second}
	resp, err := client.Get(mgmt + "/roots/0")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	root, _ := io.ReadAll(resp.Body)
	issuedRoots = x509.NewCertPool()
	if !issuedRoots.AppendCertsFromPEM(root) {
		t.Fatalf("CA root: %q", root)
	}
	return directory, dirRoots, issuedRoots
}

func TestPebbleHTTP01(t *testing.T)    { pebbleIssue(t, "http-01", "http01.acme.test") }
func TestPebbleTLSALPN01(t *testing.T) { pebbleIssue(t, "tls-alpn-01", "alpn.acme.test") }

func pebbleIssue(t *testing.T, challenge, host string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	directory, dirRoots, issuedRoots := pebbleEnv(t)
	dns := &authDNS{txt: map[string]string{}}
	dns.serve(t)

	dsn := "sqlite://" + filepath.Join(t.TempDir(), "domains.db")
	openStore := func() store.Store {
		s, err := storage.Open(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.(storage.Migrator).Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	st := openStore()
	peer := openStore()
	clock := &integrationClock{}
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "acme", Name: "acme", CanonicalHost: "acme.auth.example.test"}); err != nil {
		t.Fatal(err)
	}
	resolver := &customdomain.BoundedResolver{Server: "127.0.0.1:8053"}
	domains := customdomain.NewService(st, resolver, customdomain.ServiceConfig{BaseDomain: "auth.example.test", OriginDomain: "auth.example.test", ManagedEnabled: true}, clock.now, rand.Reader)
	w, _ := keys.NewLocalWrapper(make([]byte, 32))
	m, err := certificates.NewManager(st, w, certificates.Config{DeploymentID: "it", DirectoryURL: directory}, clock.now)
	if err != nil {
		t.Fatal(err)
	}

	// Challenges are always served by a different SQL handle/replica.
	peerManager, err := certificates.NewManager(peer, w, certificates.Config{DeploymentID: "it", DirectoryURL: directory}, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	// Challenge listeners on the fixture ports.
	switch challenge {
	case "http-01":
		ln, err := net.Listen("tcp", "127.0.0.1:5002")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: peerManager.HTTPHandler(nil), ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
	case "tls-alpn-01":
		cfg, _ := peerManager.TLSConfig()
		ln, err := tls.Listen("tcp", "127.0.0.1:5001", cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.(*tls.Conn).HandshakeContext(ctx)
				}()
			}
		}()
	}

	// Setup through the domain service with actual DNS proof.
	d, err := domains.Create(ctx, "acme", customdomain.CreateInput{Domain: host, Type: customdomain.TypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	dns.set(d.ProofRecordName, customdomain.ProofValue(d))
	res, err := domains.Verify(ctx, "acme", d.ID)
	if err != nil || res.Domain.Lifecycle != customdomain.LifecycleIssuing {
		t.Fatalf("verify = %+v, %v", res.Domain, err)
	}
	ca := &observedCA{CA: certificates.NewACMECA(directory, dirRoots)}
	ca.interrupt.Store(true)
	ca.onInterrupt = func() {
		contender := certificates.NewWorker(peerManager, ca, domains, certificates.WorkerConfig{Owner: "contender", Email: "ops@example.test", Challenge: challenge, Roots: issuedRoots})
		if err := contender.Reconcile(ctx, certificates.DomainResource(res.Domain)); err != nil {
			t.Fatalf("contender: %v", err)
		}
		if ca.orders.Load() != 1 {
			t.Fatal("two claimants created parallel orders")
		}
	}
	worker := certificates.NewWorker(m, ca, domains, certificates.WorkerConfig{
		Owner: "first", Email: "ops@example.test", Challenge: challenge, Roots: issuedRoots,
	})
	resource := certificates.DomainResource(res.Domain)
	if err := worker.Reconcile(ctx, resource); !errors.Is(err, errFixtureInterrupted) {
		t.Fatalf("expected interrupted real order: %v", err)
	}
	saved, err := st.TLSAssets().Get(ctx, "order/"+resource)
	if err != nil || len(saved.Ciphertext) == 0 || saved.PublicData.OrderURL == "" {
		t.Fatalf("order not persisted: %v", err)
	}
	// Close the issuing handle, reconstruct its manager and worker, and
	// resume the persisted CA order/key while the peer keeps listening.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st = openStore()
	m, err = certificates.NewManager(st, w, certificates.Config{DeploymentID: "it", DirectoryURL: directory}, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	worker = certificates.NewWorker(m, ca, domains, certificates.WorkerConfig{
		Owner: "restarted", Email: "ops@example.test", Challenge: challenge, Roots: issuedRoots,
	})
	// The prover must use a live handle as well.
	domains = customdomain.NewService(st, resolver, customdomain.ServiceConfig{BaseDomain: "auth.example.test", OriginDomain: "auth.example.test", ManagedEnabled: true}, clock.now, rand.Reader)
	worker = certificates.NewWorker(m, ca, domains, certificates.WorkerConfig{Owner: "restarted", Email: "ops@example.test", Challenge: challenge, Roots: issuedRoots})
	if err := worker.Reconcile(ctx, certificates.DomainResource(res.Domain)); err != nil {
		cur, _ := st.CustomDomains().Get(ctx, "acme", d.ID)
		t.Fatalf("reconcile: %v (domain %+v)", err, cur)
	}
	if ca.orders.Load() != 1 {
		t.Fatalf("restart created %d orders, want reused original", ca.orders.Load())
	}
	cur, _ := st.CustomDomains().Get(ctx, "acme", d.ID)
	if !customdomain.Usable(cur) {
		t.Fatalf("not ready: %+v", cur)
	}
	cert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatal(err)
	}
	inter := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, _ := x509.ParseCertificate(der)
		inter.AddCert(c)
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: issuedRoots, Intermediates: inter}); err != nil {
		t.Fatalf("issued certificate does not verify: %v", err)
	}
	// A restarted selector on the other node opens the same encrypted key.
	peerCert, err := peerManager.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil || !peerCert.Leaf.Equal(cert.Leaf) {
		t.Fatalf("peer certificate differs: %v", err)
	}
	before := ca.orders.Load()
	if _, err := peerManager.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.acme.test"}); err == nil {
		t.Fatal("unknown SNI served")
	}
	if ca.orders.Load() != before {
		t.Fatal("handshake created order")
	}
	// Move only the application clock, without waiting for a certificate's
	// full lifetime. A CA outage retains the valid original certificate.
	clock.set(certificates.RenewalTime(resource, cert.Leaf.NotBefore, cert.Leaf.NotAfter))
	ca.outage.Store(true)
	if err := worker.Reconcile(ctx, resource); err == nil {
		t.Fatal("CA outage reported success")
	}
	if _, err := peerManager.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err != nil {
		t.Fatalf("valid certificate lost during outage: %v", err)
	}
	ca.outage.Store(false)
	clock.add(2 * time.Minute)
	if err := worker.Reconcile(ctx, resource); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	renewed, err := peerManager.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil || renewed.Leaf.SerialNumber.Cmp(cert.Leaf.SerialNumber) == 0 {
		t.Fatalf("peer cached old certificate: %v", err)
	}
	// At exact expiry the real TLS handshake must fail, including a warm
	// parsed-certificate cache; it must never trigger a fresh CA request.
	clock.set(renewed.Leaf.NotAfter)
	cfg, err := peerManager.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			serverErr <- e
			return
		}
		defer c.Close()
		serverErr <- c.(*tls.Conn).HandshakeContext(ctx)
	}()
	before = ca.orders.Load()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: issuedRoots, ServerName: host, MinVersion: tls.VersionTLS12})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("expired handshake succeeded")
	}
	if e := <-serverErr; e == nil {
		t.Fatal("server accepted expired certificate")
	}
	if ca.orders.Load() != before {
		t.Fatal("expiry triggered on-demand issuance")
	}
	clock.set(time.Now())
	if err := domains.Delete(ctx, "acme", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := peerManager.GetCertificate(&tls.ClientHelloInfo{ServerName: host}); err == nil {
		t.Fatal("deleted domain remained in peer cache")
	}
	// Recreating the same DNS name must not accept a stale worker resource.
	recreated, err := domains.Create(ctx, "acme", customdomain.CreateInput{Domain: host, Type: customdomain.TypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Reconcile(ctx, resource); err != nil {
		t.Fatal(err)
	}
	fresh, err := peer.CustomDomains().Get(ctx, "acme", recreated.ID)
	if err != nil || customdomain.Usable(fresh) {
		t.Fatal("old resource activated recreated domain")
	}

}

// TestPebbleDNS01 issues the hosted apex+wildcard certificate through DNS-01:
// the real DigitalOcean adapter writes to a local fake API whose records the
// local authoritative DNS serves to Pebble.
func TestPebbleDNS01(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	directory, dirRoots, issuedRoots := pebbleEnv(t)
	api := provider.New("dop_v1_fixture", "example.test")
	unrelatedID := api.Add("_acme-challenge.auth", "unrelated-preexisting-record")
	ln, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	apiSrv := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = apiSrv.Serve(ln) }()
	t.Cleanup(func() { _ = apiSrv.Close() })
	auth := &dns.Server{A: [4]byte{127, 0, 0, 1}, TXT: api.TXT}
	if err := auth.Listen("127.0.0.1:8053"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auth.Close)

	dsn := "sqlite://" + filepath.Join(t.TempDir(), "hosted.db")
	st, err := storage.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.(storage.Migrator).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	peer, err := storage.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	for _, tn := range []*store.Tenant{
		{ID: "acme", Name: "acme", CanonicalHost: "acme.auth.example.test"},
		{ID: "sys", Name: "system", Reserved: true, CanonicalHost: "system.auth.example.test"},
	} {
		if err := st.Tenants().Create(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	clock := &integrationClock{}
	wr, _ := keys.NewLocalWrapper(make([]byte, 32))
	hosted := &certificates.HostedConfig{
		BaseDomain: "auth.example.test", Zone: "example.test",
		Provider: certificates.NewDigitalOcean("dop_v1_fixture", certificates.WithEndpoint("http://127.0.0.1:18080", nil, 10*time.Second)),
		Resolver: &customdomain.BoundedResolver{Server: "127.0.0.1:8053"}, PollMin: 100 * time.Millisecond, PollMax: time.Second,
	}
	var managers [2]*certificates.Manager
	var workers [2]*certificates.Worker
	for i := range workers {
		nodeStore := st
		if i == 1 {
			nodeStore = peer
		}
		m, err := certificates.NewManager(nodeStore, wr, certificates.Config{DeploymentID: "it", DirectoryURL: directory, BaseDomain: "auth.example.test", HostedWildcard: true}, clock.now)
		if err != nil {
			t.Fatal(err)
		}
		managers[i] = m
		workers[i] = certificates.NewWorker(m, certificates.NewACMECA(directory, dirRoots), nil, certificates.WorkerConfig{
			Owner: "dns-" + string(rune('a'+i)), Email: "ops@example.test", Challenge: "http-01", Roots: issuedRoots, Hosted: hosted,
		})
	}
	key := certificates.HostedResource("it", "auth.example.test")
	if err := workers[0].Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	check := func() *x509.Certificate {
		t.Helper()
		for _, sni := range []string{"acme.auth.example.test", "system.auth.example.test"} {
			c, err := managers[1].GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
			if err != nil {
				t.Fatalf("%s: %v", sni, err)
			}
			inter := x509.NewCertPool()
			for _, der := range c.Certificate[1:] {
				ic, _ := x509.ParseCertificate(der)
				inter.AddCert(ic)
			}
			if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: sni, Roots: issuedRoots, Intermediates: inter}); err != nil {
				t.Fatalf("%s does not verify: %v", sni, err)
			}
		}
		for _, sni := range []string{"a.b.auth.example.test", "login.acme.test"} {
			if _, err := managers[1].GetCertificate(&tls.ClientHelloInfo{ServerName: sni}); err == nil {
				t.Fatalf("%s served", sni)
			}
		}
		if left := api.Records(); len(left) != 1 || left[0].ID != unrelatedID || left[0].Data != "unrelated-preexisting-record" {
			t.Fatalf("challenge records left: %v", left)
		}
		row, _ := st.TLSAssets().Get(ctx, certificates.HostedWildcardKey)
		block, _ := pem.Decode(row.PublicData.CertificateChainPEM)
		leaf, _ := x509.ParseCertificate(block.Bytes)
		return leaf
	}
	first := check()
	// A restarted or second worker does nothing before renewal time...
	if err := workers[1].Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	if again := check(); again.SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("renewed early")
	}
	// ...and renews at it.
	clock.set(certificates.RenewalTime(key, first.NotBefore, first.NotAfter))
	if err := workers[1].Reconcile(ctx, key); err != nil {
		t.Fatal(err)
	}
	if renewed := check(); renewed.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("not renewed")
	}
}

// observedCA injects a process interruption at a persisted order boundary;
// every successful protocol operation still goes to the real local Pebble CA.
var errFixtureInterrupted = errors.New("fixture process interrupted")

type observedCA struct {
	certificates.CA
	interrupt   atomic.Bool
	outage      atomic.Bool
	orders      atomic.Int32
	onInterrupt func()
}

func (c *observedCA) NewOrder(ctx context.Context, key crypto.Signer, account string, names []string) (*acme.Order, error) {
	if c.outage.Load() {
		return nil, errors.New("fixture CA unavailable")
	}
	c.orders.Add(1)
	return c.CA.NewOrder(ctx, key, account, names)
}
func (c *observedCA) Accept(ctx context.Context, key crypto.Signer, account string, ch *acme.Challenge) error {
	if c.interrupt.Swap(false) {
		if c.onInterrupt != nil {
			c.onInterrupt()
		}
		return errFixtureInterrupted
	}
	return c.CA.Accept(ctx, key, account, ch)
}

// Keep real time advancing during network issuance; only renewal/expiry jumps
// are synthetic. A frozen initial instant may precede Pebble's NotBefore.
type integrationClock struct{ offset atomic.Int64 }

func (c *integrationClock) now() time.Time      { return time.Now().Add(time.Duration(c.offset.Load())) }
func (c *integrationClock) set(t time.Time)     { c.offset.Store(int64(time.Until(t))) }
func (c *integrationClock) add(d time.Duration) { c.offset.Add(int64(d)) }
