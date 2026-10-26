//go:build domainintegration

package certificates_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/zeroauthy/zeroauthy/internal/certificates"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
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

	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "acme", Name: "acme", CanonicalHost: "acme.auth.example.test"}); err != nil {
		t.Fatal(err)
	}
	resolver := &customdomain.BoundedResolver{Server: "127.0.0.1:8053"}
	domains := customdomain.NewService(st, resolver, customdomain.ServiceConfig{BaseDomain: "auth.example.test", OriginDomain: "auth.example.test", ManagedEnabled: true}, time.Now, rand.Reader)
	w, _ := keys.NewLocalWrapper(make([]byte, 32))
	m, err := certificates.NewManager(st, w, certificates.Config{DeploymentID: "it", DirectoryURL: directory}, time.Now)
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
		srv := &http.Server{Handler: m.HTTPHandler(nil), ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
	case "tls-alpn-01":
		cfg, _ := m.TLSConfig()
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
	worker := certificates.NewWorker(m, certificates.NewACMECA(directory, dirRoots), domains, certificates.WorkerConfig{
		Owner: "it", Email: "ops@example.test", Challenge: challenge, Roots: issuedRoots,
	})
	if err := worker.Reconcile(ctx, certificates.DomainResource(res.Domain)); err != nil {
		cur, _ := st.CustomDomains().Get(ctx, "acme", d.ID)
		t.Fatalf("reconcile: %v (domain %+v)", err, cur)
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
}

// TestPebbleDNS01 issues the hosted apex+wildcard certificate through DNS-01:
// the real DigitalOcean adapter writes to a local fake API whose records the
// local authoritative DNS serves to Pebble.
func TestPebbleDNS01(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	directory, dirRoots, issuedRoots := pebbleEnv(t)
	api := provider.New("dop_v1_fixture", "example.test")
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

	st := memory.New()
	for _, tn := range []*store.Tenant{
		{ID: "acme", Name: "acme", CanonicalHost: "acme.auth.example.test"},
		{ID: "sys", Name: "system", Reserved: true, CanonicalHost: "system.auth.example.test"},
	} {
		if err := st.Tenants().Create(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	clock := &clk{t: time.Now()}
	wr, _ := keys.NewLocalWrapper(make([]byte, 32))
	hosted := &certificates.HostedConfig{
		BaseDomain: "auth.example.test", Zone: "example.test",
		Provider: certificates.NewDigitalOcean("dop_v1_fixture", certificates.WithEndpoint("http://127.0.0.1:18080", nil, 10*time.Second)),
		Resolver: &customdomain.BoundedResolver{Server: "127.0.0.1:8053"}, PollMin: 100 * time.Millisecond, PollMax: time.Second,
	}
	var managers [2]*certificates.Manager
	var workers [2]*certificates.Worker
	for i := range workers {
		m, err := certificates.NewManager(st, wr, certificates.Config{DeploymentID: "it", DirectoryURL: directory, BaseDomain: "auth.example.test", HostedWildcard: true}, clock.now)
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
		if left := api.Records(); len(left) != 0 {
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
