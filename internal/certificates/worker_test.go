package certificates_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/zeroauthy/zeroauthy/internal/certificates"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type clk struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clk) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clk) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }
func (c *clk) set(t time.Time)     { c.mu.Lock(); defer c.mu.Unlock(); c.t = t }

// fakeCA validates a challenge by asking the given node, so issuance and
// validation can run on different replicas.
type fakeCA struct {
	mu        sync.Mutex
	ca        *ca
	clock     func() time.Time
	validity  time.Duration
	orders    map[string]*acme.Order
	authz     map[string]*acme.Authorization
	finalized map[string]bool
	validator func(typ, identifier, token string) bool
	newOrders int

	// Hooks simulate crashes, takeovers and CA errors.
	acceptErr   func() error
	finalizeErr func() error
	onFinalize  func()
}

func newFakeCA(c *ca, clock func() time.Time) *fakeCA {
	return &fakeCA{ca: c, clock: clock, validity: 90 * 24 * time.Hour, orders: map[string]*acme.Order{}, authz: map[string]*acme.Authorization{}, finalized: map[string]bool{}}
}

func (f *fakeCA) Register(context.Context, crypto.Signer, string) (string, error) {
	return "https://ca.test/acct/1", nil
}

func (f *fakeCA) NewOrder(_ context.Context, _ crypto.Signer, _ string, names []string) (*acme.Order, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.newOrders++
	url := fmt.Sprintf("https://ca.test/order/%d", f.newOrders)
	o := &acme.Order{URI: url, Status: acme.StatusPending, FinalizeURL: url + "/finalize"}
	for i, n := range names {
		a := fmt.Sprintf("%s/authz/%d", url, i)
		o.AuthzURLs = append(o.AuthzURLs, a)
		o.Identifiers = append(o.Identifiers, acme.AuthzID{Type: "dns", Value: n})
		f.authz[a] = &acme.Authorization{URI: a, Status: acme.StatusPending, Identifier: acme.AuthzID{Type: "dns", Value: n}, Challenges: []*acme.Challenge{
			{Type: "http-01", URI: a + "/http", Token: fmt.Sprintf("tok-%d-%d-h", f.newOrders, i), Status: acme.StatusPending},
			{Type: "tls-alpn-01", URI: a + "/alpn", Token: fmt.Sprintf("tok-%d-%d-a", f.newOrders, i), Status: acme.StatusPending},
		}}
	}
	f.orders[url] = o
	c := *o
	return &c, nil
}

func (f *fakeCA) Order(_ context.Context, _ crypto.Signer, _ string, url string) (*acme.Order, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.orders[url]
	if o == nil {
		return nil, &acme.Error{StatusCode: 404, ProblemType: "urn:ietf:params:acme:error:malformed"}
	}
	ready := true
	for _, a := range o.AuthzURLs {
		switch f.authz[a].Status {
		case acme.StatusInvalid:
			o.Status = acme.StatusInvalid
		case acme.StatusValid:
		default:
			ready = false
		}
	}
	if o.Status != acme.StatusInvalid && ready {
		o.Status = acme.StatusReady
	}
	if f.finalized[url] {
		o.Status = acme.StatusValid
	}
	c := *o
	return &c, nil
}

func (f *fakeCA) Authorization(_ context.Context, _ crypto.Signer, _ string, url string) (*acme.Authorization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := *f.authz[url]
	return &a, nil
}

func (f *fakeCA) Accept(_ context.Context, _ crypto.Signer, _ string, chal *acme.Challenge) error {
	if f.acceptErr != nil {
		if err := f.acceptErr(); err != nil {
			return err
		}
	}
	f.mu.Lock()
	var target *acme.Authorization
	for _, a := range f.authz {
		for _, c := range a.Challenges {
			if c.URI == chal.URI {
				target = a
			}
		}
	}
	validator := f.validator
	f.mu.Unlock()
	ok := validator(chal.Type, target.Identifier.Value, chal.Token)
	f.mu.Lock()
	defer f.mu.Unlock()
	if ok {
		target.Status = acme.StatusValid
	} else {
		target.Status = acme.StatusInvalid
	}
	return nil
}

func (f *fakeCA) Finalize(_ context.Context, _ crypto.Signer, _ string, finalizeURL string, csrDER []byte) ([][]byte, error) {
	if f.onFinalize != nil {
		f.onFinalize()
	}
	if f.finalizeErr != nil {
		if err := f.finalizeErr(); err != nil {
			return nil, err
		}
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	now := f.clock()
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(f.validity), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.ca.cert, csr.PublicKey, f.ca.key)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.finalized[finalizeURL[:len(finalizeURL)-len("/finalize")]] = true
	f.mu.Unlock()
	return [][]byte{der, f.ca.cert.Raw}, nil
}

func (f *fakeCA) HTTP01(_ crypto.Signer, token string) (string, error) { return token + ".thumb", nil }

func (f *fakeCA) TLSALPN01(_ crypto.Signer, token, identifier string) (tls.Certificate, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: token}, DNSNames: []string{identifier},
		NotBefore: f.clock().Add(-time.Hour), NotAfter: f.clock().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

type proofs struct{ txt map[string]string }

func (p *proofs) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := p.txt[name]; ok {
		return []string{v}, nil
	}
	return nil, customdomain.ErrDNSNotFound
}
func (p *proofs) LookupCNAME(context.Context, string) (string, error) {
	return "", customdomain.ErrDNSNotFound
}
func (p *proofs) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, customdomain.ErrDNSNotFound
}

// acmeWorld has two nodes (managers + workers) on one store and a managed
// domain whose proof has been verified through the domain service.
type acmeWorld struct {
	st      *memory.Store
	clock   *clk
	ca      *ca
	fake    *fakeCA
	domains *customdomain.Service
	dns     *proofs
	nodes   [2]*certificates.Manager
	workers [2]*certificates.Worker
	d       *store.CustomDomain
}

func newACMEWorld(t *testing.T, challenge string) *acmeWorld {
	t.Helper()
	ctx := context.Background()
	c := &clk{t: now}
	st := memory.NewWithClock(c.now)
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "acme", Name: "acme", CanonicalHost: "acme.auth.example.test"}); err != nil {
		t.Fatal(err)
	}
	w := &acmeWorld{st: st, clock: c, ca: newCA(t), dns: &proofs{txt: map[string]string{}}}
	w.fake = newFakeCA(w.ca, c.now)
	w.domains = customdomain.NewService(st, w.dns, customdomain.ServiceConfig{BaseDomain: "auth.example.test", OriginDomain: "auth.example.test", ManagedEnabled: true}, c.now, rand.Reader)
	for i := range w.nodes {
		m, err := certificates.NewManager(st, wrapper(t, 1), certificates.Config{DeploymentID: "prod-1", DirectoryURL: "https://ca.test/directory"}, c.now)
		if err != nil {
			t.Fatal(err)
		}
		w.nodes[i] = m
		w.workers[i] = certificates.NewWorker(m, w.fake, w.domains, certificates.WorkerConfig{
			Owner: fmt.Sprintf("node-%d", i), Email: "ops@example.test", Challenge: challenge, Roots: w.ca.pool, Poll: 10 * time.Millisecond,
		})
	}
	// The CA validates through node 1 while node 0 issues.
	w.fake.validator = func(typ, identifier, token string) bool { return w.validate(t, 1, typ, identifier, token) }
	d, err := w.domains.Create(ctx, "acme", customdomain.CreateInput{Domain: "login.acme.test", Type: customdomain.TypeManaged})
	if err != nil {
		t.Fatal(err)
	}
	w.dns.txt[d.ProofRecordName] = customdomain.ProofValue(d)
	res, err := w.domains.Verify(ctx, "acme", d.ID)
	if err != nil || res.Domain.Lifecycle != customdomain.LifecycleIssuing {
		t.Fatalf("verify = %+v, %v", res.Domain, err)
	}
	w.d = res.Domain
	return w
}

func (w *acmeWorld) validate(t *testing.T, node int, typ, identifier, token string) bool {
	switch typ {
	case "http-01":
		rec := httptest.NewRecorder()
		w.nodes[node].HTTPHandler(nil).ServeHTTP(rec, httptest.NewRequest("GET", "http://"+identifier+"/.well-known/acme-challenge/"+token, nil))
		body, _ := io.ReadAll(rec.Body)
		return rec.Code == 200 && string(body) == token+".thumb"
	case "tls-alpn-01":
		c, err := w.nodes[node].GetCertificate(&tls.ClientHelloInfo{ServerName: identifier, SupportedProtos: []string{"acme-tls/1"}})
		if err != nil {
			return false
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		return err == nil && leaf.Subject.CommonName == token
	}
	return false
}

func (w *acmeWorld) key() string { return certificates.DomainResource(w.d) }

func (w *acmeWorld) current(t *testing.T) *store.CustomDomain {
	t.Helper()
	d, err := w.st.CustomDomains().Get(context.Background(), "acme", w.d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestACMEIssuance(t *testing.T) {
	for _, challenge := range []string{"http-01", "tls-alpn-01"} {
		t.Run(challenge, func(t *testing.T) {
			ctx := context.Background()
			w := newACMEWorld(t, challenge)
			if err := w.workers[0].Reconcile(ctx, w.key()); err != nil {
				t.Fatal(err)
			}
			d := w.current(t)
			if !customdomain.Usable(d) || d.ActiveCertificateKey == "" {
				t.Fatalf("after issuance = %+v", d)
			}
			// Either node serves it; the order and challenge records are gone.
			for _, m := range w.nodes {
				c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "login.acme.test"})
				if err != nil || c.Leaf.Subject.CommonName != "login.acme.test" {
					t.Fatalf("served = %v", err)
				}
			}
			if left, _ := w.st.TLSAssets().Get(ctx, "order/"+w.key()); left != nil {
				t.Fatal("order record left behind")
			}
			// Private key material never sits in public data.
			cert, _ := w.st.TLSAssets().Get(ctx, d.ActiveCertificateKey)
			if len(cert.Ciphertext) == 0 || containsPrivateKey(cert.PublicData.CertificateChainPEM) {
				t.Fatal("certificate asset leaks its key")
			}
		})
	}
}

func containsPrivateKey(b []byte) bool { return bytes.Contains(b, []byte("PRIVATE KEY")) }

// A worker that saved its order and then failed is resumed from the saved
// order by another instance, without a second CA order.
func TestACMEOrderRecovery(t *testing.T) {
	ctx := context.Background()
	w := newACMEWorld(t, "http-01")
	crash := errors.New("connection reset")
	w.fake.acceptErr = func() error { return crash }
	if err := w.workers[0].Reconcile(ctx, w.key()); err == nil {
		t.Fatal("crash not reported")
	}
	saved, err := w.st.TLSAssets().Get(ctx, "order/"+w.key())
	if err != nil || saved.PublicData.OrderURL == "" || len(saved.Ciphertext) == 0 {
		t.Fatalf("order not saved before network steps: %+v, %v", saved, err)
	}
	if d := w.current(t); d.LastFailure == "" || strings.Contains(d.LastFailure, "connection reset") {
		t.Fatalf("failure message = %q", d.LastFailure)
	}
	w.fake.acceptErr = nil
	w.clock.add(10 * time.Minute)
	if err := w.workers[1].Reconcile(ctx, w.key()); err != nil {
		t.Fatal(err)
	}
	if w.fake.newOrders != 1 || !customdomain.Usable(w.current(t)) {
		t.Fatalf("orders=%d domain=%+v", w.fake.newOrders, w.current(t))
	}
}

// Only one instance works a resource; a worker that lost its lease cannot
// publish, and deleted or recreated domains reject old work.
func TestACMELeaseTakeover(t *testing.T) {
	ctx := context.Background()
	w := newACMEWorld(t, "http-01")
	held, err := w.st.TLSAssets().ClaimLease(ctx, w.key(), "elsewhere", 120*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.workers[0].Reconcile(ctx, w.key()); err != nil || w.fake.newOrders != 0 {
		t.Fatalf("worked a held lease: %v, orders=%d", err, w.fake.newOrders)
	}
	// The holder expires exactly at its deadline (storage time).
	w.clock.set(held.Until)
	// While node 0 finalizes, its lease expires and node 1 takes over.
	w.fake.onFinalize = func() {
		w.fake.onFinalize = nil
		w.clock.add(121 * time.Second)
		if _, err := w.st.TLSAssets().ClaimLease(ctx, w.key(), "node-1", 120*time.Second); err != nil {
			t.Errorf("takeover: %v", err)
		}
	}
	if err := w.workers[0].Reconcile(ctx, w.key()); err == nil {
		t.Fatal("stale worker reported success")
	}
	if d := w.current(t); customdomain.Usable(d) || d.ActiveCertificateKey != "" {
		t.Fatalf("stale worker published: %+v", d)
	}
}

func TestACMERejectsRecreatedDomain(t *testing.T) {
	ctx := context.Background()
	w := newACMEWorld(t, "http-01")
	var fresh *store.CustomDomain
	w.fake.onFinalize = func() {
		w.fake.onFinalize = nil
		if err := w.domains.Delete(ctx, "acme", w.d.ID); err != nil {
			t.Error(err)
		}
		var err error
		if fresh, err = w.domains.Create(ctx, "acme", customdomain.CreateInput{Domain: "login.acme.test", Type: customdomain.TypeManaged}); err != nil {
			t.Error(err)
		}
	}
	if err := w.workers[0].Reconcile(ctx, w.key()); err == nil {
		t.Fatal("old work reported success")
	}
	d, err := w.st.CustomDomains().Get(ctx, "acme", fresh.ID)
	if err != nil || d.ActiveCertificateKey != "" || customdomain.Usable(d) {
		t.Fatalf("recreated domain received old certificate: %+v, %v", d, err)
	}
	if _, err := w.nodes[0].GetCertificate(&tls.ClientHelloInfo{ServerName: "login.acme.test"}); err == nil {
		t.Fatal("old certificate served")
	}
}

func TestSharedChallenges(t *testing.T) {
	ctx := context.Background()
	w := newACMEWorld(t, "http-01")
	var token string
	w.fake.validator = func(typ, identifier, tok string) bool {
		token = tok
		return w.validate(t, 1, typ, identifier, tok)
	}
	if err := w.workers[0].Reconcile(ctx, w.key()); err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("no challenge validated")
	}
	// Completed challenges are no longer answered.
	rec := httptest.NewRecorder()
	w.nodes[1].HTTPHandler(nil).ServeHTTP(rec, httptest.NewRequest("GET", "http://login.acme.test/.well-known/acme-challenge/"+token, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("completed challenge = %d", rec.Code)
	}
}

func TestCertificateRenewal(t *testing.T) {
	ctx := context.Background()
	w := newACMEWorld(t, "http-01")
	if err := w.workers[0].Reconcile(ctx, w.key()); err != nil {
		t.Fatal(err)
	}
	d := w.current(t)
	cert, _ := w.st.TLSAssets().Get(ctx, d.ActiveCertificateKey)
	nb, na := cert.PublicData.NotBefore, cert.PublicData.NotAfter
	life := na.Sub(nb)
	start := nb.Add(life * 2 / 3)
	if d.NextAttemptAt == nil || d.NextAttemptAt.Before(start) || !d.NextAttemptAt.Before(start.Add(life/20+time.Second)) || !d.NextAttemptAt.Before(na) {
		t.Fatalf("renewal at %v for %v..%v", d.NextAttemptAt, nb, na)
	}
	if got := certificates.RenewalTime(w.key(), nb, na); !got.Equal(*d.NextAttemptAt) {
		t.Fatal("renewal jitter is not deterministic")
	}
	// A rate-limited renewal keeps the domain ready on its valid certificate
	// and honors Retry-After.
	w.clock.set(*d.NextAttemptAt)
	w.fake.finalizeErr = func() error {
		return &acme.Error{StatusCode: 429, ProblemType: "urn:ietf:params:acme:error:rateLimited", Header: http.Header{"Retry-After": {"7200"}}}
	}
	if err := w.workers[0].Reconcile(ctx, w.key()); err == nil {
		t.Fatal("rate limit reported as success")
	}
	d = w.current(t)
	if d.Lifecycle != customdomain.LifecycleRenewalError || !customdomain.Usable(d) || d.ActiveCertificateKey != cert.Key {
		t.Fatalf("after renewal error = %+v", d)
	}
	if wait := d.NextAttemptAt.Sub(w.clock.now()); wait < 2*time.Hour || wait > 6*time.Hour {
		t.Fatalf("retry after %s", wait)
	}
	if _, err := w.nodes[0].GetCertificate(&tls.ClientHelloInfo{ServerName: "login.acme.test"}); err != nil {
		t.Fatalf("old certificate not served during renewal error: %v", err)
	}
	// Expiry denies TLS even though renewal keeps failing.
	w.clock.set(na)
	if _, err := w.nodes[0].GetCertificate(&tls.ClientHelloInfo{ServerName: "login.acme.test"}); err == nil {
		t.Fatal("expired certificate served")
	}
	// A later successful renewal replaces it.
	w.fake.finalizeErr = nil
	if err := w.workers[1].Reconcile(ctx, w.key()); err != nil {
		t.Fatal(err)
	}
	if d := w.current(t); d.Lifecycle != customdomain.LifecycleActive || d.ActiveCertificateKey == "" {
		t.Fatalf("after renewal = %+v", d)
	}
	if _, err := w.nodes[0].GetCertificate(&tls.ClientHelloInfo{ServerName: "login.acme.test"}); err != nil {
		t.Fatalf("renewed certificate not served: %v", err)
	}
}

// Ownership is re-proven before every issuance.
func TestACMERequiresProof(t *testing.T) {
	ctx := context.Background()
	w := newACMEWorld(t, "http-01")
	delete(w.dns.txt, w.d.ProofRecordName)
	if err := w.workers[0].Reconcile(ctx, w.key()); err == nil {
		t.Fatal("issued without proof")
	}
	if w.fake.newOrders != 0 || customdomain.Usable(w.current(t)) {
		t.Fatal("ordered without proof")
	}
}

func TestWorkerRunStops(t *testing.T) {
	w := newACMEWorld(t, "http-01")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.workers[0].Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for !customdomain.Usable(w.current(t)) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if !customdomain.Usable(w.current(t)) {
		t.Fatal("Run did not issue the due domain")
	}
}

func TestChallengeRouting(t *testing.T) {
	ctx := context.Background()
	w := newACMEWorld(t, "http-01")
	if err := w.nodes[0].PublishChallengeForTest(ctx, "http-01", "login.acme.test", "tok", "tok.thumb", w.clock.now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	h := w.nodes[1].HTTPHandler(nil)
	do := func(method, target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
		return rec
	}
	if rec := do("GET", "http://login.acme.test/.well-known/acme-challenge/tok"); rec.Code != 200 || rec.Body.String() != "tok.thumb" {
		t.Fatalf("GET = %d %q", rec.Code, rec.Body)
	}
	if rec := do("HEAD", "http://login.acme.test/.well-known/acme-challenge/tok"); rec.Code != 200 {
		t.Fatalf("HEAD = %d", rec.Code)
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"wrong host":    do("GET", "http://other.acme.test/.well-known/acme-challenge/tok"),
		"unknown token": do("GET", "http://login.acme.test/.well-known/acme-challenge/nope"),
		"subpath":       do("GET", "http://login.acme.test/.well-known/acme-challenge/tok/x"),
		"unregistered":  do("GET", "http://evil.test/login?x=1"),
		"pending host":  do("GET", "http://login.acme.test/"),
	} {
		if rec.Code != http.StatusNotFound || rec.Header().Get("Location") != "" {
			t.Errorf("%s = %d %q", name, rec.Code, rec.Header().Get("Location"))
		}
	}
	if rec := do("POST", "http://login.acme.test/.well-known/acme-challenge/tok"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST challenge = %d", rec.Code)
	}
	// Active registered hosts redirect GET/HEAD to HTTPS; unsafe methods fail.
	if rec := do("GET", "http://acme.auth.example.test/authorize?client_id=a&x=%2F"); rec.Code != http.StatusPermanentRedirect ||
		rec.Header().Get("Location") != "https://acme.auth.example.test/authorize?client_id=a&x=%2F" {
		t.Errorf("redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do("POST", "http://acme.auth.example.test/oauth/token"); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Location") != "" {
		t.Errorf("POST redirect = %d", rec.Code)
	}
	// Expiry is exclusive at its instant.
	w.clock.add(time.Hour)
	if rec := do("GET", "http://login.acme.test/.well-known/acme-challenge/tok"); rec.Code != http.StatusNotFound {
		t.Errorf("expired challenge = %d", rec.Code)
	}

	// TLS-ALPN: challenge certificates only for acme-tls/1 with a live
	// challenge; ordinary handshakes never see them.
	if err := w.nodes[0].PublishChallengeForTest(ctx, "tls-alpn-01", "login.acme.test", "alpn-tok", "", w.clock.now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c, err := w.nodes[1].GetCertificate(&tls.ClientHelloInfo{ServerName: "login.acme.test", SupportedProtos: []string{"acme-tls/1"}})
	if err != nil {
		t.Fatal(err)
	}
	if leaf, _ := x509.ParseCertificate(c.Certificate[0]); leaf.Subject.CommonName != "alpn-tok" {
		t.Fatalf("challenge cert = %v", leaf.Subject)
	}
	if _, err := w.nodes[1].GetCertificate(&tls.ClientHelloInfo{ServerName: "login.acme.test", SupportedProtos: []string{"h2"}}); err == nil {
		t.Fatal("ordinary handshake got the challenge certificate")
	}
	if _, err := w.nodes[1].GetCertificate(&tls.ClientHelloInfo{ServerName: "other.acme.test", SupportedProtos: []string{"acme-tls/1"}}); err == nil {
		t.Fatal("challenge certificate for another name")
	}
}
