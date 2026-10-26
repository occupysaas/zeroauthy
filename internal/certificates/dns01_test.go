package certificates_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/certificates"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/tests/e2e/domains/dns"
	"github.com/zeroauthy/zeroauthy/tests/e2e/domains/provider"
)

const doToken = "dop_v1_secret-token-value"

func fakeDO(t *testing.T) (*provider.Server, *certificates.DigitalOcean) {
	t.Helper()
	srv := provider.New(doToken, "example.test")
	h := httptest.NewServer(srv)
	t.Cleanup(h.Close)
	return srv, certificates.NewDigitalOcean(doToken, certificates.WithEndpoint(h.URL, h.Client(), 500*time.Millisecond))
}

func TestDigitalOceanAdapter(t *testing.T) {
	ctx := context.Background()
	srv, do := fakeDO(t)
	keep := srv.Add("_acme-challenge.auth", "someone-else")
	rec, err := do.Present(ctx, "example.test", "_acme-challenge.auth.example.test", "v1")
	if err != nil || !rec.Created || rec.ID == "" || rec.Zone != "example.test" {
		t.Fatalf("present = %+v, %v", rec, err)
	}
	// The request used the zone-relative name and the bearer token.
	if got := srv.TXT("_acme-challenge.auth.example.test"); !slices.Contains(got, "v1") || !slices.Contains(got, "someone-else") {
		t.Fatalf("records = %v", got)
	}
	// An existing identical value is reported as not created by us.
	again, err := do.Present(ctx, "example.test", "_acme-challenge.auth.example.test", "v1")
	if err != nil || again.Created || again.ID != rec.ID {
		t.Fatalf("existing = %+v, %v", again, err)
	}
	found, n, err := do.Find(ctx, "example.test", "_acme-challenge.auth.example.test", "v1")
	if err != nil || n != 1 || found.ID != rec.ID {
		t.Fatalf("find = %+v %d %v", found, n, err)
	}
	if err := do.CleanUp(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if got := srv.TXT("_acme-challenge.auth.example.test"); !slices.Equal(got, []string{"someone-else"}) {
		t.Fatalf("after cleanup = %v (kept id %d)", got, keep)
	}
	// Not-created records are never deleted.
	if err := do.CleanUp(ctx, certificates.DNSRecord{ID: "1001", Zone: "example.test", Name: "x", Value: "y"}); err == nil {
		t.Fatal("deleted a record it did not create")
	}
	if _, err := do.Present(ctx, "example.test", "_acme-challenge.other.test", "v"); err == nil {
		t.Fatal("name outside the zone accepted")
	}
	// Errors never carry the token; rate limits and timeouts surface.
	srv.BeforeCreate = func() int { return http.StatusTooManyRequests }
	_, err = do.Present(ctx, "example.test", "_acme-challenge.auth.example.test", "v2")
	var rl *certificates.ProviderRateLimit
	if !errors.As(err, &rl) || rl.RetryAfter != 30*time.Second || strings.Contains(err.Error(), doToken) {
		t.Fatalf("rate limit = %v", err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(2 * time.Second) }))
	defer slow.Close()
	bounded := certificates.NewDigitalOcean(doToken, certificates.WithEndpoint(slow.URL, slow.Client(), 200*time.Millisecond))
	start := time.Now()
	if _, err := bounded.Present(ctx, "example.test", "_acme-challenge.auth.example.test", "v"); err == nil || time.Since(start) > time.Second || strings.Contains(err.Error(), doToken) {
		t.Fatalf("timeout = %v after %s", err, time.Since(start))
	}
}

// hostedWorld: base auth.example.test inside zone example.test, tenants acme
// and system, a fake provider whose records the local DNS serves, and two
// worker nodes.
type hostedWorld struct {
	*acmeWorld
	srv  *provider.Server
	dns  *dns.Server
	host [2]*certificates.Worker
	cfg  certificates.HostedConfig
}

func newHostedWorld(t *testing.T) *hostedWorld {
	t.Helper()
	w := newACMEWorld(t, "http-01")
	ctx := context.Background()
	if err := w.st.Tenants().Create(ctx, &store.Tenant{ID: "sys", Name: "system", Reserved: true, CanonicalHost: "system.auth.example.test"}); err != nil {
		t.Fatal(err)
	}
	srv, do := fakeDO(t)
	d := &dns.Server{A: [4]byte{127, 0, 0, 1}, TXT: srv.TXT}
	if err := d.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	hw := &hostedWorld{acmeWorld: w, srv: srv, dns: d}
	hw.cfg = certificates.HostedConfig{
		BaseDomain: "auth.example.test", Zone: "example.test", Provider: do,
		Resolver:           &customdomain.BoundedResolver{Server: d.Addr(), Timeout: time.Second},
		PropagationTimeout: 2 * time.Second, PollMin: 20 * time.Millisecond, PollMax: 50 * time.Millisecond,
	}
	for i := range hw.host {
		hw.host[i] = certificates.NewWorker(w.nodes[i], w.fake, w.domains, certificates.WorkerConfig{
			Owner: "hosted-" + string(rune('a'+i)), Email: "ops@example.test", Challenge: "http-01", Roots: w.ca.pool, Hosted: &hw.cfg,
		})
	}
	w.fake.validator = func(typ, identifier, token string) bool {
		if typ != "dns-01" {
			return false
		}
		return slices.Contains(srv.TXT("_acme-challenge."+identifier), token+".dns")
	}
	return hw
}

func (hw *hostedWorld) key() string {
	return certificates.HostedResource("prod-1", "auth.example.test")
}

func hostedManager(t *testing.T, hw *hostedWorld) *certificates.Manager {
	t.Helper()
	m, err := certificates.NewManager(hw.st, wrapper(t, 1), certificates.Config{DeploymentID: "prod-1", DirectoryURL: "https://ca.test/directory", BaseDomain: "auth.example.test", HostedWildcard: true}, hw.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHostedWildcard(t *testing.T) {
	ctx := context.Background()
	hw := newHostedWorld(t)
	pre := hw.srv.Add("_acme-challenge.auth", "pre-existing")
	if err := hw.host[0].Reconcile(ctx, hw.key()); err != nil {
		t.Fatal(err)
	}
	asset, err := hw.st.TLSAssets().Get(ctx, certificates.HostedWildcardKey)
	if err != nil || !slices.Equal(asset.PublicData.SANs, []string{"auth.example.test", "*.auth.example.test"}) {
		t.Fatalf("hosted asset = %+v, %v", asset, err)
	}
	// Only created challenge records were removed.
	if got := hw.srv.TXT("_acme-challenge.auth.example.test"); !slices.Equal(got, []string{"pre-existing"}) {
		t.Fatalf("records after issuance = %v (pre-existing id %d)", got, pre)
	}
	m := hostedManager(t, hw)
	for _, sni := range []string{"acme.auth.example.test", "system.auth.example.test"} {
		if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: sni}); err != nil {
			t.Errorf("%s: %v", sni, err)
		}
	}
	for _, sni := range []string{"a.b.auth.example.test", "login.acme.test", "nobody.auth.example.test"} {
		if _, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: sni}); err == nil {
			t.Errorf("%s served", sni)
		}
	}
	// Not due again until renewal; a second node does nothing meanwhile.
	orders := hw.fake.newOrders
	if err := hw.host[1].Reconcile(ctx, hw.key()); err != nil || hw.fake.newOrders != orders {
		t.Fatalf("early renewal: %v, orders %d→%d", err, orders, hw.fake.newOrders)
	}
	// At renewal time the other node renews it.
	hw.clock.set(certificates.RenewalTime(hw.key(), asset.PublicData.NotBefore, asset.PublicData.NotAfter))
	if err := hw.host[1].Reconcile(ctx, hw.key()); err != nil || hw.fake.newOrders != orders+1 {
		t.Fatalf("renewal: %v, orders %d→%d", err, orders, hw.fake.newOrders)
	}
	renewed, _ := hw.st.TLSAssets().Get(ctx, certificates.HostedWildcardKey)
	if !renewed.PublicData.NotBefore.After(asset.PublicData.NotBefore) {
		t.Fatal("hosted certificate not replaced")
	}
}

func TestDNS01RecordOwnership(t *testing.T) {
	ctx := context.Background()
	hw := newHostedWorld(t)
	// Apex and wildcard values coexist at one name while the CA validates.
	most := 0
	validate := hw.fake.validator
	hw.fake.validator = func(typ, identifier, token string) bool {
		most = max(most, len(hw.srv.TXT("_acme-challenge."+identifier)))
		return validate(typ, identifier, token)
	}
	if err := hw.host[0].Reconcile(ctx, hw.key()); err != nil {
		t.Fatal(err)
	}
	if most != 2 {
		t.Fatalf("values visible during validation = %d", most)
	}
	creates := 0
	for _, c := range hw.srv.Calls {
		if strings.HasPrefix(c, "POST ") {
			creates++
		}
	}
	if creates != 2 {
		t.Fatalf("creates = %d (%v)", creates, hw.srv.Calls)
	}
	if left := hw.srv.Records(); len(left) != 0 {
		t.Fatalf("records left = %v", left)
	}
}

func TestDNS01CrashRecovery(t *testing.T) {
	ctx := context.Background()
	hw := newHostedWorld(t)
	// The first create succeeds at the provider but its reply is lost.
	dropped := false
	hw.srv.AfterCreate = func(provider.Record) bool {
		if dropped {
			return false
		}
		dropped = true
		return true
	}
	if err := hw.host[0].Reconcile(ctx, hw.key()); err == nil {
		t.Fatal("lost reply reported success")
	}
	if n := len(hw.srv.Records()); n != 1 {
		t.Fatalf("records after lost reply = %d", n)
	}
	lost := hw.srv.Records()[0]
	// An external duplicate of a value must not be adopted or deleted; the
	// lost record (unique value) is adopted and cleaned up.
	hw.clock.add(10 * time.Minute)
	if err := hw.host[1].Reconcile(ctx, hw.key()); err != nil {
		t.Fatal(err)
	}
	for _, r := range hw.srv.Records() {
		if r.ID == lost.ID {
			t.Fatal("adopted lost record was not cleaned up")
		}
	}
	if _, err := hw.st.TLSAssets().Get(ctx, certificates.HostedWildcardKey); err != nil {
		t.Fatal("no hosted certificate after recovery")
	}
}

func TestDNS01DuplicateNotAdopted(t *testing.T) {
	ctx := context.Background()
	hw := newHostedWorld(t)
	dropped := false
	hw.srv.AfterCreate = func(r provider.Record) bool {
		if dropped {
			return false
		}
		dropped = true
		hw.srv.Add(r.Name, r.Data) // an external copy of the same value
		return true
	}
	if err := hw.host[0].Reconcile(ctx, hw.key()); err == nil {
		t.Fatal("lost reply reported success")
	}
	value := hw.srv.Records()[0].Data
	hw.clock.add(10 * time.Minute)
	_ = hw.host[1].Reconcile(ctx, hw.key())
	count := 0
	for _, r := range hw.srv.Records() {
		if r.Data == value {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("ambiguous records deleted: %d of 2 remain", count)
	}
}

func TestDNS01Delegation(t *testing.T) {
	for name, setup := range map[string]func(*dns.Server){
		"cname": func(d *dns.Server) {
			d.CNAME = func(n string) string {
				if n == "_acme-challenge.auth.example.test" {
					return "elsewhere.test"
				}
				return ""
			}
		},
		"ns": func(d *dns.Server) {
			d.NS = func(n string) []string {
				if n == "auth.example.test" {
					return []string{"ns.elsewhere.test"}
				}
				return nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			hw := newHostedWorld(t)
			hw.dns.Set(setup)
			if err := hw.host[0].Reconcile(context.Background(), hw.key()); err == nil || !strings.Contains(err.Error(), "delegat") {
				t.Fatalf("delegation = %v", err)
			}
			if len(hw.srv.Records()) != 0 {
				t.Fatal("wrote records despite delegation")
			}
		})
	}
}

func TestDNS01Propagation(t *testing.T) {
	hw := newHostedWorld(t)
	hw.dns.Set(func(d *dns.Server) { d.TXT = func(string) []string { return nil } }) // never visible
	start := time.Now()
	err := hw.host[0].Reconcile(context.Background(), hw.key())
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("propagation = %v after %s", err, time.Since(start))
	}
	if len(hw.srv.Records()) != 0 {
		t.Fatal("records left after a failed attempt")
	}
	// Cancellation stops waiting promptly.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	hw.clock.add(10 * time.Minute)
	start = time.Now()
	if err := hw.host[1].Reconcile(ctx, hw.key()); err == nil || time.Since(start) > time.Second {
		t.Fatalf("cancel = %v after %s", err, time.Since(start))
	}
}

func TestDNS01StaleWorkerCannotCleanSuccessorRecord(t *testing.T) {
	hw := newHostedWorld(t)
	ctx := context.Background()
	successorReady := make(chan struct{})
	releaseSuccessor := make(chan struct{})
	successorDone := make(chan error, 1)
	var calls atomic.Int32
	var adopted []provider.Record
	hw.fake.acceptErr = func() error {
		switch calls.Add(1) {
		case 1:
			adopted = hw.srv.Records()
			if len(adopted) != 2 {
				return errors.New("missing apex/wildcard values")
			}
			hw.clock.add(121 * time.Second)
			go func() { successorDone <- hw.host[1].Reconcile(ctx, hw.key()) }()
			select {
			case <-successorReady:
			case <-time.After(5 * time.Second):
				return errors.New("successor failed to resume order")
			}
			return errors.New("delayed CA response after takeover")
		case 2:
			close(successorReady)
			<-releaseSuccessor
		}
		return nil
	}
	if err := hw.host[0].Reconcile(ctx, hw.key()); err == nil {
		t.Error("stale worker reported success")
	}
	for _, r := range adopted {
		if !slices.Contains(hw.srv.TXT("_acme-challenge.auth.example.test"), r.Data) {
			t.Errorf("stale cleanup removed successor's TXT record ID %d", r.ID)
		}
	}
	close(releaseSuccessor)
	select {
	case err := <-successorDone:
		if err != nil {
			t.Fatalf("resumed order: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("successor did not finish")
	}
	if hw.fake.newOrders != 1 {
		t.Fatalf("successor did not reuse the saved order: %d", hw.fake.newOrders)
	}
	if len(hw.srv.Records()) != 0 {
		t.Fatal("current owner failed to clean records")
	}
}

// Finishing near expiry must renew ownership before a bounded external delete,
// so a normal lease takeover cannot happen in the middle of that request.
func TestDNS01CleanupRenewsLeaseBeforeProviderCall(t *testing.T) {
	hw := newHostedWorld(t)
	ctx := context.Background()
	original := hw.cfg.Provider
	hw.cfg.Provider = &cleanupHookProvider{DNSProvider: original, before: func() {
		hw.clock.add(2 * time.Second)
		if _, err := hw.st.TLSAssets().ClaimLease(ctx, hw.key(), "competing-cleanup", 120*time.Second); !errors.Is(err, store.ErrConflict) {
			t.Errorf("cleanup allowed a normal takeover during provider call: %v", err)
		}
	}}
	hw.fake.acceptErr = func() error { hw.clock.add(119 * time.Second); return errors.New("near-expiry cleanup") }
	if err := hw.host[0].Reconcile(ctx, hw.key()); err == nil {
		t.Fatal("fixture failure missing")
	}
}

type cleanupHookProvider struct {
	certificates.DNSProvider
	before func()
}

func (p *cleanupHookProvider) CleanUp(ctx context.Context, r certificates.DNSRecord) error {
	p.before()
	return p.DNSProvider.CleanUp(ctx, r)
}
