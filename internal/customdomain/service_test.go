package customdomain_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// fakeDNS answers TXT lookups from a mutable table; err overrides a name.
type fakeDNS struct {
	mu   sync.Mutex
	txt  map[string][]string
	errs map[string]error
}

func (f *fakeDNS) set(name string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.errs, name)
	f.txt[name] = values
}
func (f *fakeDNS) fail(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[name] = err
}
func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errs[name]; err != nil {
		return nil, err
	}
	v, ok := f.txt[name]
	if !ok {
		return nil, customdomain.ErrDNSNotFound
	}
	return v, nil
}
func (f *fakeDNS) LookupCNAME(context.Context, string) (string, error) {
	return "", customdomain.ErrDNSNotFound
}
func (f *fakeDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return nil, customdomain.ErrDNSNotFound
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time)     { c.mu.Lock(); defer c.mu.Unlock(); c.t = t }
func (c *clock) add(d time.Duration) { c.set(c.now().Add(d)) }

type fixture struct {
	st  *memory.Store
	dns *fakeDNS
	clk *clock
	svc *customdomain.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
	st := memory.NewWithClock(clk.now)
	ctx := context.Background()
	for _, n := range []string{"acme", "globex"} {
		if err := st.Tenants().Create(ctx, &store.Tenant{ID: n, Name: n, CanonicalHost: n + ".auth.example.test"}); err != nil {
			t.Fatal(err)
		}
	}
	dns := &fakeDNS{txt: map[string][]string{}, errs: map[string]error{}}
	cfg := customdomain.ServiceConfig{BaseDomain: "auth.example.test", SystemHost: "system.auth.example.test", OriginDomain: "auth.example.test", ManagedEnabled: true, OriginTLSReady: true}
	return &fixture{st: st, dns: dns, clk: clk, svc: customdomain.NewService(st, dns, cfg, clk.now, rand.Reader)}
}

func (f *fixture) create(t *testing.T, tenantID, domain, typ string) *store.CustomDomain {
	t.Helper()
	d, err := f.svc.Create(context.Background(), tenantID, customdomain.CreateInput{
		Domain: domain, Type: typ,
		TLSPolicy:            customdomain.Field[string]{Value: "recommended"},
		CustomClientIPHeader: customdomain.Field[string]{Value: "x-forwarded-for"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// publish puts the correct proof for d into DNS.
func (f *fixture) publish(d *store.CustomDomain) {
	f.dns.set(d.ProofRecordName, customdomain.ProofValue(d))
}

func (f *fixture) get(t *testing.T, d *store.CustomDomain) *store.CustomDomain {
	t.Helper()
	cur, err := f.st.CustomDomains().Get(context.Background(), d.TenantID, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	return cur
}

func TestDomainProof(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	d := f.create(t, "acme", "login.acme.test", customdomain.TypeManaged)
	if d.ProofRecordName != "_zeroauthy-domain-verification.login.acme.test" || d.ProofRecordValue != customdomain.ProofValue(d) || len(d.ProofToken) != 32 {
		t.Fatalf("proof = %q %q", d.ProofRecordName, d.ProofRecordValue)
	}
	// Values bound to another tenant, ID or generation never match.
	for _, other := range []store.CustomDomain{
		{TenantID: "globex", ID: d.ID, Generation: d.Generation, ProofToken: d.ProofToken},
		{TenantID: d.TenantID, ID: "cd_other", Generation: d.Generation, ProofToken: d.ProofToken},
		{TenantID: d.TenantID, ID: d.ID, Generation: d.Generation + 1, ProofToken: d.ProofToken},
	} {
		f.dns.set(d.ProofRecordName, customdomain.ProofValue(&other), "unrelated")
		res, err := f.svc.Verify(ctx, "acme", d.ID)
		if err != nil || res.Domain.ProofStatus != customdomain.ProofPending || res.Domain.Status != customdomain.StatusPending {
			t.Fatalf("foreign proof = %+v, %v", res.Domain, err)
		}
		f.clk.add(31 * time.Second)
	}
	f.dns.fail(d.ProofRecordName, customdomain.ErrDNSNotFound)
	if res, err := f.svc.Verify(ctx, "acme", d.ID); err != nil || res.Domain.ProofStatus != customdomain.ProofPending || res.Domain.LastFailure == "" {
		t.Fatalf("nxdomain = %+v, %v", res.Domain, err)
	}
	f.clk.add(31 * time.Second)
	// A value split across chunks arrives joined; prefix-only values fail.
	f.dns.set(d.ProofRecordName, customdomain.ProofValue(d)[:20])
	if res, _ := f.svc.Verify(ctx, "acme", d.ID); res.Domain.ProofStatus != customdomain.ProofPending {
		t.Fatal("partial value accepted")
	}
	f.clk.add(31 * time.Second)
	f.publish(d)
	res, err := f.svc.Verify(ctx, "acme", d.ID)
	if err != nil || res.Domain.ProofStatus != customdomain.ProofVerified || res.CNAMEAPIKey != "" {
		t.Fatalf("verified = %+v, %v", res, err)
	}
	// Managed proof queues certificate work; it is not ready yet.
	if res.Domain.Lifecycle != customdomain.LifecycleIssuing || res.Domain.Status != customdomain.StatusPending || customdomain.Usable(res.Domain) {
		t.Fatalf("managed after proof = %+v", res.Domain)
	}
	if res.Domain.NextAttemptAt == nil || res.Domain.NextAttemptAt.After(f.clk.now()) {
		t.Fatal("certificate work not queued")
	}
	if _, err := customdomain.ResolveHost(ctx, f.st, "login.acme.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("managed domain routes before a certificate: %v", err)
	}
}

func TestDomainVerificationBudgets(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	d := f.create(t, "acme", "a0.acme.test", customdomain.TypeManaged)
	if _, err := f.svc.Verify(ctx, "acme", d.ID); err != nil {
		t.Fatal(err)
	}
	f.clk.add(29 * time.Second)
	var rl *customdomain.RateLimitError
	if _, err := f.svc.Verify(ctx, "acme", d.ID); !errors.As(err, &rl) || rl.RetryAfter != time.Second {
		t.Fatalf("per-domain limit = %v", err)
	}
	f.clk.add(time.Second)
	if _, err := f.svc.Verify(ctx, "acme", d.ID); err != nil {
		t.Fatalf("at 30s = %v", err)
	}
	// Twenty tenant attempts per minute, counting the two above.
	f.clk.add(time.Minute)
	ids := []string{}
	for i := range 21 {
		ids = append(ids, f.create(t, "acme", "b"+string(rune('a'+i))+".acme.test", customdomain.TypeManaged).ID)
	}
	for i, id := range ids {
		_, err := f.svc.Verify(ctx, "acme", id)
		if i < 20 && err != nil {
			t.Fatalf("attempt %d = %v", i, err)
		}
		if i == 20 && !errors.As(err, &rl) {
			t.Fatalf("21st attempt = %v", err)
		}
	}
	// Another tenant has its own budget.
	g := f.create(t, "globex", "g.globex.test", customdomain.TypeManaged)
	if _, err := f.svc.Verify(ctx, "globex", g.ID); err != nil {
		t.Fatalf("other tenant = %v", err)
	}
}

func TestDomainRetrySchedule(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	d := f.create(t, "acme", "login.acme.test", customdomain.TypeManaged)
	created := f.clk.now()
	within := func(got *time.Time, from time.Time, want time.Duration) {
		t.Helper()
		if got == nil {
			t.Fatalf("no next attempt, want %s", want)
		}
		delta := got.Sub(from)
		if delta < want-want/10 || delta > want+want/10 {
			t.Fatalf("next attempt after %s, want %s ±10%%", delta, want)
		}
	}
	within(d.NextAttemptAt, created, time.Minute)
	for _, want := range []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour, 6 * time.Hour} {
		f.clk.set(*f.get(t, d).NextAttemptAt)
		if err := f.svc.CheckDue(ctx); err != nil {
			t.Fatal(err)
		}
		within(f.get(t, d).NextAttemptAt, f.clk.now(), want)
	}
	// Retries pause at 72h of pending verification.
	for f.get(t, d).Lifecycle == customdomain.LifecycleProofPending {
		if f.clk.now().After(created.Add(80 * time.Hour)) {
			t.Fatal("retries did not pause after 72h")
		}
		f.clk.set(*f.get(t, d).NextAttemptAt)
		if err := f.svc.CheckDue(ctx); err != nil {
			t.Fatal(err)
		}
	}
	cur := f.get(t, d)
	if f.clk.now().Before(created.Add(72*time.Hour)) || cur.Status != customdomain.StatusFailed || cur.NextAttemptAt != nil {
		t.Fatalf("paused at %s: %+v", f.clk.now().Sub(created), cur)
	}
	// Manual verification restarts the schedule with the same proof.
	res, err := f.svc.Verify(ctx, "acme", d.ID)
	if err != nil || res.Domain.Lifecycle != customdomain.LifecycleProofPending || res.Domain.Status != customdomain.StatusPending ||
		res.Domain.ProofRecordValue != d.ProofRecordValue {
		t.Fatalf("restart = %+v, %v", res.Domain, err)
	}
	within(res.Domain.NextAttemptAt, f.clk.now(), time.Minute)
	// The background proof then succeeds without another manual call.
	f.publish(d)
	f.clk.set(*res.Domain.NextAttemptAt)
	if err := f.svc.CheckDue(ctx); err != nil {
		t.Fatal(err)
	}
	if cur := f.get(t, d); cur.Lifecycle != customdomain.LifecycleIssuing {
		t.Fatalf("background proof = %+v", cur)
	}
}

// noLimit lets concurrent verifications reach the store together.
type noLimit struct{ *memory.Store }
type noLimitDomains struct{ store.CustomDomains }

func (s noLimit) CustomDomains() store.CustomDomains { return noLimitDomains{s.Store.CustomDomains()} }
func (noLimitDomains) AdmitAttempt(context.Context, string, string) (time.Duration, error) {
	return 0, nil
}

func TestDomainOneTimeKey(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	d := f.create(t, "acme", "login.acme.test", customdomain.TypeSelfManaged)
	if d.OriginHost == "" || d.ProxyKeyHash != nil {
		t.Fatalf("self-managed create = %+v", d)
	}
	f.publish(d)
	// Background proof never activates or creates a key.
	f.clk.set(*d.NextAttemptAt)
	if err := f.svc.CheckDue(ctx); err != nil {
		t.Fatal(err)
	}
	if cur := f.get(t, d); cur.Status != customdomain.StatusPending || cur.ProxyKeyHash != nil || cur.ProofStatus != customdomain.ProofVerified {
		t.Fatalf("background self-managed = %+v", cur)
	}
	svc := customdomain.NewService(noLimit{f.st}, f.dns, customdomain.ServiceConfig{OriginDomain: "auth.example.test", OriginTLSReady: true}, f.clk.now, rand.Reader)
	var wg sync.WaitGroup
	keys := make(chan string, 8)
	for range 8 {
		wg.Go(func() {
			res, err := svc.Verify(ctx, "acme", d.ID)
			if err != nil {
				t.Error(err)
				return
			}
			if res.Domain.Status != customdomain.StatusReady {
				t.Errorf("status = %s", res.Domain.Status)
			}
			keys <- res.CNAMEAPIKey
		})
	}
	wg.Wait()
	close(keys)
	var winners []string
	for k := range keys {
		if k != "" {
			winners = append(winners, k)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("key winners = %d", len(winners))
	}
	cur := f.get(t, d)
	if !bytes.Equal(cur.ProxyKeyHash, customdomain.HashProxyKey(winners[0])) || bytes.Contains(cur.ProxyKeyHash, []byte(winners[0])) {
		t.Fatal("stored key is not the hash of the returned key")
	}
	if res, err := svc.Verify(ctx, "acme", d.ID); err != nil || res.CNAMEAPIKey != "" {
		t.Fatalf("repeat verify = %+v, %v", res, err)
	}
	for _, host := range []string{"login.acme.test", cur.OriginHost} {
		h, err := f.st.CustomDomains().GetHost(ctx, host)
		if err != nil || !h.Active {
			t.Fatalf("binding %s = %+v, %v", host, h, err)
		}
	}
	if _, err := customdomain.ResolveHost(ctx, f.st, cur.OriginHost); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("origin alias resolves as a browser host")
	}
	tn, _ := f.st.Tenants().Get(ctx, "acme")
	if !containsHost(tn.Domains, "login.acme.test") || containsHost(tn.Domains, cur.OriginHost) {
		t.Fatalf("projection = %v", tn.Domains)
	}
}

func containsHost(hosts []string, h string) bool {
	for _, x := range hosts {
		if x == h {
			return true
		}
	}
	return false
}

// failingUpdate makes the verification commit fail.
type failingUpdate struct{ *memory.Store }

func (s failingUpdate) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error {
		if err := fn(tx); err != nil {
			return err
		}
		return errors.New("commit failed")
	})
}

func TestDomainOneTimeKeyStoreFailure(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	d := f.create(t, "acme", "login.acme.test", customdomain.TypeSelfManaged)
	f.publish(d)
	svc := customdomain.NewService(failingUpdate{f.st}, f.dns, customdomain.ServiceConfig{OriginDomain: "auth.example.test", OriginTLSReady: true}, f.clk.now, rand.Reader)
	if res, err := svc.Verify(ctx, "acme", d.ID); err == nil || res.CNAMEAPIKey != "" {
		t.Fatalf("failed commit = %+v, %v", res, err)
	}
	if cur := f.get(t, d); cur.ProxyKeyHash != nil || cur.Status == customdomain.StatusReady {
		t.Fatalf("rolled back = %+v", cur)
	}
}

func TestDomainLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	in := customdomain.CreateInput{Domain: "x.acme.test", Type: customdomain.TypeManaged}
	off := customdomain.NewService(f.st, f.dns, customdomain.ServiceConfig{}, f.clk.now, rand.Reader)
	if _, err := off.Create(ctx, "acme", in); !errors.Is(err, customdomain.ErrManagedUnavailable) {
		t.Fatalf("managed disabled = %v", err)
	}
	in.Type = customdomain.TypeSelfManaged
	if _, err := off.Create(ctx, "acme", in); !errors.Is(err, customdomain.ErrOriginTLSUnavailable) {
		t.Fatalf("origin TLS missing = %v", err)
	}
	d := f.create(t, "acme", "login.acme.test", customdomain.TypeManaged)
	// Both names are claimed globally while pending.
	for _, host := range []string{d.Domain, d.OriginHost} {
		h, err := f.st.CustomDomains().GetHost(ctx, host)
		if err != nil || h.Active || h.TenantID != "acme" {
			t.Fatalf("pending claim %s = %+v, %v", host, h, err)
		}
	}
	if _, err := f.svc.Create(ctx, "globex", customdomain.CreateInput{Domain: "LOGIN.acme.test", Type: customdomain.TypeManaged}); err == nil {
		t.Fatal("second tenant claimed the name")
	}
	tn, _ := f.st.Tenants().Get(ctx, "acme")
	if containsHost(tn.Domains, d.Domain) {
		t.Fatal("pending name in the resolver projection")
	}
	// Recreation needs a fresh proof; the old record never verifies it.
	f.publish(d)
	if err := f.svc.Delete(ctx, "acme", d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.CustomDomains().GetHost(ctx, d.OriginHost); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("origin claim survived delete: %v", err)
	}
	again := f.create(t, "acme", "login.acme.test", customdomain.TypeManaged)
	if again.ID == d.ID || again.ProofRecordValue == d.ProofRecordValue || again.OriginHost == d.OriginHost {
		t.Fatal("recreation reused proof or identity")
	}
	if res, err := f.svc.Verify(ctx, "acme", again.ID); err != nil || res.Domain.ProofStatus != customdomain.ProofPending {
		t.Fatalf("stale proof = %+v, %v", res.Domain, err)
	}
}

// activeSelfManaged returns a ready self-managed domain.
func (f *fixture) activeSelfManaged(t *testing.T, tenantID, domain string) *store.CustomDomain {
	t.Helper()
	d := f.create(t, tenantID, domain, customdomain.TypeSelfManaged)
	f.publish(d)
	res, err := f.svc.Verify(context.Background(), tenantID, d.ID)
	if err != nil || res.CNAMEAPIKey == "" || !customdomain.Usable(res.Domain) {
		t.Fatalf("activate = %+v, %v", res, err)
	}
	return res.Domain
}

func TestDomainLossAndDefault(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	d := f.activeSelfManaged(t, "acme", "login.acme.test")
	other := f.create(t, "acme", "pending.acme.test", customdomain.TypeManaged)
	// No automatic default; pending domains cannot be selected.
	if def, err := f.svc.Default(ctx, "acme"); err != nil || def != nil {
		t.Fatalf("implicit default = %+v, %v", def, err)
	}
	if _, err := f.svc.SetDefault(ctx, "acme", other.Domain); !errors.Is(err, customdomain.ErrNotReady) {
		t.Fatalf("pending default = %v", err)
	}
	if _, err := f.svc.SetDefault(ctx, "globex", d.Domain); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant default = %v", err)
	}
	if got, err := f.svc.SetDefault(ctx, "acme", "Login.Acme.Test."); err != nil || got.ID != d.ID {
		t.Fatalf("default = %+v, %v", got, err)
	}
	if o, _ := f.svc.NotificationOrigin(ctx, "acme", ""); o != "login.acme.test" {
		t.Fatalf("implicit origin = %q", o)
	}

	// Loss: definite misses start a 24h window; resolver outages neither start
	// nor complete it.
	f.clk.set(*f.get(t, d).NextAttemptAt)
	f.dns.fail(d.ProofRecordName, errors.New("timeout"))
	if err := f.svc.CheckDue(ctx); err != nil {
		t.Fatal(err)
	}
	if cur := f.get(t, d); cur.ProofFailureSince != nil || !customdomain.Usable(cur) {
		t.Fatalf("timeout started loss = %+v", cur)
	}
	f.dns.fail(d.ProofRecordName, customdomain.ErrDNSNotFound)
	f.clk.set(*f.get(t, d).NextAttemptAt)
	if err := f.svc.CheckDue(ctx); err != nil {
		t.Fatal(err)
	}
	if f.get(t, d).ProofFailureSince == nil {
		t.Fatal("definite miss did not start the loss window")
	}
	// Recovery inside the window clears it.
	f.publish(d)
	f.clk.set(*f.get(t, d).NextAttemptAt)
	if err := f.svc.CheckDue(ctx); err != nil {
		t.Fatal(err)
	}
	if cur := f.get(t, d); cur.ProofFailureSince != nil || !customdomain.Usable(cur) {
		t.Fatalf("recovery = %+v", cur)
	}
	f.dns.fail(d.ProofRecordName, customdomain.ErrDNSNotFound)
	f.clk.set(*f.get(t, d).NextAttemptAt)
	if err := f.svc.CheckDue(ctx); err != nil {
		t.Fatal(err)
	}
	lossStart := *f.get(t, d).ProofFailureSince
	for f.clk.now().Before(lossStart.Add(24 * time.Hour)) {
		if cur := f.get(t, d); !customdomain.Usable(cur) {
			t.Fatalf("suspended after %s", f.clk.now().Sub(lossStart))
		}
		f.clk.set(*f.get(t, d).NextAttemptAt)
		if err := f.svc.CheckDue(ctx); err != nil {
			t.Fatal(err)
		}
	}
	cur := f.get(t, d)
	if cur.Lifecycle != customdomain.LifecycleSuspended || customdomain.Usable(cur) {
		t.Fatalf("after grace = %+v", cur)
	}
	if _, err := customdomain.ResolveHost(ctx, f.st, d.Domain); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("suspended domain still routes")
	}
	// The configured pointer stays for recovery; new links use canonical and
	// explicit selection of the unusable domain is refused.
	if def, _ := f.svc.Default(ctx, "acme"); def == nil || def.ID != d.ID {
		t.Fatalf("default pointer lost: %+v", def)
	}
	if o, err := f.svc.NotificationOrigin(ctx, "acme", ""); err != nil || o != "acme.auth.example.test" {
		t.Fatalf("implicit fallback = %q, %v", o, err)
	}
	if _, err := f.svc.NotificationOrigin(ctx, "acme", d.Domain); !errors.Is(err, customdomain.ErrDomainUnavailable) {
		t.Fatalf("explicit unusable = %v", err)
	}
	if o, err := f.svc.NotificationOrigin(ctx, "acme", "ACME.auth.example.test"); err != nil || o != "acme.auth.example.test" {
		t.Fatalf("explicit canonical = %q, %v", o, err)
	}
	if _, err := f.svc.NotificationOrigin(ctx, "globex", d.Domain); !errors.Is(err, customdomain.ErrDomainUnavailable) {
		t.Fatalf("cross-tenant explicit = %v", err)
	}
	// Re-proof reactivates with the established key; nothing is reissued.
	f.publish(d)
	f.clk.set(*cur.NextAttemptAt)
	if err := f.svc.CheckDue(ctx); err != nil {
		t.Fatal(err)
	}
	if again := f.get(t, d); !customdomain.Usable(again) || !bytes.Equal(again.ProxyKeyHash, d.ProxyKeyHash) {
		t.Fatalf("reactivation = %+v", again)
	}
	// Deleting the default falls back to canonical atomically.
	if err := f.svc.Delete(ctx, "acme", d.ID); err != nil {
		t.Fatal(err)
	}
	if def, err := f.svc.Default(ctx, "acme"); err != nil || def != nil {
		t.Fatalf("default after delete = %+v, %v", def, err)
	}
	if o, _ := f.svc.NotificationOrigin(ctx, "acme", ""); o != "acme.auth.example.test" {
		t.Fatalf("origin after delete = %q", o)
	}
	// Selecting canonical clears an explicit pointer.
	e := f.activeSelfManaged(t, "acme", "id.acme.test")
	if _, err := f.svc.SetDefault(ctx, "acme", e.Domain); err != nil {
		t.Fatal(err)
	}
	if got, err := f.svc.SetDefault(ctx, "acme", "acme.auth.example.test"); err != nil || got != nil {
		t.Fatalf("canonical default = %+v, %v", got, err)
	}
	if def, _ := f.svc.Default(ctx, "acme"); def != nil {
		t.Fatal("canonical selection kept a pointer")
	}
}
