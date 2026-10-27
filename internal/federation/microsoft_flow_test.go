package federation

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type observedAttempts struct {
	store.Federation
	creates int
}

func (a *observedAttempts) CreateAttempt(ctx context.Context, in *store.FederationAttempt) error {
	a.creates++
	return a.Federation.CreateAttempt(ctx, in)
}

type observedFlowStore struct {
	store.Store
	attempts *observedAttempts
}

func (s observedFlowStore) Federation() store.Federation                       { return s.attempts }
func (s observedFlowStore) MicrosoftFederationSupported(context.Context) error { return nil }

func TestMicrosoftFlowMetadata(t *testing.T) {
	for _, mode := range []string{"organizations", "consumers", testMicrosoftTenant} {
		for _, bad := range []bool{false, true} {
			t.Run(mode+map[bool]string{true: " invalid", false: " valid"}[bad], func(t *testing.T) {
				ctx := context.Background()
				st := memory.New()
				defer st.Close()
				w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{1}, 32))
				authority := mode
				issuer := testMicrosoftTemplate
				if mode == testMicrosoftTenant {
					issuer = testMicrosoftBase + "/" + mode + "/v2.0"
				}
				raw := microsoftTestMetadata(authority, issuer)
				if bad {
					raw["issuer"] = "https://evil.invalid/{tenantid}/v2.0"
				}
				ps, _, _, _ := microsoftDiscoveryFixture(t, raw)
				spec := connrules.Spec{Name: "ms", Strategy: StrategyWAAD, EnabledClients: []string{"client"}, Options: connrules.Options{Extra: map[string]any{"client_id": testMicrosoftTenant}}}
				if mode == "organizations" {
					spec.Options.Extra["useCommonEndpoint"] = true
				} else if mode == "consumers" {
					spec.Strategy = StrategyWindowsLive
				} else {
					spec.Options.Extra["tenant_domain"] = mode
				}
				c := &store.Connection{TenantID: "local", ID: "ms", FederationRevision: 1}
				connrules.Apply(&spec, c)
				c.FederationSecretsSealed, _ = SealCredentials(w, "local", "ms", Credentials{ClientSecret: "secret"})
				if err := st.Connections().Create(ctx, c); err != nil {
					t.Fatal(err)
				}
				attempts := &observedAttempts{Federation: st.Federation()}
				target := observedFlowStore{st, attempts}
				svc := FlowService{Service: Service{Wrapper: w, Now: func() time.Time { return fixedTime }}, Store: target, Providers: ps}
				in := BeginInput{Connection: c, Client: &store.Client{ClientID: "client", IsFirstParty: true}, Txn: &store.AuthTransaction{ID: "txn", ExpiresAt: fixedTime.Add(time.Hour)}, Origin: "https://local.example"}
				_ = st.Tenants().Create(ctx, &store.Tenant{ID: "local", Name: "local"})
				_ = st.Clients().Create(ctx, &store.Client{TenantID: "local", ClientID: "client", IsFirstParty: true})
				in.Txn.TenantID = "local"
				in.Txn.ClientID = "client"
				if err := st.AuthTransactions().Create(ctx, in.Txn); err != nil {
					t.Fatal(err)
				}
				begun, err := svc.Begin(ctx, in)
				if bad {
					if err == nil || attempts.creates != 0 {
						t.Fatalf("invalid metadata persisted attempt: %+v %v creates=%d", begun, err, attempts.creates)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				u, _ := url.Parse(begun.URL)
				a, err := st.Federation().GetAttempt(ctx, "local", StateHash(u.Query().Get("state")))
				if err != nil || a.Issuer != issuer || a.Endpoints.TokenURL == "" {
					t.Fatalf("snapshot %+v %v", a, err)
				}
				persisted, _ := st.Connections().Get(ctx, "local", "ms")
				wantRev := int64(1)
				wantPinned := ""
				if mode == testMicrosoftTenant {
					wantRev = 2
					wantPinned = issuer
				}
				if persisted.FederationRevision != wantRev || a.Revision != wantRev || connrules.FromConnection(persisted).FederationIssuer != wantPinned || c.FederationRevision != 1 {
					t.Fatal("revision/policy mutation")
				}
			})
		}
	}
}

func TestMicrosoftFlowCapability(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	svc := FlowService{Store: predecessorStore{st}}
	c := &store.Connection{Strategy: StrategyWindowsLive, ID: "ms", TenantID: "local", EnabledClients: []string{"client"}, FederationSecretsSealed: []byte("sealed"), Extra: map[string]any{"client_id": testMicrosoftTenant}}
	if _, err := svc.Begin(ctx, BeginInput{Connection: c, Client: &store.Client{ClientID: "client", IsFirstParty: true}}); !errors.Is(err, store.ErrFederationUnavailable) {
		t.Fatalf("unsupported begin: %v", err)
	}
}
func TestMicrosoftFlowDispatch(t *testing.T) {
	for _, strategy := range []string{StrategyWindowsLive, StrategyWAAD, StrategyGoogle, StrategyOIDC, StrategyOAuth2} {
		if !IsFederated(strategy) {
			t.Fatalf("omitted %s", strategy)
		}
	}
	ps := NewProviders(NetworkPolicy{}, nil)
	if _, err := ps.For(Config{Strategy: "unknown"}).AuthorizationURL(StartInput{Config: Config{ClientID: "client"}, Endpoints: Endpoints{AuthorizationURL: "https://example.com/authorize"}}); err == nil {
		t.Fatal("unknown strategy used generic OIDC")
	}
	for strategy, label := range map[string]string{StrategyWindowsLive: "Microsoft personal account", StrategyWAAD: "Microsoft work or school account", StrategyGoogle: "Google"} {
		c := &store.Connection{Name: "configured-name", Strategy: strategy}
		if ButtonLabel(c) != label {
			t.Fatalf("label %s", ButtonLabel(c))
		}
		spec := connrules.FromConnection(c)
		spec.DisplayName = "Display"
		connrules.Apply(spec, c)
		if ButtonLabel(c) != "Display" {
			t.Fatalf("display override %s", ButtonLabel(c))
		}
	}
}

func TestMicrosoftFlowIssuerCAS(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	spec := connrules.Spec{Name: "directory", Strategy: StrategyWAAD, Options: connrules.Options{Extra: map[string]any{"client_id": testMicrosoftTenant, "tenant_domain": testMicrosoftTenant}}}
	c := &store.Connection{TenantID: "local", ID: "ms", FederationRevision: 1}
	connrules.Apply(&spec, c)
	c.FederationSecretsSealed = []byte("sealed")
	if err := st.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	issuer := testMicrosoftBase + "/" + testMicrosoftTenant + "/v2.0"
	var wg sync.WaitGroup
	var successes atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rev, err := PinIssuer(ctx, st, "local", "ms", 1, issuer)
			if err == nil {
				if rev != 2 {
					t.Errorf("pinned revision %d", rev)
				}
				successes.Add(1)
			} else if !errors.Is(err, store.ErrConflict) {
				t.Errorf("CAS: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("%d CAS winners", successes.Load())
	}
	if _, err := PinIssuer(ctx, st, "local", "ms", 2, testMicrosoftBase+"/"+testMicrosoftOtherTenant+"/v2.0"); !errors.Is(err, ErrImmutable) {
		t.Fatalf("issuer rebound: %v", err)
	}
}
