// The isolated Plan 24 fixture: two zeroauthy nodes over independently
// opened SQLite handles, and the mock upstream providers on idp.e2e.test,
// behind one TLS listener per node. Federation uses the production network
// policy; only the resolver answer and the final dial of that validated
// public answer are mapped to the local listener (constructor injection).
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/script"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/tests/e2e/social/provider"
)

const idpHost = "idp.e2e.test"

// publicAnswer resolves every *.e2e.test name to one public address, which
// the production address check accepts.
type publicAnswer struct{}

func (publicAnswer) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if !strings.HasSuffix(host, ".e2e.test") {
		return nil, fmt.Errorf("unexpected lookup")
	}
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	ctx := context.Background()
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(os.Getenv("E2E_CERT"))
	if err != nil {
		return err
	}
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid fixture root")
	}
	wrapper, err := keys.NewLocalWrapper([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		return err
	}
	idp, err := provider.New("https://" + idpHost)
	if err != nil {
		return err
	}
	policy := federation.NetworkPolicy{Resolver: publicAnswer{}, RootCAs: roots,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != "8.8.8.8:443" {
				return nil, fmt.Errorf("unexpected provider address")
			}
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:9543")
		}}
	base := "https://" + idpHost
	newProviders := func() (*federation.Providers, *script.Runner, error) {
		ps := federation.NewProviders(policy, nil).WithGoogleFixture(federation.GoogleOverride{Issuer: base + "/google",
			Endpoints: store.FederationEndpoints{AuthorizationURL: base + "/google/authorize", TokenURL: base + "/google/token", JWKSURL: base + "/google/jwks", TokenAuthMethod: "client_secret_post"}})
		r, err := script.NewRunner(script.Config{}, script.NewBroker(ps.HTTPClient()))
		if err != nil {
			return nil, nil, err
		}
		if err := r.Probe(); err != nil {
			return nil, nil, fmt.Errorf("profile script runtime: %w", err)
		}
		return ps.WithScripts(r), r, nil
	}
	for i, port := range []string{"9543", "9544"} {
		st, err := storage.Open(ctx, "sqlite://"+os.Getenv("E2E_DATABASE"))
		if err != nil {
			return err
		}
		defer st.Close()
		if i == 0 {
			if err := st.(storage.Migrator).Migrate(ctx); err != nil {
				return err
			}
			f, err := seed.Load(os.Getenv("E2E_SEED"))
			if err != nil {
				return err
			}
			if err := f.CheckManagementAPI(""); err != nil {
				return err
			}
			if err := seed.Apply(ctx, st, f, time.Now, wrapper); err != nil {
				return err
			}
			if _, err := system.Ensure(ctx, st, system.Config{Host: "system.e2e.test", Wrapper: wrapper}); err != nil {
				return err
			}
			link, err := system.Bootstrap(ctx, st, "operator@e2e.local")
			if err != nil {
				return err
			}
			if err := os.WriteFile(os.Getenv("E2E_SETUP_FILE"), []byte(link), 0o600); err != nil {
				return err
			}
		}
		km := keys.NewManager(st.SigningKeys(), wrapper)
		tenants, err := st.Tenants().List(ctx)
		if err != nil {
			return err
		}
		for _, tn := range tenants {
			if err := km.Ensure(ctx, tn.ID); err != nil {
				return err
			}
		}
		ps, runner, err := newProviders()
		if err != nil {
			return err
		}
		defer runner.Close()
		flows := &federation.FlowService{Service: federation.Service{Wrapper: wrapper}, Store: st, Providers: ps, Log: slog.Default()}
		za := server.New(server.Deps{Store: st, Keys: km, Wrapper: wrapper, Resolver: tenant.NewResolver(st.Tenants(), "", false),
			Sessions: &session.Manager{Store: st}, Log: slog.Default(), SystemHost: "system.e2e.test", Federation: flows})
		mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(strings.Split(r.Host, ":")[0], idpHost) {
				idp.ServeHTTP(w, r)
				return
			}
			za.ServeHTTP(w, r)
		})
		ln, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			return err
		}
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := srv.ServeTLS(ln, os.Getenv("E2E_CERT"), os.Getenv("E2E_KEY")); err != nil && err != http.ErrServerClosed {
				panic(err)
			}
		}()
	}
	control := http.NewServeMux()
	control.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("two nodes and providers listening")) })
	// Exchange counts only: never codes, tokens or keys.
	control.HandleFunc("GET /exchanges", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(idp.ExchangeCounts())
	})
	return http.ListenAndServe("127.0.0.1:9173", control)
}
