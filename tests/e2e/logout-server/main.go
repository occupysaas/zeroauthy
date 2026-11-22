// Plan 41a acceptance server: the production app, configuration and SQLite
// storage (including the events decorator every production store is wrapped
// in), with only the federation transport pointed at the local upstream
// fixture. Production does not import this harness. JWT and HTTPS validation
// are real.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/app"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

const upstreamListen = "127.0.0.1:9743"

// network is the production federation policy with only DNS and the final
// dial injected: example.com resolves to a public address, and that address
// is dialled at the local upstream fixture.
func network(roots *x509.CertPool) *federation.Providers {
	return federation.NewProviders(federation.NetworkPolicy{RootCAs: roots, Resolver: resolver{}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "8.8.8.8:443" {
			return nil, fmt.Errorf("unexpected fixture address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstreamListen)
	}}, nil)
}

type resolver struct{}

func (resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host != "example.com" {
		return nil, fmt.Errorf("fixture host refused")
	}
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

// prepare applies the seed and links the upstream identity before the app
// starts: seed files cannot express a linked federated identity.
func prepare(ctx context.Context, dsn, work string) error {
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("ZEROAUTHY_SECURITY__MASTER_KEY"))
	if err != nil {
		return err
	}
	wrapper, err := keys.NewLocalWrapper(raw)
	clear(raw)
	if err != nil {
		return err
	}
	st, err := sqlstore.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	f, err := seed.Load(work + "/seed.yaml")
	if err != nil {
		return err
	}
	if err := f.CheckManagementAPI(""); err != nil {
		return err
	}
	if err := seed.Apply(ctx, st, f, time.Now, wrapper); err != nil {
		return err
	}
	tn, err := st.Tenants().GetByName(ctx, "logout")
	if err != nil {
		return err
	}
	user, err := st.Users().FindByLogin(ctx, tn.ID, "DB", "alice@example.test")
	if err != nil {
		return err
	}
	user.Identities = append(user.Identities, store.Identity{Connection: "Enterprise", Provider: "oidc", UserID: "Enterprise|upstream-user", ProfileData: map[string]any{"email": "linked@example.test"}})
	return st.Users().Update(ctx, user)
}

// upstream is the enterprise IdP: its JWKS and a global token revocation
// JWT minter for the browser test.
func upstream() (*http.Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Use: "sig", Algorithm: "RS256"}}})
	})
	mux.HandleFunc("POST /global-jwt", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("global-token-revocation+jwt").WithHeader("kid", "fixture"))
		if e != nil {
			w.WriteHeader(500)
			return
		}
		payload, _ := json.Marshal(map[string]any{"iss": "https://example.com", "sub": "integration", "aud": "https://localhost:9543/oauth/global-token-revocation/connection/Enterprise", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": secrets.RandomString(32)})
		obj, _ := signer.Sign(payload)
		token, _ := obj.CompactSerialize()
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	})
	return &http.Server{Addr: upstreamListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}, nil
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	work := os.Getenv("E2E_M41A_WORK")
	if work == "" {
		return errors.New("E2E_M41A_WORK is required")
	}
	cfg, err := config.Load("tests/e2e/config.yaml", os.Environ())
	if err != nil {
		return err
	}
	if err := prepare(ctx, cfg.Storage.DSN, work); err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	cfg.Seed = "" // applied by prepare
	pem, err := os.ReadFile(cfg.Server.TLSCertFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid fixture root")
	}
	up, err := upstream()
	if err != nil {
		return err
	}
	go func() {
		if err := up.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("upstream fixture", "err", err)
			stop()
		}
	}()
	defer up.Close()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	a, err := app.New(ctx, cfg, log, app.WithFederationProviders(func() *federation.Providers { return network(roots) }))
	if err != nil {
		return err
	}
	defer a.Close()
	return a.Serve(ctx)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Plan 41a fixture server failed", err)
		os.Exit(1)
	}
}
