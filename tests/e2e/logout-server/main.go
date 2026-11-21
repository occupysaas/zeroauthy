// Isolated Plan 41a acceptance server. Production does not import this harness.
// Only upstream DNS/final dialing is injected; JWT and HTTPS validation are real.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"
)

type resolver struct{}

func (resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host != "example.com" {
		return nil, fmt.Errorf("fixture host refused")
	}
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}
func run() error {
	ctx := context.Background()
	work := os.Getenv("E2E_M41A_WORK")
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("ZEROAUTHY_SECURITY__MASTER_KEY"))
	if err != nil {
		return err
	}
	wrapper, err := keys.NewLocalWrapper(raw)
	clear(raw)
	if err != nil {
		return err
	}
	st, err := sqlstore.Open(ctx, "sqlite://"+work+"/logout.db")
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
	if err := st.Users().Update(ctx, user); err != nil {
		return err
	}
	manager := keys.NewManager(st.SigningKeys(), wrapper)
	if err := manager.Ensure(ctx, tn.ID); err != nil {
		return err
	}
	pem, err := os.ReadFile(work + "/cert.pem")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid fixture CA")
	}
	upstreamKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	upstream := http.NewServeMux()
	upstream.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &upstreamKey.PublicKey, KeyID: "fixture", Use: "sig", Algorithm: "RS256"}}})
	})
	upstream.HandleFunc("POST /global-jwt", func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: upstreamKey}, (&jose.SignerOptions{}).WithType("global-token-revocation+jwt").WithHeader("kid", "fixture"))
		if e != nil {
			w.WriteHeader(500)
			return
		}
		payload, _ := json.Marshal(map[string]any{"iss": "https://example.com", "sub": "integration", "aud": "https://localhost:9543/oauth/global-token-revocation/connection/Enterprise", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": secrets.RandomString(32)})
		obj, _ := signer.Sign(payload)
		token, _ := obj.CompactSerialize()
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	})
	go func() {
		if err := http.ListenAndServeTLS("127.0.0.1:9743", work+"/cert.pem", work+"/key.pem", upstream); err != nil {
			panic(err)
		}
	}()
	policy := federation.NetworkPolicy{RootCAs: roots, Resolver: resolver{}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, "127.0.0.1:9743")
	}}
	flows := &federation.FlowService{Service: federation.Service{Wrapper: wrapper}, Store: st, Providers: federation.NewProviders(policy, time.Now)}
	notifications := &logout.Service{Store: st, Wrapper: wrapper, Keys: manager, AllowPrivateNetworks: true}
	engine := &actions.Engine{Store: st, Secrets: wrapper, BackchannelLogout: notifications}
	worker := &actions.Worker{Store: st, Engine: engine, Workers: 1, Poll: 20 * time.Millisecond}
	go worker.Run(ctx)
	mfaService := mfa.NewService(st, wrapper, nil, nil, slog.Default(), time.Now)
	handler := server.New(server.Deps{Store: st, Keys: manager, Wrapper: wrapper, Sessions: &session.Manager{Store: st}, Resolver: tenant.NewResolver(st.Tenants(), "", false), Federation: flows, Logout: notifications, Actions: engine, MFA: mfaService, Log: slog.Default(), SystemHost: "system.e2e.test"})
	return http.ListenAndServeTLS("127.0.0.1:9543", work+"/cert.pem", work+"/key.pem", handler)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Plan 41a fixture server failed", err)
		os.Exit(1)
	}
}
