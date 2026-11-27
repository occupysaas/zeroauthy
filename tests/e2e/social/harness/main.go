// The isolated Plan 24 fixture: two zeroauthy nodes over independently
// opened SQLite handles, and the mock upstream providers on idp.e2e.test,
// behind one TLS listener per node. Federation uses the production network
// policy; only the resolver answer and the final dial of that validated
// public answer are mapped to the local listener (constructor injection).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	pemencoding "encoding/pem"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	dnsfixture "github.com/zeroauthy/zeroauthy/tests/e2e/domains/dns"
	"github.com/zeroauthy/zeroauthy/tests/e2e/social/fixture"
	"github.com/zeroauthy/zeroauthy/tests/e2e/social/provider"
)

const idpHost = "idp.e2e.test"

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
	var apple *provider.Provider
	if os.Getenv("E2E_M39A") == "1" {
		apple, err = provider.New("https://apple.idp.test")
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(os.Getenv("E2E_APPLE_KEY"))
		if err != nil {
			return err
		}
		block, _ := pemencoding.Decode(raw)
		if block == nil {
			return fmt.Errorf("invalid Apple fixture key")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("invalid Apple fixture key type")
		}
		if err := apple.RegisterApple(provider.AppleRegistration{ServicesID: "test.apple.web", BundleID: "test.apple.native", TeamID: "ABCDE12345", KeyID: "ABCDE67890", PublicKey: &ec.PublicKey}); err != nil {
			return err
		}
		apple.EnableAppleAudit()
	}
	// GitHub (Plan 39c): the fixture lives under E2E_GITHUB_BASE on the idp
	// host; adapter endpoints are pointed at it by constructor injection.
	github := ""
	if os.Getenv("E2E_M39C") == "1" {
		github = os.Getenv("E2E_GITHUB_BASE")
		if u, err := url.Parse(github); err != nil || u.Scheme != "https" || u.Host != idpHost || u.Path != "/github" {
			return fmt.Errorf("E2E_GITHUB_BASE must be https://%s/github", idpHost)
		}
	}
	// Plan 39b: every descriptor strategy's stand-in lives under
	// E2E_SOCIAL_BASE on the idp host (provider /social routes).
	social := ""
	if os.Getenv("E2E_M39B") == "1" {
		social = os.Getenv("E2E_SOCIAL_BASE")
		if u, err := url.Parse(social); err != nil || u.Scheme != "https" || u.Host != idpHost || u.Path != "/social" {
			return fmt.Errorf("E2E_SOCIAL_BASE must be https://%s/social", idpHost)
		}
	}
	var dnsMu sync.RWMutex
	records := map[string][]string{}
	dns := &dnsfixture.Server{A: [4]byte{8, 8, 8, 8}, TXT: func(name string) []string {
		dnsMu.RLock()
		defer dnsMu.RUnlock()
		return append([]string(nil), records[name]...)
	}}
	if err := dns.Listen("127.0.0.1:8073"); err != nil {
		return err
	}
	defer dns.Close()
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
			if os.Getenv("E2E_M28") == "1" {
				// A verified fixture operator is required by the real email-test
				// endpoint. Authentication still uses the hosted bootstrap/login.
				sys, err := st.Tenants().GetByName(ctx, tenant.SystemName)
				if err != nil {
					return err
				}
				login, err := st.Users().FindByLogin(ctx, sys.ID, system.OperatorsConnection, "operator@e2e.local")
				if err != nil {
					return err
				}
				operator, err := st.Users().Get(ctx, sys.ID, login.UserID)
				if err != nil {
					return err
				}
				operator.EmailVerified = true
				if err := st.Users().Update(ctx, operator); err != nil {
					return err
				}
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
		ps, runner, err := fixture.Providers(roots, "127.0.0.1:9543")
		if err != nil {
			return err
		}
		defer runner.Close()
		if apple != nil {
			base := "https://apple.idp.test/apple"
			ps.WithAppleFixture(federation.AppleOverride{Issuer: base, DiscoveryURL: base + "/.well-known/openid-configuration", Endpoints: federation.Endpoints{AuthorizationURL: base + "/authorize", TokenURL: base + "/token", JWKSURL: base + "/jwks", TokenAuthMethod: "client_secret_post"}})
		}
		if social != "" {
			ps.WithSocialFixture(social)
		}
		if github != "" {
			ps.WithGitHubFixture(federation.GitHubOverride{Endpoints: federation.Endpoints{AuthorizationURL: github + "/login/oauth/authorize", TokenURL: github + "/login/oauth/access_token"}, APIBase: github + "/api"})
		}
		flows := &federation.FlowService{Service: federation.Service{Wrapper: wrapper}, Store: st, Providers: ps, Log: slog.Default()}
		domains := customdomain.NewService(st, &customdomain.BoundedResolver{Server: "127.0.0.1:8073"}, customdomain.ServiceConfig{SystemHost: "system.e2e.test", OriginDomain: "origin.e2e.test", OriginTLSReady: true, Proxy: customdomain.ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}}, time.Now, rand.Reader)
		var engine *actions.Engine
		if os.Getenv("E2E_M27") == "1" {
			cfg := config.Actions{CacheDir: filepath.Join(os.Getenv("E2E_ACTIONS_CACHE"), port), Registry: os.Getenv("E2E_NPM_REGISTRY")}
			builds, err := build.New(cfg, st, slog.Default())
			if err != nil {
				return err
			}
			defer builds.Close()
			pool, err := actions.NewRunner(cfg, builds, slog.Default())
			if err != nil {
				return err
			}
			defer pool.Close()
			engine = &actions.Engine{Store: st, Builds: builds, Runner: pool, Secrets: wrapper, Log: slog.Default()}
		}
		var emailService *email.Service
		if os.Getenv("E2E_M28") == "1" {
			renderer, err := email.NewRenderer()
			if err != nil {
				return err
			}
			emailService = &email.Service{Store: st, Wrapper: wrapper, Renderer: renderer, Providers: &providers.Factory{}, DefaultFrom: "fixture@example.test", Actions: engine}
			worker := &actions.Worker{Engine: engine, Store: st, Workers: 1, Poll: 20 * time.Millisecond}
			go worker.Run(ctx)
		}
		// Users import jobs (the GitHub lane imports github identities) run
		// on node one only.
		var jobNotify func()
		if github != "" && i == 0 {
			runner := &jobs.Runner{Store: st, Workers: 1, Poll: 50 * time.Millisecond, Log: slog.Default(),
				Processors: map[store.JobType]jobs.Processor{store.JobUsersImport: jobs.Importer{Wrapper: wrapper, Log: slog.Default()}}}
			go runner.Run(ctx)
			jobNotify = runner.Notify
		}
		za := server.New(server.Deps{JobNotify: jobNotify, EmailService: emailService, Domains: domains, Store: st, Keys: km, Wrapper: wrapper, Resolver: tenant.NewResolver(st.Tenants(), "", false),
			Sessions: &session.Manager{Store: st}, Log: slog.Default(), SystemHost: "system.e2e.test", Federation: flows, Actions: engine})
		mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if (os.Getenv("E2E_M27") == "1" || os.Getenv("E2E_M29") == "1") && strings.EqualFold(strings.Split(r.Host, ":")[0], "callback.e2e.test") {
				switch r.URL.Path {
				case "/reset-redirect":
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte(`<form method="post" action="https://sdk.e2e.test/continue?ok=1"><input name="state" type="hidden"><button>Continue reset</button></form><script>document.querySelector("input").value=new URLSearchParams(location.search).get("state")</script>`))
				case "/invitation-login":
					if os.Getenv("E2E_M30") != "1" {
						http.NotFound(w, r)
						return
					}
					// Application-owned route forwards the two email bindings into
					// its normal authorization request, including PKCE and state.
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte(`<script>
(async()=>{
const incoming=new URLSearchParams(location.search);
const bytes=n=>crypto.getRandomValues(new Uint8Array(n));
const b64=b=>btoa(String.fromCharCode(...b)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
const verifier=b64(bytes(32)),state=b64(bytes(16)),nonce=b64(bytes(16));
const challenge=b64(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))));
const flow={domain:'sdk.e2e.test',client:'m24-spa',redirect:'https://callback.e2e.test/',verifier,state,nonce};
sessionStorage.setItem('m30-flow',JSON.stringify(flow));
const p=new URLSearchParams({client_id:flow.client,redirect_uri:flow.redirect,response_type:'code',scope:'openid profile email offline_access',state,nonce,code_challenge:challenge,code_challenge_method:'S256',invitation:incoming.get('invitation'),organization:incoming.get('organization')});
location.replace('https://sdk.e2e.test/authorize?'+p);
})();</script>`))
				case "/org-spa":
					http.ServeFile(w, r, "tests/e2e/organizations-spa.html")
				case "/spa":
					http.ServeFile(w, r, "tests/e2e/actions-spa.html")
				case "/redirect":
					http.ServeFile(w, r, "tests/e2e/actions-redirect.html")
				case "/auth0-spa-js.js":
					http.ServeFile(w, r, "tests/e2e/node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js")
				default:
					_, _ = w.Write([]byte("Application callback"))
				}
				return
			}
			if apple != nil && strings.EqualFold(strings.Split(r.Host, ":")[0], "apple.idp.test") {
				apple.ServeHTTP(w, r)
				return
			}
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
	if os.Getenv("E2E_M36") == "1" {
		control.HandleFunc("POST /enterprise/register", func(w http.ResponseWriter, r *http.Request) {
			var registration provider.EnterpriseRegistration
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 32768)).Decode(&registration) != nil || idp.RegisterEnterprise(registration) != nil {
				http.Error(w, "invalid registration", 400)
				return
			}
			w.WriteHeader(204)
		})
		control.HandleFunc("GET /enterprise/audit", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(idp.EnterpriseAudit())
		})
	}
	if apple != nil {
		control.HandleFunc("POST /apple/code", func(w http.ResponseWriter, r *http.Request) {
			var v struct{ Client, Subject string }
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&v) != nil {
				http.Error(w, "bad request", 400)
				return
			}
			code, err := apple.AppleCode(v.Client, v.Subject)
			if err != nil {
				http.Error(w, "invalid client", 400)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
		})
		control.HandleFunc("GET /apple/audit", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(apple.AppleAuditSecrets())
		})
	}
	if github != "" {
		control.HandleFunc("POST /github/account", func(w http.ResponseWriter, r *http.Request) {
			var a provider.GitHubAccount
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&a) != nil || idp.RegisterGitHub(a) != nil {
				http.Error(w, "invalid GitHub account", 400)
				return
			}
			w.WriteHeader(204)
		})
	}
	if os.Getenv("E2E_M28") == "1" {
		var mu sync.Mutex
		rows := []json.RawMessage{}
		control.HandleFunc("/m28/sink", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if r.Method == "POST" {
				var row json.RawMessage
				if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&row) != nil {
					http.Error(w, "bad JSON", 400)
					return
				}
				rows = append(rows, row)
			}
			_ = json.NewEncoder(w).Encode(rows)
		})
	}
	if os.Getenv("E2E_M27") == "1" {
		target, _ := url.Parse("https://sdk.e2e.test:9543")
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:9543")
		}}
		original := proxy.Director
		proxy.Director = func(r *http.Request) {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/action-sdk")
			original(r)
			r.Host = "sdk.e2e.test"
		}
		control.Handle("/action-sdk/", proxy)
	}
	control.HandleFunc("POST /dns", func(w http.ResponseWriter, r *http.Request) {
		var row struct {
			Name  string
			Value string
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&row) != nil || row.Name == "" {
			http.Error(w, "bad DNS fixture", 400)
			return
		}
		dnsMu.Lock()
		records[row.Name] = []string{row.Value}
		dnsMu.Unlock()
		w.WriteHeader(204)
	})
	control.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("two nodes and providers listening"))
	})
	// Exchange counts only: never codes, tokens or keys.
	control.HandleFunc("GET /exchanges", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(idp.ExchangeCounts())
	})
	return http.ListenAndServe("127.0.0.1:9173", control)
}
