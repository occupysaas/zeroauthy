// The isolated Plan 23 fixture serves two independently opened SQLite handles.
// Domain state is changed exclusively by the production Management API. This
// control listener changes authoritative DNS answers only; it cannot ready a row.
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	dnsfixture "github.com/zeroauthy/zeroauthy/tests/e2e/domains/dns"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}
func run() error {
	ctx := context.Background()
	var mu sync.RWMutex
	records := map[string][]string{}
	dns := &dnsfixture.Server{A: [4]byte{8, 8, 8, 8}, TXT: func(name string) []string {
		mu.RLock()
		defer mu.RUnlock()
		return append([]string(nil), records[name]...)
	}}
	if err := dns.Listen("127.0.0.1:8073"); err != nil {
		return err
	}
	defer dns.Close()
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
	var servers []*http.Server
	for i, port := range []string{"9443", "9444"} {
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
			if err := os.WriteFile(os.Getenv("E2E_SETUP_FILE"), []byte(link), 0600); err != nil {
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
		svc := customdomain.NewServiceWithProbe(st, &customdomain.BoundedResolver{Server: "127.0.0.1:8073"}, customdomain.ServiceConfig{SystemHost: "system.e2e.test", OriginDomain: "origin.e2e.test", OriginTLSReady: true, Proxy: customdomain.ProxyPolicy{Trusted: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}}, time.Now, rand.Reader, customdomain.ProbeDeps{RootCAs: roots, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Keep production public-address validation. Only the final connection to
			// its already validated 8.8.8.8 fixture answer is mapped to node two.
			if addr != "8.8.8.8:443" {
				return nil, fmt.Errorf("unexpected diagnostic address")
			}
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:9444")
		}})
		handler := server.New(server.Deps{Store: st, Keys: km, Wrapper: wrapper, Resolver: tenant.NewResolver(st.Tenants(), "", false), Sessions: &session.Manager{Store: st}, Log: slog.Default(), SystemHost: "system.e2e.test", Domains: svc})
		ln, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			return err
		}
		srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		go func() {
			if err := srv.ServeTLS(ln, os.Getenv("E2E_CERT"), os.Getenv("E2E_KEY")); err != nil && err != http.ErrServerClosed {
				panic(err)
			}
		}()
	}
	control := http.NewServeMux()
	control.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("two nodes listening")) })
	control.HandleFunc("POST /dns", func(w http.ResponseWriter, r *http.Request) {
		var row struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&row) != nil || row.Name == "" {
			http.Error(w, "invalid DNS record", 400)
			return
		}
		mu.Lock()
		records[row.Name] = []string{row.Value}
		mu.Unlock()
		w.WriteHeader(204)
	})
	// No fixture control endpoint returns keys, claims, defaults or certificates.
	return http.ListenAndServe("127.0.0.1:9073", control)
}
