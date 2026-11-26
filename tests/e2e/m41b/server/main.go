// Plan 41b acceptance server: the production app, configuration and SQLite
// storage, with only DNS and the final dial of the outbound policy pointed
// at a local Client ID Metadata Document host: cimd.example.com resolves to
// a public address, which is dialled at the fixture. Production does not
// import this harness; TLS validation is real.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/zeroauthy/zeroauthy/internal/app"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/federation"
)

const (
	docsHost   = "cimd.example.com"
	docsListen = "127.0.0.1:9744"
	publicAddr = "8.8.8.8"
)

type resolver struct{}

func (resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host != docsHost {
		return nil, fmt.Errorf("fixture host refused")
	}
	return []netip.Addr{netip.MustParseAddr(publicAddr)}, nil
}

func network(roots *x509.CertPool) *federation.Providers {
	return federation.NewProviders(federation.NetworkPolicy{RootCAs: roots, Resolver: resolver{}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != publicAddr+":443" {
			return nil, fmt.Errorf("unexpected fixture address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, docsListen)
	}}, nil)
}

// docs serves the metadata documents: client.json (registered by the
// seed), dynamic.json (registered on first use) and mismatch.json (names
// another client_id).
func docs(app string) http.Handler {
	mux := http.NewServeMux()
	doc := func(path string, mutate func(map[string]any)) {
		mux.HandleFunc("/"+path, func(w http.ResponseWriter, r *http.Request) {
			d := map[string]any{"client_id": "https://" + docsHost + "/" + path, "client_name": "Plan41b agent " + path,
				"redirect_uris": []string{app + "/"}, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}}
			if mutate != nil {
				mutate(d)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "max-age=300")
			_ = json.NewEncoder(w).Encode(d)
		})
	}
	doc("client.json", nil)
	doc("dynamic.json", nil)
	doc("mismatch.json", func(d map[string]any) { d["client_id"] = "https://evil.example/client.json" })
	return mux
}

func run() error {
	cfgPath := flag.String("c", "", "configuration file")
	appOrigin := flag.String("app", "", "the browser application's origin")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := config.Load(*cfgPath, os.Environ())
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(cfg.Server.TLSCertFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid fixture root")
	}
	srv := &http.Server{Addr: docsListen, Handler: docs(*appOrigin)}
	go func() {
		if err := srv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("document fixture", "err", err)
			stop()
		}
	}()
	defer srv.Close()
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a, err := app.New(ctx, cfg, log, app.WithFederationProviders(func() *federation.Providers { return network(roots) }))
	if err != nil {
		return err
	}
	defer a.Close()
	return a.Serve(ctx)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Plan 41b fixture server failed", err)
		os.Exit(1)
	}
}
