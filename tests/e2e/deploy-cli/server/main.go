// Migration fixture server: the production app, configuration and storage,
// with only the federation transport pointed at a local mock provider. The
// provider listens on E2E_IDP_LISTEN with the server certificate.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/app"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/tests/e2e/social/fixture"
	"github.com/zeroauthy/zeroauthy/tests/e2e/social/provider"
)

func main() {
	if err := run(); err != nil {
		slog.Error("deploy fixture server", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := config.Load("tests/e2e/config.yaml", os.Environ())
	if err != nil {
		return err
	}
	idpListen := os.Getenv("E2E_IDP_LISTEN")
	if idpListen == "" {
		return errors.New("E2E_IDP_LISTEN is required")
	}
	pem, err := os.ReadFile(cfg.Server.TLSCertFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid fixture root")
	}
	idp, err := provider.New("https://idp.e2e.test")
	if err != nil {
		return err
	}
	idpServer := &http.Server{Addr: idpListen, Handler: idp, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := idpServer.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("mock provider", "err", err)
			stop()
		}
	}()
	defer idpServer.Close()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	a, err := app.New(ctx, cfg, log, app.WithFederationProviders(func() *federation.Providers { return fixture.Network(roots, idpListen) }))
	if err != nil {
		return err
	}
	defer a.Close()
	return a.Serve(ctx)
}
