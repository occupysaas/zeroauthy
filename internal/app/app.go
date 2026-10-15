// Package app wires configuration, storage, keys and the HTTP server.
package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type App struct {
	cfg     *config.Config
	log     *slog.Logger
	store   store.Store
	handler http.Handler
}

func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*App, error) {
	st, err := storage.Open(ctx, cfg.Storage.DSN)
	if err != nil {
		return nil, err
	}
	a, err := build(ctx, cfg, log, st)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	return a, nil
}

func build(ctx context.Context, cfg *config.Config, log *slog.Logger, st store.Store) (*App, error) {
	masterKey, err := cfg.Security.MasterKeyBytes()
	if err != nil {
		return nil, err
	}
	if masterKey == nil {
		if !strings.HasPrefix(cfg.Storage.DSN, "memory:") {
			return nil, errors.New("app: security.master_key or security.master_key_file is required with persistent storage")
		}
		log.Warn("no master key configured; using an ephemeral key (acceptable only with memory storage)")
		masterKey = make([]byte, 32)
		if _, err := rand.Read(masterKey); err != nil {
			return nil, err
		}
	}
	wrapper, err := keys.NewLocalWrapper(masterKey)
	if err != nil {
		return nil, err
	}
	km := keys.NewManager(st.SigningKeys(), wrapper)

	if cfg.Seed != "" {
		f, err := seed.Load(cfg.Seed)
		if err != nil {
			return nil, err
		}
		if err := seed.Apply(ctx, st, f, time.Now); err != nil {
			return nil, err
		}
		log.Info("applied seed", "file", cfg.Seed, "tenants", len(f.Tenants))
	}

	tenants, err := st.Tenants().List(ctx)
	if err != nil {
		return nil, err
	}
	for _, tn := range tenants {
		if err := km.Ensure(ctx, tn.ID); err != nil {
			return nil, fmt.Errorf("app: signing keys for tenant %q: %w", tn.Name, err)
		}
	}

	mailer, err := email.New(cfg.Email, log)
	if err != nil {
		return nil, err
	}

	lockout := time.Duration(cfg.Security.LoginLockoutSeconds) * time.Second
	return &App{
		cfg:   cfg,
		log:   log,
		store: st,
		handler: server.New(server.Deps{
			Store:    st,
			Keys:     km,
			Resolver: tenant.NewResolver(st.Tenants(), cfg.Server.BaseDomain, cfg.Server.TrustProxyHeaders),
			Sessions: &session.Manager{Store: st},
			Log:      log,
			Mailer:   mailer,

			UserThrottle:      identity.NewThrottle(cfg.Security.LoginMaxAttempts, lockout, lockout),
			IPThrottle:        identity.NewThrottle(10*cfg.Security.LoginMaxAttempts, lockout, lockout),
			TrustProxyHeaders: cfg.Server.TrustProxyHeaders,
		}),
	}, nil
}

func (a *App) Handler() http.Handler { return a.handler }

// httpServer builds the http.Server with explicit timeouts so slow clients
// cannot hold connections open indefinitely.
func (a *App) httpServer() *http.Server {
	return &http.Server{
		Addr:              a.cfg.Server.Listen,
		Handler:           a.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// Serve listens until ctx is cancelled, then shuts down gracefully.
func (a *App) Serve(ctx context.Context) error {
	srv := a.httpServer()
	tls := a.cfg.Server.TLSCertFile != ""
	errc := make(chan error, 1)
	go func() {
		if tls {
			errc <- srv.ListenAndServeTLS(a.cfg.Server.TLSCertFile, a.cfg.Server.TLSKeyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	a.log.Info("listening", "addr", a.cfg.Server.Listen, "tls", tls)
	go a.sweepLoop(ctx, sweepInterval)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		a.log.Info("shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}

func (a *App) Close() error { return a.store.Close() }
