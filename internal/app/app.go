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

	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
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
	runner  *customdb.NodeRunner
	handler http.Handler
}

func New(ctx context.Context, cfg *config.Config, log *slog.Logger) (*App, error) {
	// The master key is checked before the store is opened, so a missing key
	// never leaves a created or migrated database behind.
	masterKey, err := MasterKey(cfg, log)
	if err != nil {
		return nil, err
	}
	st, err := storage.Open(ctx, cfg.Storage.DSN)
	if err != nil {
		return nil, err
	}
	if err := prepareSchema(ctx, cfg, log, st); err != nil {
		_ = st.Close()
		return nil, err
	}
	a, err := build(ctx, cfg, log, st, masterKey)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	return a, nil
}

// prepareSchema migrates (storage.auto_migrate) or verifies the schema of
// drivers that have one. serve never runs against a schema that is behind or
// ahead of this binary.
func prepareSchema(ctx context.Context, cfg *config.Config, log *slog.Logger, st store.Store) error {
	m, ok := st.(storage.Migrator)
	if !ok {
		return nil
	}
	if cfg.Storage.AutoMigrate {
		if err := m.Migrate(ctx); err != nil {
			return err
		}
	} else if err := m.CheckSchema(ctx); err != nil {
		return err
	}
	if v, ok := st.(interface {
		SchemaVersion(context.Context) (int64, error)
	}); ok {
		version, err := v.SchemaVersion(ctx)
		if err != nil {
			return err
		}
		log.Info("storage schema ready", "schema_version", version, "auto_migrate", cfg.Storage.AutoMigrate)
	}
	return nil
}

// MasterKey returns the configured master key. Persistent storage
// requires one; memory storage gets an ephemeral key.
func MasterKey(cfg *config.Config, log *slog.Logger) ([]byte, error) {
	masterKey, err := cfg.Security.MasterKeyBytes()
	if err != nil || masterKey != nil {
		return masterKey, err
	}
	if !strings.HasPrefix(cfg.Storage.DSN, "memory:") {
		return nil, errors.New("app: security.master_key or security.master_key_file is required with persistent storage")
	}
	log.Warn("no master key configured; using an ephemeral key (acceptable only with memory storage)")
	masterKey = make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, err
	}
	return masterKey, nil
}

func build(ctx context.Context, cfg *config.Config, log *slog.Logger, st store.Store, masterKey []byte) (*App, error) {
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
		if err := seed.Apply(ctx, st, f, time.Now, wrapper); err != nil {
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
	if cfg.Email.Driver == "" || cfg.Email.Driver == "log" {
		log.Warn("email.driver is log: emails are written to the server log and not delivered; reset links are redacted unless email.log_links is true")
	}

	// The runner starts no Node process until a script runs.
	runner, err := customdb.NewNodeRunner(cfg.CustomDB, log)
	if err != nil {
		return nil, err
	}
	if err := checkCustomDB(ctx, st, tenants, runner, log); err != nil {
		_ = runner.Close()
		return nil, err
	}

	lockout := time.Duration(cfg.Security.LoginLockoutSeconds) * time.Second
	sec := cfg.Security
	return &App{
		cfg:    cfg,
		log:    log,
		store:  st,
		runner: runner,
		handler: server.New(server.Deps{
			Store:    st,
			Keys:     km,
			Resolver: tenant.NewResolver(st.Tenants(), cfg.Server.BaseDomain, cfg.Server.TrustProxyHeaders),
			Sessions: &session.Manager{Store: st},
			Log:      log,
			Mailer:   mailer,
			Scripts:  &customdb.Client{Exec: runner, Wrapper: wrapper},

			UserThrottle:      identity.NewThrottle(cfg.Security.LoginMaxAttempts, lockout, lockout),
			IPThrottle:        identity.NewThrottle(10*cfg.Security.LoginMaxAttempts, lockout, lockout),
			TrustProxyHeaders: cfg.Server.TrustProxyHeaders,

			DeviceTxnThrottle: identity.NewThrottle(sec.DeviceActivationTxnMaxMisses, authz.TxnLifetime, authz.TxnLifetime),
			DeviceIPThrottle: identity.NewThrottleOrOff(sec.DeviceActivationIPMaxMisses,
				seconds(sec.DeviceActivationIPLockoutSeconds), seconds(sec.DeviceActivationIPLockoutSeconds)),
			DeviceTenantThrottle: identity.NewThrottleOrOff(sec.DeviceActivationTenantMaxMisses,
				seconds(sec.DeviceActivationTenantWindowSeconds), seconds(sec.DeviceActivationTenantLockoutSeconds)),
		}),
	}, nil
}

// checkCustomDB warns once when a tenant has a customized connection and
// Node.js cannot run scripts. The server still starts: other tenants and
// connections keep working, and those connections fail per request.
func checkCustomDB(ctx context.Context, st store.Store, tenants []*store.Tenant, runner *customdb.NodeRunner, log *slog.Logger) error {
	for _, tn := range tenants {
		conns, err := st.Connections().List(ctx, tn.ID)
		if err != nil {
			return err
		}
		for _, c := range conns {
			if !identity.IsCustom(c) {
				continue
			}
			if err := runner.Probe(); err != nil {
				log.Warn("custom database connections cannot run their scripts until Node.js is available (the check is cached: restart zeroauthy after installing or upgrading Node.js)",
					"tenant", tn.Name, "connection", c.Name, "err", err)
			}
			return nil
		}
	}
	return nil
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
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		a.log.Info("shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}

// Close stops the custom database runner and closes the store.
func (a *App) Close() error {
	var errRunner error
	if a.runner != nil {
		errRunner = a.runner.Close()
	}
	return errors.Join(errRunner, a.store.Close())
}

func seconds(n int) time.Duration { return time.Duration(n) * time.Second }
