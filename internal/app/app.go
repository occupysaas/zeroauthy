// Package app wires configuration, storage, keys and the HTTP server.
package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/certificates"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	actionsbuild "github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/email/providers"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/script"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/login"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

type App struct {
	cfg        *config.Config
	log        *slog.Logger
	store      store.Store
	runner     *customdb.NodeRunner
	builds     *actionsbuild.Manager // Actions dependency builds
	actions    *noderunner.Pool      // Actions flow processes
	profiles   *script.Runner        // nil when profile scripts cannot run
	actionJobs *actions.Worker
	jobs       *jobs.Runner
	handler    http.Handler
	breachFile *protection.FileChecker
	// tls serves certificates when ACME is on; nil keeps static or
	// externally terminated TLS exactly as configured.
	tls *certificates.Manager
	// acme issues and renews managed certificates; domains proves ownership
	// for it. Both are nil when ACME is off.
	acme    *certificates.Worker
	domains *customdomain.Service
}

// Option adjusts construction from Go code only. No option is reachable from
// configuration, the environment, seed files or any API.
type Option func(*options)

type options struct {
	federation func() *federation.Providers
}

// WithFederationProviders replaces the production federation transport. It
// exists for local fixture harnesses that pin provider endpoints and trust
// roots; profile scripts are still attached by the app.
func WithFederationProviders(f func() *federation.Providers) Option {
	return func(o *options) { o.federation = f }
}

func New(ctx context.Context, cfg *config.Config, log *slog.Logger, opts ...Option) (*App, error) {
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
	a, err := build(ctx, cfg, log, st, masterKey, opts...)
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

func build(ctx context.Context, cfg *config.Config, log *slog.Logger, st store.Store, masterKey []byte, opts ...Option) (*App, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if capable, ok := st.(store.RBACSupporter); ok {
		if err := capable.CheckRBACSupport(ctx); err != nil {
			return nil, fmt.Errorf("app: RBAC storage capability required: %w", err)
		}
	}
	if capable, ok := st.(store.ActionsSupporter); ok {
		if err := capable.CheckActionsSupport(ctx); err != nil {
			return nil, fmt.Errorf("app: Actions storage capability required: %w", err)
		}
	}
	if err := federation.PreflightMicrosoftIdentities(ctx, st); err != nil {
		return nil, err
	}
	wrapper, err := keys.NewLocalWrapper(masterKey)
	if err != nil {
		return nil, err
	}
	km := keys.NewManager(st.SigningKeys(), wrapper)

	systemHost := tenant.SystemHost(cfg.Server.BaseDomain, cfg.Server.SystemHost)
	if cfg.Server.TrustProxyHeaders && len(cfg.Server.TrustedProxyCIDRs) == 0 {
		log.Warn("server.trust_proxy_headers without server.trusted_proxy_cidrs is deprecated: forwarded headers are trusted from every peer")
	}
	if err := tenantsetup.ReconcileDomains(ctx, st, cfg.Server.BaseDomain, systemHost, cfg.Server.OriginDomain()); err != nil {
		return nil, fmt.Errorf("app: domain reconciliation: %w", err)
	}
	// Seed Actions build outside the ordinary seed transaction. Keep this
	// manager for the runtime so configuration and artifacts are identical.
	builds, err := actionsbuild.New(cfg.Actions, st, log)
	if err != nil {
		return nil, err
	}
	buildsOwned := false
	defer func() {
		if !buildsOwned {
			builds.Close()
		}
	}()
	if cfg.Seed != "" {
		f, err := seed.Load(cfg.Seed)
		if err != nil {
			return nil, err
		}
		f.Mode = seed.Mode(cfg.SeedMode)
		if err := f.CheckSystemHost(systemHost); err != nil {
			return nil, err
		}
		if err := f.CheckManagementAPI(cfg.Server.BaseDomain); err != nil {
			return nil, err
		}
		if err := seed.ApplyWithActions(ctx, st, f, time.Now, wrapper, &actions.Engine{Store: st, Builds: builds, Secrets: wrapper, Log: log}); err != nil {
			return nil, err
		}
		log.Info("applied seed", "file", cfg.Seed, "mode", cfg.SeedMode, "tenants", len(f.Tenants))
	}
	if _, err := system.Ensure(ctx, st, system.Config{Host: systemHost, Wrapper: wrapper}); err != nil {
		return nil, err
	}
	tlsManager, err := certificateManager(ctx, cfg, st, wrapper)
	if err != nil {
		return nil, err
	}
	domains, err := domainService(cfg, st, tlsManager, systemHost, log)
	if err != nil {
		return nil, err
	}
	acmeWorker, err := certificateWorker(cfg, tlsManager, domains)
	if err != nil {
		return nil, err
	}
	if err := seed.InitializeProtection(ctx, st, cfg.Security, log); err != nil {
		return nil, err
	}
	if err := bootstrapOperator(ctx, st, cfg.Bootstrap.AdminEmail, log); err != nil {
		return nil, err
	}

	tenants, err := st.Tenants().List(ctx)
	if err != nil {
		return nil, err
	}
	for _, tn := range tenants {
		if err := tenantsetup.UpgradeManagementAPIName(ctx, st, tn, cfg.Server.BaseDomain); err != nil {
			return nil, fmt.Errorf("app: upgrade Management API for tenant %q: %w", tn.Name, err)
		}
		if err := tenantsetup.UpgradeManagementAPIScopes(ctx, st, tn, cfg.Server.BaseDomain); err != nil {
			return nil, fmt.Errorf("app: upgrade Management API scopes for tenant %q: %w", tn.Name, err)
		}
		if err := km.Ensure(ctx, tn.ID); err != nil {
			return nil, fmt.Errorf("app: signing keys for tenant %q: %w", tn.Name, err)
		}
	}

	mailer, err := email.New(cfg.Email, log)
	if err != nil {
		return nil, err
	}
	emailRenderer, err := email.NewRenderer()
	if err != nil {
		return nil, err
	}
	tenantEmail := &email.Service{Store: st, Wrapper: wrapper, Renderer: emailRenderer, Providers: &providers.Factory{LocalSMTPAllowlist: cfg.Email.AllowLocalSMTP}, Fallback: mailer, DefaultFrom: cfg.Email.From}
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

	// The workers send verification and import completion emails through
	// the same mailer kind as the Management API's users routes.
	exportKey, err := secrets.DeriveKey(masterKey, mgmt.ExportLinkInfo)
	if err != nil {
		return nil, err
	}
	jobRunner := &jobs.Runner{
		Store: st, Workers: cfg.Jobs.Workers, LeaseFor: cfg.Jobs.Lease, Log: log,
		Processors: map[store.JobType]jobs.Processor{
			store.JobVerificationEmail: jobs.VerifyEmail{
				Sender: &login.VerificationMailer{Store: st, Mailer: mailer, Email: tenantEmail, BaseDomain: cfg.Server.BaseDomain, Log: log},
				Log:    log,
			},
			store.JobUsersImport: jobs.Importer{Mailer: mailer, Email: tenantEmail, Log: log},
			store.JobUsersExport: jobs.Exporter{View: mgmt.UserJSON, Log: log},
		},
		Sweeps: []jobs.Sweep{{Name: "actions continuations", Every: time.Minute,
			Run: func(ctx context.Context, st store.Store, now time.Time) error {
				_, err := actions.PurgeContinue(ctx, st, now)
				return err
			}}},
	}

	var checker protection.BreachChecker
	var breachFile *protection.FileChecker
	switch cfg.Security.BreachedPasswords.Mode {
	case "", "off":
	case "range":
		checker = protection.NewRangeChecker(nil)
	case "file":
		breachFile, err = protection.NewFileChecker(cfg.Security.BreachedPasswords.File)
		if err != nil {
			_ = runner.Close()
			return nil, fmt.Errorf("app: breached password corpus unavailable or invalid")
		}
		checker = breachFile
	default:
		_ = runner.Close()
		return nil, fmt.Errorf("app: invalid breached password mode")
	}
	// Social login: a bounded production network policy, and the restricted
	// profile script runner when Node can prove network denial. Without it
	// custom OAuth2 login alone is unavailable.
	providers := federation.NewProviders(federation.NetworkPolicy{}, nil)
	if o.federation != nil {
		providers = o.federation()
	}
	profiles, err := script.NewRunner(script.Config{Node: cfg.CustomDB.Node}, script.NewBroker(providers.HTTPClient()))
	if err == nil {
		if perr := profiles.Probe(); perr != nil {
			log.Warn("custom OAuth2 profile scripts unavailable", "reason", perr)
		}
		providers.WithScripts(profiles)
	} else {
		log.Warn("custom OAuth2 profile scripts unavailable", "reason", err)
		profiles = nil
	}
	// Actions flows run in their own Node processes, started on first use.
	actionsRunner, err := actions.NewRunner(cfg.Actions, builds, log)
	if err != nil {
		builds.Close()
		_ = runner.Close()
		if profiles != nil {
			_ = profiles.Close()
		}
		return nil, err
	}
	engine := &actions.Engine{Store: st, Runner: actionsRunner, Builds: builds, Secrets: wrapper, Log: log}
	tenantEmail.Actions = engine
	flows := &federation.FlowService{Service: federation.Service{Wrapper: wrapper}, Store: st, Providers: providers, Log: log}
	sec := cfg.Security
	buildsOwned = true
	return &App{
		profiles:   profiles,
		tls:        tlsManager,
		acme:       acmeWorker,
		domains:    domains,
		cfg:        cfg,
		log:        log,
		store:      st,
		runner:     runner,
		builds:     builds,
		actions:    actionsRunner,
		actionJobs: &actions.Worker{Engine: engine, Store: st, Workers: cfg.Actions.JobWorkers, Poll: cfg.Actions.JobPollInterval},
		jobs:       jobRunner,
		breachFile: breachFile,
		handler: server.New(server.Deps{
			Store:        st,
			Keys:         km,
			Resolver:     tenant.NewResolver(st.Tenants(), cfg.Server.BaseDomain, cfg.Server.TrustProxyHeaders),
			Sessions:     &session.Manager{Store: st, TrustProxyHeaders: cfg.Server.TrustProxyHeaders},
			Log:          log,
			Mailer:       mailer,
			EmailService: tenantEmail,
			JobNotify:    jobRunner.Notify,
			ExportKey:    exportKey,
			Wrapper:      wrapper,
			Scripts:      &customdb.Client{Exec: runner, Wrapper: wrapper},
			Federation:   flows,
			Actions:      engine,

			Protection:        &protection.Service{Store: st, Log: log, BreachChecker: checker, Wrapper: wrapper, Notifier: tenantEmail},
			TrustProxyHeaders: cfg.Server.TrustProxyHeaders,
			BaseDomain:        cfg.Server.BaseDomain,
			SystemHost:        systemHost,
			Domains:           domains,

			DeviceTxnThrottle: identity.NewThrottle(sec.DeviceActivationTxnMaxMisses, authz.TxnLifetime, authz.TxnLifetime),
			DeviceIPThrottle: identity.NewThrottleOrOff(sec.DeviceActivationIPMaxMisses,
				seconds(sec.DeviceActivationIPLockoutSeconds), seconds(sec.DeviceActivationIPLockoutSeconds)),
			DeviceTenantThrottle: identity.NewThrottleOrOff(sec.DeviceActivationTenantMaxMisses,
				seconds(sec.DeviceActivationTenantWindowSeconds), seconds(sec.DeviceActivationTenantLockoutSeconds)),
		}),
	}, nil
}

// bootstrapOperator creates the first operator from bootstrap.admin_email
// when the system tenant has none, and logs its one-time setup link.
func bootstrapOperator(ctx context.Context, st store.Store, email string, log *slog.Logger) error {
	link, err := system.Bootstrap(ctx, st, email)
	if err != nil || link == "" {
		return err
	}
	log.Warn("created the first console operator from bootstrap.admin_email; open the one-time setup link within an hour to choose a password",
		"email", email, "setup_url", link, "expires_in", system.SetupLinkLifetime.String())
	return nil
}

// checkCustomDB warns once when a tenant has a customized connection and
// Node.js cannot run scripts. The server still starts: other tenants and
// connections keep working, and those connections fail per request.
func checkCustomDB(ctx context.Context, st store.Store, tenants []*store.Tenant, runner *customdb.NodeRunner, log *slog.Logger) error {
	for _, tn := range tenants {
		conns, _, err := st.Connections().List(ctx, tn.ID, store.ConnectionFilter{}, store.Page{})
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

// certificateManager builds the ACME-mode certificate manager, after the
// registry is reconciled, and checks that every canonical and system host is
// covered by the static certificate or the hosted wildcard.
func certificateManager(ctx context.Context, cfg *config.Config, st store.Store, w keys.Wrapper) (*certificates.Manager, error) {
	a := cfg.Server.ACME
	if !a.Enabled {
		return nil, nil
	}
	var static []tls.Certificate
	if cfg.Server.TLSCertFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("app: static TLS certificate: %w", err)
		}
		static = append(static, c)
	}
	m, err := certificates.NewManager(st, w, certificates.Config{
		DeploymentID: a.DeploymentID, DirectoryURL: a.DirectoryURL, BaseDomain: cfg.Server.BaseDomain,
		HostedWildcard: a.HostedWildcard.Enabled, Static: static,
	}, time.Now)
	if err != nil {
		return nil, err
	}
	if err := m.ValidateCoverage(ctx); err != nil {
		return nil, fmt.Errorf("app: TLS coverage: %w", err)
	}
	return m, nil
}

// domainService builds the custom domain service: API operations, proxy
// admission and ownership proof. Managed domains need ACME; self-managed
// ones need origin TLS (the ACME manager's coverage, or a static certificate
// covering the origin namespace). Without a usable resolver the API is off.
func domainService(cfg *config.Config, st store.Store, m *certificates.Manager, systemHost string, log *slog.Logger) (*customdomain.Service, error) {
	resolver := cfg.Server.CustomDomains.DNSResolver
	if resolver == "" {
		var err error
		if resolver, err = customdomain.SystemResolver(); err != nil {
			if m != nil {
				return nil, fmt.Errorf("app: set server.custom_domains.dns_resolver: %w", err)
			}
			log.Warn("custom domains are unavailable: no DNS resolver; set server.custom_domains.dns_resolver", "err", err)
			return nil, nil
		}
	}
	proxies, err := cfg.Server.TrustedProxies()
	if err != nil {
		return nil, err
	}
	origin := cfg.Server.OriginDomain()
	originTLS := false
	switch {
	case origin == "":
	case m != nil:
		originTLS = m.CoversOrigin(origin)
	case cfg.Server.TLSCertFile != "":
		originTLS = staticCovers(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile, "cd-0."+origin)
	}
	return customdomain.NewService(st, &customdomain.BoundedResolver{Server: resolver}, customdomain.ServiceConfig{
		BaseDomain: cfg.Server.BaseDomain, SystemHost: systemHost, OriginDomain: origin,
		ManagedEnabled: m != nil, OriginTLSReady: originTLS,
		Proxy: customdomain.ProxyPolicy{Trusted: proxies, LegacyTrust: cfg.Server.TrustProxyHeaders},
	}, time.Now, rand.Reader), nil
}

// staticCovers reports whether the static certificate serves host.
func staticCovers(certFile, keyFile, host string) bool {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil || len(c.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	return err == nil && leaf.VerifyHostname(host) == nil
}

// certificateWorker builds the ACME worker when ACME is on; it re-proves
// ownership through the domain service.
func certificateWorker(cfg *config.Config, m *certificates.Manager, domains *customdomain.Service) (*certificates.Worker, error) {
	if m == nil {
		return nil, nil
	}
	resolver := cfg.Server.CustomDomains.DNSResolver
	if resolver == "" {
		var err error
		if resolver, err = customdomain.SystemResolver(); err != nil {
			return nil, fmt.Errorf("app: set server.custom_domains.dns_resolver: %w", err)
		}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	a := cfg.Server.ACME
	if a.CABundleFile != "" {
		b, err := os.ReadFile(a.CABundleFile)
		if err != nil || !roots.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("app: server.acme.ca_bundle_file %q has no usable certificates", a.CABundleFile)
		}
	}
	var hosted *certificates.HostedConfig
	if w := a.HostedWildcard; w.Enabled {
		// The token stays in its deployment file: never tenant state or logs.
		raw, err := os.ReadFile(w.TokenFile)
		token := strings.TrimSpace(string(raw))
		if err != nil || token == "" {
			return nil, fmt.Errorf("app: server.acme.hosted_wildcard.token_file %q is unreadable or empty", w.TokenFile)
		}
		hosted = &certificates.HostedConfig{
			BaseDomain: cfg.Server.BaseDomain, Zone: w.Zone, Provider: certificates.NewDigitalOcean(token),
			Resolver: &customdomain.BoundedResolver{Server: resolver},
		}
	}
	host, _ := os.Hostname()
	owner := host + "-" + secrets.RandomString(8)
	worker := certificates.NewWorker(m, certificates.NewACMECA(a.DirectoryURL, roots), domains, certificates.WorkerConfig{
		Owner: owner, Email: a.Email, Challenge: a.Challenge, Roots: roots, Workers: a.Workers, Hosted: hosted,
	})
	return worker, nil
}

// Serve listens until ctx is cancelled, then shuts down gracefully.
func (a *App) Serve(ctx context.Context) error {
	srv := a.httpServer()
	useTLS := a.cfg.Server.TLSCertFile != "" || a.tls != nil
	errc := make(chan error, 1)
	go func() {
		if a.tls != nil {
			srv.TLSConfig, _ = a.tls.TLSConfig()
			errc <- srv.ListenAndServeTLS("", "")
		} else if useTLS {
			errc <- srv.ListenAndServeTLS(a.cfg.Server.TLSCertFile, a.cfg.Server.TLSKeyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	a.log.Info("listening", "addr", a.cfg.Server.Listen, "tls", useTLS)
	if a.tls != nil && a.cfg.Server.ACME.HTTPListen != "" {
		// HTTP-01 challenges and HTTPS redirects for registered hosts only.
		challenges := &http.Server{
			Addr: a.cfg.Server.ACME.HTTPListen, Handler: a.tls.HTTPHandler(nil),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		}
		go func() {
			if err := challenges.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case errc <- fmt.Errorf("app: challenge listener: %w", err):
				default: // the main listener already failed
				}
			}
		}()
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = challenges.Shutdown(sctx)
		}()
		a.log.Info("listening for ACME HTTP-01", "addr", a.cfg.Server.ACME.HTTPListen)
	}
	if a.domains != nil {
		proofCtx, stopProof := context.WithCancel(ctx)
		proofDone := make(chan struct{})
		go func() { defer close(proofDone); a.domainProofLoop(proofCtx, 30*time.Second) }()
		defer func() {
			stopProof()
			select {
			case <-proofDone:
			case <-time.After(10 * time.Second):
				a.log.Warn("domain proof worker did not stop within 10s")
			}
		}()
	}
	if a.acme != nil {
		acmeCtx, stopACME := context.WithCancel(ctx)
		acmeDone := make(chan struct{})
		go func() { defer close(acmeDone); a.acme.Run(acmeCtx) }()
		defer func() {
			stopACME()
			select {
			case <-acmeDone:
			case <-time.After(10 * time.Second):
				a.log.Warn("certificate worker did not stop within 10s; its leases expire on their own")
			}
		}()
	}
	go a.sweepLoop(ctx, sweepInterval)
	if a.builds != nil {
		// Pre-extract deployed Action builds in the background.
		go func() {
			if err := a.builds.Prewarm(ctx); err != nil && ctx.Err() == nil {
				a.log.Warn("actions: pre-extracting deployed builds failed", "err", err)
			}
		}()
	}
	if a.actionJobs != nil {
		workerCtx, stopWorker := context.WithCancel(ctx)
		workerDone := make(chan struct{})
		go func() { defer close(workerDone); a.actionJobs.Run(workerCtx) }()
		defer func() { stopWorker(); <-workerDone }()
	}
	if a.jobs != nil && a.jobs.Workers > 0 {
		// Workers stop with Serve, which waits a little for the job they
		// are on before the caller closes the store.
		jobsCtx, stopJobs := context.WithCancel(ctx)
		jobsDone := make(chan struct{})
		go func() { defer close(jobsDone); a.jobs.Run(jobsCtx) }()
		defer func() {
			stopJobs()
			select {
			case <-jobsDone:
			case <-time.After(10 * time.Second):
				a.log.Warn("job workers did not stop within 10s; a job may be left to its lease")
			}
		}()
	}

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

// Close stops Actions builds and runners and the custom database runner and closes the
// store.
func (a *App) Close() error {
	if a.builds != nil {
		a.builds.Close()
	}
	var errRunner error
	if a.actions != nil {
		errRunner = a.actions.Close()
	}
	if a.runner != nil {
		errRunner = errors.Join(errRunner, a.runner.Close())
	}
	if a.profiles != nil {
		_ = a.profiles.Close()
	}
	var errBreach error
	if a.breachFile != nil {
		errBreach = a.breachFile.Close()
	}
	return errors.Join(errRunner, errBreach, a.store.Close())
}

func seconds(n int) time.Duration { return time.Duration(n) * time.Second }

// Proof retries and ownership-loss checks run independently of issuance;
// customer-proxy domains need the same lifecycle even with ACME disabled.
func (a *App) domainProofLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := a.domains.CheckDue(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("domain ownership checks failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
