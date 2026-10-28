// Package config loads zeroauthy configuration from a YAML file and
// ZEROAUTHY_* environment variables. In variable names, "__" separates
// nesting levels: ZEROAUTHY_SERVER__LISTEN sets server.listen.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const envPrefix = "ZEROAUTHY_"

type Config struct {
	Server   Server   `koanf:"server"`
	Storage  Storage  `koanf:"storage"`
	Security Security `koanf:"security"`
	Log      Log      `koanf:"log"`
	Email    Email    `koanf:"email"`
	CustomDB CustomDB `koanf:"custom_db"`
	Actions  Actions  `koanf:"actions"`
	Jobs     Jobs     `koanf:"jobs"`
	// Bootstrap creates the first console operator on an empty install.
	Bootstrap Bootstrap `koanf:"bootstrap"`
	// Seed is an optional path to a declarative seed file applied at startup.
	Seed string `koanf:"seed"`
	// SeedMode is "apply" (the default: the seed overwrites what it
	// defines at every start) or "create_only" (it only creates what is
	// missing, so edits made in the console survive a restart).
	SeedMode string `koanf:"seed_mode"`
}

type Server struct {
	Listen string `koanf:"listen"`
	// BaseDomain makes tenant "acme" reachable at acme.<BaseDomain>.
	BaseDomain string `koanf:"base_domain"`
	// SystemHost is the host of the system tenant, which serves the console
	// at /admin. It defaults to system.<BaseDomain> and is required when
	// BaseDomain is empty. No other tenant may use it.
	SystemHost string `koanf:"system_host"`
	// TrustProxyHeaders honors X-Forwarded-Host. Enable it only behind a
	// proxy that sets the header. Deprecated without TrustedProxyCIDRs.
	TrustProxyHeaders bool `koanf:"trust_proxy_headers"`
	// TrustedProxyCIDRs lists the immediate peers allowed to act as proxies:
	// self-managed custom-domain proxies, and the only peers whose forwarded
	// headers TrustProxyHeaders honors once any are listed. Entries may also
	// be comma-separated (one environment variable).
	TrustedProxyCIDRs []string      `koanf:"trusted_proxy_cidrs"`
	ACME              ACME          `koanf:"acme"`
	CustomDomains     CustomDomains `koanf:"custom_domains"`
	TLSCertFile       string        `koanf:"tls_cert_file"`
	TLSKeyFile        string        `koanf:"tls_key_file"`
}

// ACME is opt-in automatic certificate issuance for managed custom domains
// and the hosted wildcard. It never disables certificate validation.
type ACME struct {
	Enabled bool `koanf:"enabled"`
	// DirectoryURL is the CA's ACME directory (HTTPS only); accounts are
	// bound to it, so staging and production never share an account.
	DirectoryURL  string `koanf:"directory_url"`
	Email         string `koanf:"email"`
	TermsAccepted bool   `koanf:"terms_accepted"`
	// DeploymentID is a stable identifier shared by every replica; it binds
	// sealed TLS material to this deployment.
	DeploymentID string `koanf:"deployment_id"`
	// Challenge is http-01 or tls-alpn-01; there is no hidden fallback.
	Challenge string `koanf:"challenge"`
	// HTTPListen serves HTTP-01 challenges (default :80); it must be empty
	// for tls-alpn-01.
	HTTPListen string `koanf:"http_listen"`
	// CABundleFile adds trust roots for the CA's issued chains.
	CABundleFile   string         `koanf:"ca_bundle_file"`
	Workers        int            `koanf:"workers"`
	HostedWildcard HostedWildcard `koanf:"hosted_wildcard"`
}

// HostedWildcard issues base_domain and *.base_domain through DigitalOcean
// DNS-01. The token stays in a deployment file, never in tenant state.
type HostedWildcard struct {
	Enabled   bool   `koanf:"enabled"`
	Zone      string `koanf:"zone"`
	TokenFile string `koanf:"token_file"`
}

// CustomDomains is deployment policy for API custom domains.
type CustomDomains struct {
	// OriginDomain is the operator DNS suffix of private origin aliases
	// (cd-<hex>.<origin_domain>); it defaults to base_domain.
	OriginDomain string `koanf:"origin_domain"`
	// DNSResolver (host:port) answers ownership-proof and diagnostic
	// lookups; it defaults to the host's first resolv.conf nameserver.
	DNSResolver string `koanf:"dns_resolver"`
}

// OriginDomain is the effective origin suffix, normalized; "" when neither
// it nor base_domain is set.
func (s Server) OriginDomain() string {
	if s.CustomDomains.OriginDomain != "" {
		return tenant.NormalizeHost(s.CustomDomains.OriginDomain)
	}
	return tenant.NormalizeHost(s.BaseDomain)
}

// Bootstrap configures the first console operator for automated installs.
type Bootstrap struct {
	// AdminEmail, when set and the system tenant has no operator, makes
	// the server create that operator at start and log a one-time setup
	// link. It never takes a password.
	AdminEmail string `koanf:"admin_email"`
}

type Storage struct {
	// DSN selects the driver: memory://, sqlite://, postgres:// (or
	// postgresql://), mysql://. plugin:// comes with the gRPC plugin host.
	DSN string `koanf:"dsn"`
	// AutoMigrate applies pending schema migrations at startup. When false,
	// serve refuses to start against a schema that is behind or ahead; run
	// zeroauthy migrate first.
	AutoMigrate bool `koanf:"auto_migrate"`
}

type BreachedPasswords struct {
	Mode string `koanf:"mode"`
	File string `koanf:"file"`
}

type Security struct {
	BreachedPasswords           BreachedPasswords `koanf:"breached_passwords"`
	LoginMaxAttemptsExplicit    bool              `koanf:"-"`
	LoginLockoutSecondsExplicit bool              `koanf:"-"`

	// MasterKey is a base64-encoded 32-byte key. Prefer MasterKeyFile.
	MasterKey     string `koanf:"master_key"`
	MasterKeyFile string `koanf:"master_key_file"`

	// LoginMaxAttempts failed logins for one account within the lockout
	// window lock that account for LoginLockoutSeconds. Per-IP limits are
	// ten times higher.
	LoginMaxAttempts    int `koanf:"login_max_attempts"`
	LoginLockoutSeconds int `koanf:"login_lockout_seconds"`

	// Device activation limits wrong user codes. The transaction limit
	// (misses on one device code) must be at least 1. The IP and tenant
	// limits are off at 0.
	DeviceActivationTxnMaxMisses         int `koanf:"device_activation_txn_max_misses"`
	DeviceActivationIPMaxMisses          int `koanf:"device_activation_ip_max_misses"`
	DeviceActivationIPLockoutSeconds     int `koanf:"device_activation_ip_lockout_seconds"`
	DeviceActivationTenantMaxMisses      int `koanf:"device_activation_tenant_max_misses"`
	DeviceActivationTenantWindowSeconds  int `koanf:"device_activation_tenant_window_seconds"`
	DeviceActivationTenantLockoutSeconds int `koanf:"device_activation_tenant_lockout_seconds"`
}

// CustomDB configures the runner for custom database connection scripts.
type CustomDB struct {
	Node        string        `koanf:"node"`          // Node.js executable; default "node"
	ModulesDir  string        `koanf:"modules_dir"`   // optional absolute path of allowed npm modules
	MaxMemoryMB int           `koanf:"max_memory_mb"` // default 256, at least 32
	IdleTimeout time.Duration `koanf:"idle_timeout"`  // idle runner lifetime; default 5m
}

// Actions configures the Actions runner and the npm dependency builds.
type Actions struct {
	Node string `koanf:"node"` // Node.js executable; default "node"
	// NPMCLI is the absolute path of npm's bin/npm-cli.js; default the npm
	// bundled with Node (<node prefix>/lib/node_modules/npm). Builds run it
	// under Node's permission model, never as a separate npm executable.
	NPMCLI string `koanf:"npm_cli"`
	// Registry is the npm registry (or a mirror for air-gapped installs);
	// default https://registry.npmjs.org/.
	Registry string `koanf:"registry"`
	// CacheDir is the absolute path holding extracted builds, one 0700
	// directory per tenant. Default: <user cache dir>/zeroauthy/actions-cache,
	// i.e. $XDG_CACHE_HOME or $HOME/.cache on Linux. When neither is known
	// the server still starts, logs a warning, and Actions builds fail until
	// cache_dir is set.
	CacheDir            string        `koanf:"cache_dir"`
	MaxMemoryMB         int           `koanf:"max_memory_mb"`         // runner heap; default 256, at least 32
	IdleTimeout         time.Duration `koanf:"idle_timeout"`          // idle runner lifetime; default 5m
	BuildTimeout        time.Duration `koanf:"build_timeout"`         // one build's time limit; default 2m
	MaxArtifactMB       int           `koanf:"max_artifact_mb"`       // installed and packed size cap; default 50, at most 50
	MaxConcurrentBuilds int           `koanf:"max_concurrent_builds"` // builds at once on this server; default 2
}

// maxActionsArtifactMB is the store's artifact limit in MB (10^6 bytes; spec §5).
var maxActionsArtifactMB = actionsrules.Inventory().Limits["artifact_bytes_max"] / 1_000_000

// Jobs configures the workers that run Management API jobs.
type Jobs struct {
	// Workers is how many jobs this process runs at once; default 2. 0
	// disables the pool on this process (another process may run the jobs).
	Workers int `koanf:"workers"`
	// Lease is how long a worker holds a job before another may take it
	// over; workers renew it every third of it. Default 60s, at least 1s.
	Lease time.Duration `koanf:"lease"`
}

type Log struct {
	Level  string `koanf:"level"`  // debug, info, warn, error
	Format string `koanf:"format"` // json, text
}

// Email configures outgoing mail (password reset, verification).
type Email struct {
	Driver string `koanf:"driver"` // log (default) | dir | smtp
	From   string `koanf:"from"`   // default "zeroauthy@localhost"
	Dir    string `koanf:"dir"`
	SMTP   SMTP   `koanf:"smtp"`
	// LogLinks makes the log driver print reset links in full. Off by
	// default: a logged link lets anyone who reads the log reset a password.
	LogLinks bool `koanf:"log_links"`
	// AllowLocalSMTP permits explicit host:port targets that resolve to private
	// addresses. Leave empty in production unless local relay use is deliberate.
	AllowLocalSMTP []string `koanf:"allow_local_smtp"`
}

type SMTP struct {
	Host     string `koanf:"host"`
	Port     int    `koanf:"port"` // default 587
	Username string `koanf:"username"`
	Password string `koanf:"password"`
	Insecure bool   `koanf:"insecure"` // allow plaintext (no STARTTLS); for local test servers only
}

func defaults() *Config {
	return &Config{
		Server:   Server{Listen: ":8080", ACME: ACME{DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory", Workers: 2}},
		Log:      Log{Level: "info", Format: "json"},
		SeedMode: "apply",
		Security: Security{
			LoginMaxAttempts: 10, LoginLockoutSeconds: 900, BreachedPasswords: BreachedPasswords{Mode: "off"},
			DeviceActivationTxnMaxMisses: 5, DeviceActivationIPMaxMisses: 10, DeviceActivationIPLockoutSeconds: 900,
			DeviceActivationTenantMaxMisses: 1000, DeviceActivationTenantWindowSeconds: 600, DeviceActivationTenantLockoutSeconds: 60,
		},
		Jobs:     Jobs{Workers: 2, Lease: time.Minute},
		CustomDB: CustomDB{Node: "node", MaxMemoryMB: 256, IdleTimeout: 5 * time.Minute},
		Actions: Actions{
			Node: "node", Registry: "https://registry.npmjs.org/", MaxMemoryMB: 256, IdleTimeout: 5 * time.Minute,
			BuildTimeout: 2 * time.Minute, MaxArtifactMB: maxActionsArtifactMB, MaxConcurrentBuilds: 2,
		},
		Email: Email{Driver: "log", From: "zeroauthy@localhost", SMTP: SMTP{Port: 587}},
	}
}

// Load reads the YAML file at path (skipped when path is ""), applies
// ZEROAUTHY_* variables from environ, and validates the result.
func Load(path string, environ []string) (*Config, error) {
	k := koanf.New(".")
	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
	}
	err := k.Load(env.Provider(".", env.Opt{
		Prefix:      envPrefix,
		EnvironFunc: func() []string { return environ },
		TransformFunc: func(key, value string) (string, any) {
			// ZEROAUTHY_CONFIG names the config file (see cmd/zeroauthy); it is
			// not a setting. An empty key makes koanf drop the entry, so it does
			// not reach strict decoding as an unknown key "config".
			if key == envPrefix+"CONFIG" {
				return "", nil
			}
			key = strings.ToLower(strings.TrimPrefix(key, envPrefix))
			return strings.ReplaceAll(key, "__", "."), value
		},
	}), nil)
	if err != nil {
		return nil, fmt.Errorf("config: environment: %w", err)
	}
	cfg := defaults()
	// ErrorUnused makes misspelled keys (file or environment) fail loudly
	// instead of silently leaving a setting at its default.
	err = k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
			WeaklyTypedInput: true,
			ErrorUnused:      true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.Security.LoginMaxAttemptsExplicit = k.Exists("security.login_max_attempts")
	cfg.Security.LoginLockoutSecondsExplicit = k.Exists("security.login_lockout_seconds")
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validateACME checks issuance settings and fills the HTTP-01 listener
// default. Settings of a disabled feature are not interpreted.
func (s *Server) validateACME() []error {
	var errs []error
	a := &s.ACME
	if o := s.CustomDomains.OriginDomain; o != "" {
		if h, err := hostname.NormalizeDNSName(o); err != nil || h != tenant.NormalizeHost(o) {
			errs = append(errs, fmt.Errorf("server.custom_domains.origin_domain %q must be a DNS name without scheme or port", o))
		}
	}
	if r := s.CustomDomains.DNSResolver; r != "" {
		if _, err := netip.ParseAddrPort(r); err != nil {
			errs = append(errs, fmt.Errorf("server.custom_domains.dns_resolver %q must be an IP address and port", r))
		}
	}
	if a.HostedWildcard.Enabled {
		w := a.HostedWildcard
		base, err := hostname.NormalizeDNSName(s.BaseDomain)
		zone, zerr := hostname.NormalizeDNSName(w.Zone)
		switch {
		case !a.Enabled:
			errs = append(errs, errors.New("server.acme.hosted_wildcard needs server.acme.enabled"))
		case s.BaseDomain == "" || err != nil:
			errs = append(errs, errors.New("server.acme.hosted_wildcard needs a portless DNS server.base_domain"))
		case w.Zone == "" || zerr != nil:
			errs = append(errs, errors.New("server.acme.hosted_wildcard.zone must name the DNS zone containing base_domain"))
		case base != zone && !strings.HasSuffix(base, "."+zone):
			errs = append(errs, fmt.Errorf("server.base_domain %q is not inside server.acme.hosted_wildcard.zone %q", base, zone))
		}
		if w.TokenFile == "" {
			errs = append(errs, errors.New("server.acme.hosted_wildcard.token_file is required"))
		}
	}
	if !a.Enabled {
		return errs
	}
	if u, err := url.Parse(a.DirectoryURL); err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, fmt.Errorf("server.acme.directory_url %q must be an https URL", a.DirectoryURL))
	}
	if m, err := mail.ParseAddress(a.Email); err != nil || m.Address != a.Email {
		errs = append(errs, errors.New("server.acme.email must be a valid contact address"))
	}
	if !a.TermsAccepted {
		errs = append(errs, errors.New("server.acme.terms_accepted must be true to use the CA"))
	}
	if strings.TrimSpace(a.DeploymentID) == "" {
		errs = append(errs, errors.New("server.acme.deployment_id is required and must be the same on every replica"))
	}
	switch a.Challenge {
	case "http-01":
		if a.HTTPListen == "" {
			a.HTTPListen = ":80"
		}
	case "tls-alpn-01":
		if a.HTTPListen != "" {
			errs = append(errs, errors.New("server.acme.http_listen must be empty for tls-alpn-01"))
		}
	default:
		errs = append(errs, errors.New("server.acme.challenge must be http-01 or tls-alpn-01"))
	}
	if a.Workers < 1 || a.Workers > 8 {
		errs = append(errs, fmt.Errorf("server.acme.workers %d must be between 1 and 8", a.Workers))
	}
	return errs
}

// TrustedProxies parses TrustedProxyCIDRs.
func (s Server) TrustedProxies() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, entry := range s.TrustedProxyCIDRs {
		for _, raw := range strings.Split(entry, ",") {
			if raw = strings.TrimSpace(raw); raw == "" {
				continue
			}
			p, err := netip.ParsePrefix(raw)
			if err != nil || p.Addr().Zone() != "" {
				return nil, fmt.Errorf("server.trusted_proxy_cidrs: %q is not a CIDR prefix", raw)
			}
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

func (c *Config) validate() error {
	var errs []error
	switch c.Security.BreachedPasswords.Mode {
	case "off", "range":
	case "file":
		if c.Security.BreachedPasswords.File == "" {
			errs = append(errs, errors.New("security.breached_passwords.file is required in file mode"))
		}
	default:
		errs = append(errs, errors.New("security.breached_passwords.mode must be off, range or file"))
	}
	if c.Storage.DSN == "" {
		errs = append(errs, errors.New("storage.dsn is required"))
	}
	if c.Server.BaseDomain == "" && c.Server.SystemHost == "" {
		errs = append(errs, errors.New("server.system_host is required when server.base_domain is empty (the console's host, e.g. system.localhost:8443)"))
	}
	if h := c.Server.SystemHost; h != "" && (strings.ContainsAny(h, "/?#@ ") || strings.Contains(h, "://")) {
		errs = append(errs, fmt.Errorf("server.system_host %q must be a host name with an optional port, not a URL", h))
	}
	// The resolver maps <name>.<base_domain> to the tenant called name
	// before it looks at domains, so any other host under the base domain
	// could be captured by a tenant with a matching name.
	if bd, h := tenant.NormalizeHost(c.Server.BaseDomain), tenant.NormalizeHost(c.Server.SystemHost); bd != "" && h != "" &&
		strings.HasSuffix(h, "."+bd) && h != tenant.SystemName+"."+bd {
		errs = append(errs, fmt.Errorf("server.system_host %q is under server.base_domain, so it must be %s.%s (or a host outside the base domain)", c.Server.SystemHost, tenant.SystemName, bd))
	}
	if c.SeedMode != "apply" && c.SeedMode != "create_only" {
		errs = append(errs, fmt.Errorf("seed_mode %q must be apply or create_only", c.SeedMode))
	}
	if e := c.Bootstrap.AdminEmail; e != "" {
		if a, err := mail.ParseAddress(e); err != nil || a.Address != e {
			errs = append(errs, fmt.Errorf("bootstrap.admin_email %q is not a valid address", e))
		}
	}
	if _, err := c.Server.TrustedProxies(); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, c.Server.validateACME()...)
	if (c.Server.TLSCertFile == "") != (c.Server.TLSKeyFile == "") {
		errs = append(errs, errors.New("set both server.tls_cert_file and server.tls_key_file, or neither"))
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level %q must be debug, info, warn or error", c.Log.Level))
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log.format %q must be json or text", c.Log.Format))
	}
	if c.Security.MasterKey != "" && c.Security.MasterKeyFile != "" {
		errs = append(errs, errors.New("set only one of security.master_key and security.master_key_file"))
	}
	if c.Security.LoginMaxAttempts <= 0 || c.Security.LoginLockoutSeconds <= 0 {
		errs = append(errs, errors.New("security.login_max_attempts and security.login_lockout_seconds must be positive"))
	}
	sec := c.Security
	if sec.DeviceActivationTxnMaxMisses < 1 {
		errs = append(errs, errors.New("security.device_activation_txn_max_misses must be at least 1"))
	}
	if sec.DeviceActivationIPMaxMisses < 0 || sec.DeviceActivationTenantMaxMisses < 0 {
		errs = append(errs, errors.New("security.device_activation_ip_max_misses and device_activation_tenant_max_misses must not be negative"))
	}
	if sec.DeviceActivationIPMaxMisses > 0 && sec.DeviceActivationIPLockoutSeconds <= 0 {
		errs = append(errs, errors.New("security.device_activation_ip_lockout_seconds must be positive"))
	}
	if sec.DeviceActivationTenantMaxMisses > 0 && (sec.DeviceActivationTenantWindowSeconds <= 0 || sec.DeviceActivationTenantLockoutSeconds <= 0) {
		errs = append(errs, errors.New("security.device_activation_tenant_window_seconds and device_activation_tenant_lockout_seconds must be positive"))
	}
	if c.CustomDB.ModulesDir != "" && !filepath.IsAbs(c.CustomDB.ModulesDir) {
		errs = append(errs, errors.New("custom_db.modules_dir must be an absolute path"))
	}
	if c.CustomDB.MaxMemoryMB < 32 {
		errs = append(errs, fmt.Errorf("custom_db.max_memory_mb %d must be at least 32", c.CustomDB.MaxMemoryMB))
	}
	if c.CustomDB.Node == "" {
		errs = append(errs, errors.New("custom_db.node must not be empty"))
	}
	if c.CustomDB.IdleTimeout <= 0 {
		errs = append(errs, errors.New("custom_db.idle_timeout must be positive"))
	}
	errs = append(errs, c.Actions.validate()...)
	if c.Jobs.Workers < 0 {
		errs = append(errs, fmt.Errorf("jobs.workers %d must not be negative", c.Jobs.Workers))
	}
	if c.Jobs.Lease < time.Second {
		errs = append(errs, fmt.Errorf("jobs.lease %s must be at least 1s", c.Jobs.Lease))
	}
	switch c.Email.Driver {
	case "log":
	case "dir":
		if c.Email.Dir == "" {
			errs = append(errs, errors.New("email.dir is required with email.driver dir"))
		}
	case "smtp":
		if c.Email.SMTP.Host == "" || c.Email.SMTP.Port <= 0 || c.Email.SMTP.Port > 65535 {
			errs = append(errs, errors.New("email.smtp.host and a valid email.smtp.port are required with email.driver smtp"))
		}
	default:
		errs = append(errs, fmt.Errorf("email.driver %q must be log, dir or smtp", c.Email.Driver))
	}
	if a, err := mail.ParseAddress(c.Email.From); err != nil || strings.ContainsAny(c.Email.From, "\r\n") || a.Address == "" {
		errs = append(errs, fmt.Errorf("email.from %q is not a valid address", c.Email.From))
	}
	for _, target := range c.Email.AllowLocalSMTP {
		host, port, err := net.SplitHostPort(target)
		portNum, portErr := strconv.Atoi(port)
		if err != nil || host == "" || host == "*" || strings.ContainsAny(host, " \t\r\n") || portErr != nil || portNum < 1 || portNum > 65535 {
			errs = append(errs, fmt.Errorf("email.allow_local_smtp entry %q must be host:port", target))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// MasterKeyBytes decodes the configured master key. It returns nil, nil
// when no key is configured.
func (s Security) MasterKeyBytes() ([]byte, error) {
	encoded := s.MasterKey
	if s.MasterKeyFile != "" {
		b, err := os.ReadFile(s.MasterKeyFile)
		if err != nil {
			return nil, fmt.Errorf("config: master key file: %w", err)
		}
		encoded = string(b)
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("config: master key is not valid base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("config: master key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

func (a Actions) validate() []error {
	var errs []error
	if a.Node == "" {
		errs = append(errs, errors.New("actions.node must not be empty"))
	}
	if a.NPMCLI != "" && !filepath.IsAbs(a.NPMCLI) {
		errs = append(errs, errors.New("actions.npm_cli must be an absolute path"))
	}
	if a.CacheDir != "" && !filepath.IsAbs(a.CacheDir) {
		errs = append(errs, errors.New("actions.cache_dir must be an absolute path"))
	}
	if u, err := url.Parse(a.Registry); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, errors.New("actions.registry must be an http or https URL"))
	}
	if a.MaxMemoryMB < 32 {
		errs = append(errs, fmt.Errorf("actions.max_memory_mb %d must be at least 32", a.MaxMemoryMB))
	}
	if a.IdleTimeout <= 0 {
		errs = append(errs, errors.New("actions.idle_timeout must be positive"))
	}
	if a.BuildTimeout <= 0 {
		errs = append(errs, errors.New("actions.build_timeout must be positive"))
	}
	if a.MaxArtifactMB < 1 || a.MaxArtifactMB > maxActionsArtifactMB {
		errs = append(errs, fmt.Errorf("actions.max_artifact_mb %d must be between 1 and %d", a.MaxArtifactMB, maxActionsArtifactMB))
	}
	if a.MaxConcurrentBuilds < 1 {
		errs = append(errs, fmt.Errorf("actions.max_concurrent_builds %d must be at least 1", a.MaxConcurrentBuilds))
	}
	return errs
}
