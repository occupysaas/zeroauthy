// Package config loads zeroauthy configuration from a YAML file and
// ZEROAUTHY_* environment variables. In variable names, "__" separates
// nesting levels: ZEROAUTHY_SERVER__LISTEN sets server.listen.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const envPrefix = "ZEROAUTHY_"

type Config struct {
	Server   Server   `koanf:"server"`
	Storage  Storage  `koanf:"storage"`
	Security Security `koanf:"security"`
	Log      Log      `koanf:"log"`
	Email    Email    `koanf:"email"`
	// Seed is an optional path to a declarative seed file applied at startup.
	Seed string `koanf:"seed"`
}

type Server struct {
	Listen string `koanf:"listen"`
	// BaseDomain makes tenant "acme" reachable at acme.<BaseDomain>.
	BaseDomain string `koanf:"base_domain"`
	// TrustProxyHeaders honors X-Forwarded-Host. Enable it only behind a
	// proxy that sets the header.
	TrustProxyHeaders bool   `koanf:"trust_proxy_headers"`
	TLSCertFile       string `koanf:"tls_cert_file"`
	TLSKeyFile        string `koanf:"tls_key_file"`
}

type Storage struct {
	// DSN selects the driver: memory://, and later sqlite://, postgres://,
	// mysql://, plugin://.
	DSN string `koanf:"dsn"`
}

type Security struct {
	// MasterKey is a base64-encoded 32-byte key. Prefer MasterKeyFile.
	MasterKey     string `koanf:"master_key"`
	MasterKeyFile string `koanf:"master_key_file"`

	// LoginMaxAttempts failed logins for one account within the lockout
	// window lock that account for LoginLockoutSeconds. Per-IP limits are
	// ten times higher.
	LoginMaxAttempts    int `koanf:"login_max_attempts"`
	LoginLockoutSeconds int `koanf:"login_lockout_seconds"`
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
		Server:   Server{Listen: ":8080"},
		Log:      Log{Level: "info", Format: "json"},
		Security: Security{LoginMaxAttempts: 10, LoginLockoutSeconds: 900},
		Email:    Email{Driver: "log", From: "zeroauthy@localhost", SMTP: SMTP{Port: 587}},
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
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	var errs []error
	if c.Storage.DSN == "" {
		errs = append(errs, errors.New("storage.dsn is required"))
	}
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
