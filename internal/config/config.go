// Package config loads zeroauthy configuration from a YAML file and
// ZEROAUTHY_* environment variables. In variable names, "__" separates
// nesting levels: ZEROAUTHY_SERVER__LISTEN sets server.listen.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

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
}

type Log struct {
	Level  string `koanf:"level"`  // debug, info, warn, error
	Format string `koanf:"format"` // json, text
}

func defaults() *Config {
	return &Config{
		Server: Server{Listen: ":8080"},
		Log:    Log{Level: "info", Format: "json"},
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
			key = strings.ToLower(strings.TrimPrefix(key, envPrefix))
			return strings.ReplaceAll(key, "__", "."), value
		},
	}), nil)
	if err != nil {
		return nil, fmt.Errorf("config: environment: %w", err)
	}
	cfg := defaults()
	if err := k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{Tag: "koanf"}); err != nil {
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
