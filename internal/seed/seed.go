// Package seed applies a declarative YAML description of tenants, APIs,
// applications and grants to a store. Until the Management API exists,
// seeding is how zeroauthy is administered.
package seed

import (
	"bytes"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

type File struct {
	Tenants []Tenant `yaml:"tenants"`
}

type Tenant struct {
	Name            string           `yaml:"name"`
	FriendlyName    string           `yaml:"friendly_name"`
	Domains         []string         `yaml:"domains"`
	DefaultAudience string           `yaml:"default_audience"`
	ResourceServers []ResourceServer `yaml:"resource_servers"`
	Clients         []Client         `yaml:"clients"`
	ClientGrants    []ClientGrant    `yaml:"client_grants"`
}

type ResourceServer struct {
	Identifier         string  `yaml:"identifier"`
	Name               string  `yaml:"name"`
	Scopes             []Scope `yaml:"scopes"`
	TokenLifetime      int     `yaml:"token_lifetime"`
	AllowOfflineAccess bool    `yaml:"allow_offline_access"`
}

type Scope struct {
	Value       string `yaml:"value"`
	Description string `yaml:"description"`
}

type Client struct {
	ClientID string `yaml:"client_id"`
	Name     string `yaml:"name"`
	AppType  string `yaml:"app_type"`
	// ClientSecret is plaintext in the seed file and hashed when applied.
	// Protect seed files like any other credential store.
	ClientSecret            string   `yaml:"client_secret"`
	TokenEndpointAuthMethod string   `yaml:"token_endpoint_auth_method"`
	GrantTypes              []string `yaml:"grant_types"`
	Callbacks               []string `yaml:"callbacks"`
	AllowedLogoutURLs       []string `yaml:"allowed_logout_urls"`
	WebOrigins              []string `yaml:"web_origins"`
	AllowedOrigins          []string `yaml:"allowed_origins"`
}

type ClientGrant struct {
	ClientID string   `yaml:"client_id"`
	Audience string   `yaml:"audience"`
	Scopes   []string `yaml:"scopes"`
}

// Load reads and validates a seed file.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("seed %s: %w", path, err)
	}
	return f, nil
}

// Parse decodes seed YAML, rejecting unknown fields, and validates it.
func Parse(data []byte) (*File, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}
