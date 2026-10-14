// Package seed applies a declarative YAML description of tenants, APIs,
// applications and grants to a store. Until the Management API exists,
// seeding is how zeroauthy is administered.
package seed

import (
	"bytes"
	"fmt"
	"os"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"go.yaml.in/yaml/v3"
)

type File struct {
	Tenants []Tenant `yaml:"tenants"`
}

type Tenant struct {
	Name                string           `yaml:"name"`
	FriendlyName        string           `yaml:"friendly_name"`
	Domains             []string         `yaml:"domains"`
	DefaultAudience     string           `yaml:"default_audience"`
	DefaultDirectory    string           `yaml:"default_directory"`
	AllowedLogoutURLs   []string         `yaml:"allowed_logout_urls"`
	ResourceServers     []ResourceServer `yaml:"resource_servers"`
	Clients             []Client         `yaml:"clients"`
	ClientGrants        []ClientGrant    `yaml:"client_grants"`
	SessionLifetime     int              `yaml:"session_lifetime"`
	IdleSessionLifetime int              `yaml:"idle_session_lifetime"`
	Branding            Branding         `yaml:"branding"`
	Connections         []Connection     `yaml:"connections"`
	Users               []User           `yaml:"users"`
	EnabledLocales      []string         `yaml:"enabled_locales"`
	CustomText          store.CustomText `yaml:"custom_text"`
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
	ClientSecret            string       `yaml:"client_secret"`
	TokenEndpointAuthMethod string       `yaml:"token_endpoint_auth_method"`
	GrantTypes              []string     `yaml:"grant_types"`
	Callbacks               []string     `yaml:"callbacks"`
	AllowedLogoutURLs       []string     `yaml:"allowed_logout_urls"`
	WebOrigins              []string     `yaml:"web_origins"`
	AllowedOrigins          []string     `yaml:"allowed_origins"`
	IDTokenLifetime         int          `yaml:"id_token_lifetime"`
	RefreshToken            RefreshToken `yaml:"refresh_token"`
}

// RefreshToken is a client's refresh-token policy. Values follow Auth0's
// public application settings; empty types take defaults in validate.
type RefreshToken struct {
	RotationType      string `yaml:"rotation_type"`   // rotating | non-rotating
	ExpirationType    string `yaml:"expiration_type"` // expiring | non-expiring
	Leeway            int    `yaml:"leeway"`
	TokenLifetime     int    `yaml:"token_lifetime"`
	IdleTokenLifetime int    `yaml:"idle_token_lifetime"`
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

type Branding struct {
	LogoURL      string `yaml:"logo_url"`
	PrimaryColor string `yaml:"primary_color"`
}

type Connection struct {
	Name             string         `yaml:"name"`
	Strategy         string         `yaml:"strategy"`
	EnabledClients   []string       `yaml:"enabled_clients"`
	DisableSignup    bool           `yaml:"disable_signup"`
	RequiresUsername bool           `yaml:"requires_username"`
	PasswordPolicy   PasswordPolicy `yaml:"password_policy"`
}

type PasswordPolicy struct {
	MinLength               int `yaml:"min_length"`
	RequireCharacterClasses int `yaml:"require_character_classes"`
}

type User struct {
	Connection string `yaml:"connection"`
	Email      string `yaml:"email"`
	Username   string `yaml:"username"`
	// Password is plaintext in the seed file and hashed when applied.
	Password      string `yaml:"password"`
	EmailVerified bool   `yaml:"email_verified"`
	Name          string `yaml:"name"`
	Nickname      string `yaml:"nickname"`
	Picture       string `yaml:"picture"`
	Blocked       bool   `yaml:"blocked"`
}
