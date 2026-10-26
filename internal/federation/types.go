// Package federation implements Plan 24's upstream login: connection
// configuration for the federated strategies, provider adapters, single-use
// attempts and the identity/profile service. Strategy validation itself lives
// in the leaf package federation/rules, shared with connrules.
package federation

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Strategy names, re-exported from rules.
const (
	StrategyGoogle = rules.Google
	StrategyOAuth2 = rules.OAuth2
	StrategyOIDC   = rules.OIDC
)

// Store model aliases used throughout the package.
type (
	Attempt     = store.FederationAttempt
	Endpoints   = store.FederationEndpoints
	IdentityKey = store.FederatedIdentityKey
)

// Provider is one strategy adapter. It talks to the provider only; it never
// creates a local user or session.
type Provider interface {
	// AuthorizationURL returns the provider redirect for a started attempt.
	AuthorizationURL(in StartInput) (string, error)
	// Exchange redeems the authorization code once and returns the
	// validated profile and tokens. It never retries the token request.
	Exchange(ctx context.Context, in ExchangeInput) (ProviderResult, error)
}

// StartInput is what an adapter needs to build the authorization redirect.
type StartInput struct {
	Config        Config
	Endpoints     Endpoints
	CallbackURL   string
	State         string
	Nonce         string
	CodeChallenge string // S256 of the attempt's verifier
}

// ExchangeInput is what an adapter needs to redeem a code. ClientSecret is
// the opened credential, held only for the duration of the exchange.
type ExchangeInput struct {
	Config       Config
	Endpoints    Endpoints
	Issuer       string
	CallbackURL  string
	Code         string
	CodeVerifier string
	Nonce        string
	ClientSecret string
	Now          time.Time
}

// TokenSet is a successful token response. Values are sensitive.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	Scope        string
	ExpiresIn    int64
	// ExpiresAt is derived from ExpiresIn at exchange time; zero if unknown.
	ExpiresAt time.Time
}

// ProviderResult is a validated provider identity with its tokens.
type ProviderResult struct {
	Profile Profile
	Tokens  TokenSet
}
