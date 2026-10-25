package mgmt

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

// Kind is the kind of Management API caller.
type Kind int

const (
	// M2M is a machine-to-machine client of the tenant, with a client
	// credentials token for the tenant's Management API identifier.
	M2M Kind = iota + 1
	// Operator is a console operator, with a system-tenant token for
	// tenant.OperatorAudience. Operators hold every scope.
	Operator
)

// Caller is the authenticated caller of a Management API request.
type Caller struct {
	Kind Kind
	// ClientID is the token's azp: the M2M client, or the operator's
	// console client.
	ClientID string
	// UserID is the operator's user ID in the system tenant; empty for M2M.
	UserID string
	// Scopes are the token's scopes (M2M), or every Management API scope
	// (Operator).
	Scopes []string
	// Tenants are the tenants an operator manages ("*" for all); empty
	// for M2M.
	Tenants []string
}

// Has reports whether the caller holds scope.
func (c Caller) Has(scope string) bool {
	return c.Kind == Operator || slices.Contains(c.Scopes, scope)
}

type callerKey struct{}

// CallerFrom returns the caller stored by Auth.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	return c, ok
}

// WithCaller returns ctx carrying c (for tests of handlers behind Auth).
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// Config is what Auth needs.
type Config struct {
	Store store.Store
	Keys  *keys.Manager
	// BaseDomain is server.base_domain, which names each tenant's
	// Management API identifier and hosts.
	BaseDomain string
	// SystemHost is the system tenant's canonical host
	// (tenant.SystemHost): operator tokens must be issued exactly by
	// https://<SystemHost>/.
	SystemHost string
	Now        func() time.Time
	Log        *slog.Logger
}

// leeway is the clock skew allowed on exp, nbf and iat.
const leeway = time.Minute

// Auth authenticates a bearer token and stores the Caller in the request
// context. It must run after tenant resolution. It accepts:
//   - a client credentials token of the resolved tenant: signed with its
//     keys, issued under one of its hosts, for its Management API
//     identifier (whichever host received the request);
//   - an operator token: signed with the system tenant's keys, issued by
//     exactly https://<SystemHost>/, for tenant.OperatorAudience, with the
//     tenant.OperatorClaim, from a user who is still an operator of the
//     resolved tenant.
//
// Anything else is 401 (403 for an operator outside its tenants).
func Auth(cfg Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res, ok := tenant.FromContext(r.Context())
			if !ok {
				WriteError(w, http.StatusInternalServerError, "internal_error", "Internal error")
				return
			}
			authRes, err := cfg.operatorTarget(r.Context(), r, res)
			if err != nil {
				Fail(w, err)
				return
			}
			c, err := cfg.authenticate(r, authRes)
			if err != nil {
				Fail(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), c)))
		})
	}
}

// operatorTarget binds the two system email extension routes to the path
// tenant for both token and persisted operator grant checks. The request's
// resolved system tenant remains in context for system-host routing.
func (cfg Config) operatorTarget(ctx context.Context, r *http.Request, base tenant.Resolved) (tenant.Resolved, error) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "api" || parts[1] != "system" || parts[2] != "tenants" || parts[4] != "emails" || (parts[5] != "preview" && parts[5] != "test") {
		return base, nil
	}
	t, err := cfg.Store.Tenants().GetByName(ctx, parts[3])
	if errors.Is(err, store.ErrNotFound) {
		return tenant.Resolved{}, &Error{Status: http.StatusNotFound, Code: "inexistent_tenant", Message: "The tenant does not exist"}
	}
	if err != nil {
		cfg.log().ErrorContext(ctx, "management API: load target tenant", "err", err)
		return tenant.Resolved{}, &Error{Status: http.StatusInternalServerError, Code: "internal_error", Message: "Internal error"}
	}
	return tenant.Resolved{Tenant: t, Host: base.Host}, nil
}

func invalidToken(message string) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: "invalid_token", Message: message}
}

// tokenClaims are the claims Auth reads beyond the registered ones.
type tokenClaims struct {
	Scope     string    `json:"scope"`
	AZP       string    `json:"azp"`
	GrantType string    `json:"gty"`
	Operator  *[]string `json:"https://zeroauthy.dev/operator"`
}

func (cfg Config) now() time.Time {
	if cfg.Now != nil {
		return cfg.Now()
	}
	return time.Now()
}

func (cfg Config) log() *slog.Logger {
	if cfg.Log != nil {
		return cfg.Log
	}
	return slog.Default()
}

func (cfg Config) authenticate(r *http.Request, res tenant.Resolved) (Caller, error) {
	scheme, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if r.Header.Get("Authorization") == "" {
		return Caller{}, invalidToken("Missing authentication")
	}
	raw = strings.TrimSpace(raw)
	if !ok || !strings.EqualFold(scheme, "Bearer") || raw == "" {
		return Caller{}, invalidToken("Bad authentication: a Bearer token is required")
	}
	// The audience picks the trust anchor; the signature, checked next
	// with that anchor's keys only, decides.
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return Caller{}, invalidToken("Invalid token")
	}
	var peek jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&peek); err != nil {
		return Caller{}, invalidToken("Invalid token")
	}
	if peek.Audience.Contains(tenant.OperatorAudience) {
		return cfg.operator(r.Context(), res, raw)
	}
	return cfg.m2m(r.Context(), res, raw)
}

// verify checks raw's signature with tenantID's keys, its time claims (exp
// required), its audience, and that its issuer is one of issuers.
func (cfg Config) verify(ctx context.Context, tenantID, raw, aud string, issuers []string) (jwt.Claims, tokenClaims, error) {
	var std jwt.Claims
	var extra tokenClaims
	if err := cfg.Keys.Verify(ctx, tenantID, raw, &std, &extra); err != nil {
		if errors.Is(err, keys.ErrInvalidToken) {
			return std, extra, invalidToken("Invalid token")
		}
		cfg.log().ErrorContext(ctx, "management API: load keys", "tenant", tenantID, "err", err)
		return std, extra, &Error{Status: http.StatusInternalServerError, Code: "internal_error", Message: "Internal error"}
	}
	if std.Expiry == nil {
		return std, extra, invalidToken("Invalid token: no expiry")
	}
	if err := std.ValidateWithLeeway(jwt.Expected{AnyAudience: jwt.Audience{aud}, Time: cfg.now()}, leeway); err != nil {
		switch {
		case errors.Is(err, jwt.ErrExpired):
			return std, extra, invalidToken("Expired token")
		case errors.Is(err, jwt.ErrInvalidAudience):
			return std, extra, invalidToken("Invalid token: wrong audience")
		}
		return std, extra, invalidToken("Invalid token")
	}
	if !slices.Contains(issuers, std.Issuer) {
		return std, extra, invalidToken("Invalid token: wrong issuer")
	}
	return std, extra, nil
}

func (cfg Config) m2m(ctx context.Context, res tenant.Resolved, raw string) (Caller, error) {
	aud := tenant.ManagementAPIIdentifier(res.Tenant, cfg.BaseDomain)
	if aud == "" {
		return Caller{}, invalidToken("Invalid token: the tenant has no Management API")
	}
	std, extra, err := cfg.verify(ctx, res.Tenant.ID, raw, aud, tenant.Issuers(res.Tenant, cfg.BaseDomain))
	if err != nil {
		return Caller{}, err
	}
	// Only client credentials tokens; tenant users do not manage tenants.
	if extra.GrantType != "client-credentials" || extra.AZP == "" || std.Subject != extra.AZP+"@clients" {
		return Caller{}, invalidToken("Invalid token: only client credentials tokens are accepted")
	}
	// Only operators manage the system tenant (it defines no M2M
	// Management API; this guards against one appearing anyway).
	if res.Tenant.Reserved {
		return Caller{}, &Error{Status: http.StatusForbidden, Code: "insufficient_scope", Message: "Only console operators may manage the system tenant"}
	}
	return Caller{Kind: M2M, ClientID: extra.AZP, Scopes: strings.Fields(extra.Scope)}, nil
}

func (cfg Config) operator(ctx context.Context, res tenant.Resolved, raw string) (Caller, error) {
	sys, err := cfg.Store.Tenants().GetByName(ctx, tenant.SystemName)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !sys.Reserved) || cfg.SystemHost == "" {
		return Caller{}, invalidToken("Invalid token")
	}
	if err != nil {
		cfg.log().ErrorContext(ctx, "management API: load system tenant", "err", err)
		return Caller{}, &Error{Status: http.StatusInternalServerError, Code: "internal_error", Message: "Internal error"}
	}
	// Only the canonical system host's issuer: the system tenant may also
	// answer on system.<base_domain>, which does not count.
	iss := "https://" + tenant.NormalizeHost(cfg.SystemHost) + "/"
	std, extra, err := cfg.verify(ctx, sys.ID, raw, tenant.OperatorAudience, []string{iss})
	if err != nil {
		return Caller{}, err
	}
	if extra.Operator == nil || std.Subject == "" {
		return Caller{}, invalidToken("Invalid token: not an operator token")
	}
	// Operator tokens are bound to the console client.
	if extra.AZP != system.ConsoleClientID {
		return Caller{}, invalidToken("Invalid token: operator tokens are issued to the console only")
	}
	op, err := cfg.Store.Operators().Get(ctx, sys.ID, std.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return Caller{}, invalidToken("Invalid token: the user is no longer an operator")
	}
	if err != nil {
		cfg.log().ErrorContext(ctx, "management API: load operator", "err", err)
		return Caller{}, &Error{Status: http.StatusInternalServerError, Code: "internal_error", Message: "Internal error"}
	}
	// Both the token and the stored operator must allow the tenant.
	if !manages(*extra.Operator, res.Tenant.Name) || !manages(op.Tenants, res.Tenant.Name) {
		return Caller{}, &Error{Status: http.StatusForbidden, Code: "insufficient_scope", Message: "The operator does not manage this tenant"}
	}
	scopes := make([]string, len(tenantsetup.ManagementAPIScopes))
	for i, s := range tenantsetup.ManagementAPIScopes {
		scopes[i] = s.Value
	}
	return Caller{Kind: Operator, ClientID: extra.AZP, UserID: std.Subject, Scopes: scopes, Tenants: slices.Clone(op.Tenants)}, nil
}

func manages(tenants []string, name string) bool {
	return slices.Contains(tenants, store.OperatorAllTenants) || slices.Contains(tenants, name)
}

// Require refuses, with 403 insufficient_scope, a caller holding none of
// scopes. Operators hold every scope.
func Require(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := CallerFrom(r.Context())
			if !ok {
				WriteError(w, http.StatusUnauthorized, "invalid_token", "Missing authentication")
				return
			}
			if !slices.ContainsFunc(scopes, c.Has) {
				WriteError(w, http.StatusForbidden, "insufficient_scope", "Insufficient scope, expected any of: "+strings.Join(scopes, ","))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOperator refuses every caller but an operator (the system API).
func RequireOperator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := CallerFrom(r.Context())
		if !ok {
			WriteError(w, http.StatusUnauthorized, "invalid_token", "Missing authentication")
			return
		}
		if c.Kind != Operator {
			WriteError(w, http.StatusForbidden, "insufficient_scope", "Only console operators may call this API")
			return
		}
		next.ServeHTTP(w, r)
	})
}
