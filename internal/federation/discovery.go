package federation

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/federation/script"
)

// ErrProviderResponse reports a provider answer that cannot be trusted or
// used: a failed or malformed exchange, discovery or key fetch, or an ID token
// that fails validation. Its messages never contain tokens, secrets or raw
// provider error text.
var ErrProviderResponse = errors.New("federation: unusable provider response")

// Cache limits (spec §5).
const (
	maxCacheTTL     = 5 * time.Minute
	maxCacheEntries = 256
	maxJWKSKeys     = 100
)

// Token client authentication methods.
const (
	authBasic = "client_secret_basic"
	authPost  = "client_secret_post"
)

// CacheKey scopes cached discovery and keys to one configuration of one
// connection: a configuration change (revision) never reuses them.
type CacheKey struct {
	TenantID     string
	ConnectionID string
	Revision     int64
}

func (k CacheKey) with(parts ...string) string {
	return strings.Join(append([]string{k.TenantID, k.ConnectionID, fmt.Sprint(k.Revision)}, parts...), "\x00")
}

// Metadata is validated OpenID provider discovery.
type Metadata struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	UserInfoEndpoint      string
	TokenAuthMethod       string
}

// Endpoints is the endpoint snapshot an attempt pins.
func (m Metadata) Endpoints() Endpoints {
	return Endpoints{AuthorizationURL: m.AuthorizationEndpoint, TokenURL: m.TokenEndpoint, JWKSURL: m.JWKSURI,
		UserInfoURL: m.UserInfoEndpoint, TokenAuthMethod: m.TokenAuthMethod}
}

// GoogleEndpoints are Google's fixed endpoints.
func GoogleEndpoints() Endpoints {
	return Endpoints{AuthorizationURL: rules.GoogleAuthorizationURL, TokenURL: rules.GoogleTokenURL,
		JWKSURL: rules.GoogleJWKSURL, TokenAuthMethod: authPost}
}

// Providers builds strategy adapters over one bounded HTTP client and
// process-wide discovery and key caches.
type Providers struct {
	client       *http.Client
	policy       NetworkPolicy
	now          func() time.Time
	discovery    *ttlCache[Metadata]
	keys         *keyCache
	scripts      script.Executor
	googleFix    *GoogleOverride
	microsoftFix *MicrosoftOverride
}

// GoogleOverride replaces Google's fixed endpoints and issuer for a local
// provider harness. It is set only at construction (WithGoogleFixture); no
// configuration or API reaches it.
type GoogleOverride struct {
	Endpoints Endpoints
	Issuer    string
}

// WithGoogleFixture points google-oauth2 at a local harness; tests and the
// E2E harness only.
func (ps *Providers) WithGoogleFixture(o GoogleOverride) *Providers {
	ps.googleFix = &o
	return ps
}

// google returns the Google endpoints and issuer in use.
func (ps *Providers) google() (Endpoints, string) {
	if ps.googleFix != nil {
		return ps.googleFix.Endpoints, ps.googleFix.Issuer
	}
	return GoogleEndpoints(), rules.GoogleIssuer
}

// NewProviders returns adapters whose network access follows policy. now
// defaults to time.Now.
func NewProviders(policy NetworkPolicy, now func() time.Time) *Providers {
	if now == nil {
		now = time.Now
	}
	ps := &Providers{
		policy: policy, now: now,
		client: &http.Client{Transport: NewTransport(policy), CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("%w: redirect refused", ErrNetworkPolicy)
		}},
		discovery: newTTLCache[Metadata](maxCacheEntries, maxCacheTTL, now),
	}
	ps.keys = &keyCache{ps: ps, sets: newTTLCache[*keySet](maxCacheEntries, maxCacheTTL, now), inflight: map[string]*keyFetch{}}
	return ps
}

// HTTPClient is the bounded client adapters use; the script broker shares it.
func (ps *Providers) HTTPClient() *http.Client { return ps.client }

// For returns the adapter of cfg's strategy.
func (ps *Providers) For(cfg Config) Provider {
	switch cfg.Strategy {
	case StrategyOAuth2:
		return oauth2Provider{ps}
	case StrategyWindowsLive, StrategyWAAD:
		return microsoftProvider{ps}
	case StrategyOIDC, StrategyGoogle:
		return oidcProvider{ps}
	default:
		return unsupportedProvider{}
	}
}

// Discover fetches and validates OpenID discovery. expectedIssuer, when set
// (a pinned OIDC issuer), must match exactly.
func (ps *Providers) Discover(ctx context.Context, key CacheKey, discoveryURL, expectedIssuer string) (Metadata, error) {
	ck := key.with("discovery", discoveryURL, expectedIssuer)
	if m, ok := ps.discovery.get(ck); ok {
		return m, nil
	}
	var raw map[string]any
	if err := ps.getJSON(ctx, discoveryURL, "", &raw); err != nil {
		return Metadata{}, err
	}
	m, err := ps.validateMetadata(raw, expectedIssuer)
	if err != nil {
		return Metadata{}, err
	}
	ps.discovery.put(ck, m)
	return m, nil
}

func (ps *Providers) validateMetadata(raw map[string]any, expectedIssuer string) (Metadata, error) {
	bad := func(what string) (Metadata, error) {
		return Metadata{}, fmt.Errorf("%w: discovery %s", ErrProviderResponse, what)
	}
	str := func(k string) string { s, _ := raw[k].(string); return s }
	m := Metadata{Issuer: str("issuer"), AuthorizationEndpoint: str("authorization_endpoint"),
		TokenEndpoint: str("token_endpoint"), JWKSURI: str("jwks_uri"), UserInfoEndpoint: str("userinfo_endpoint")}
	issuerURL, issuerErr := url.Parse(m.Issuer)
	if m.Issuer == "" || issuerErr != nil || strings.ContainsAny(issuerURL.Path, "{}") || ps.policy.CheckEndpoint(m.Issuer) != nil {
		return bad("issuer is missing or not https")
	}
	if expectedIssuer != "" && m.Issuer != expectedIssuer {
		return bad("issuer does not match the pinned issuer")
	}
	for _, e := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.JWKSURI} {
		if e == "" || ps.policy.CheckEndpoint(e) != nil {
			return bad("endpoint is missing or refused")
		}
	}
	if m.UserInfoEndpoint != "" && ps.policy.CheckEndpoint(m.UserInfoEndpoint) != nil {
		return bad("userinfo endpoint refused")
	}
	if list, ok := stringSlice(raw["code_challenge_methods_supported"]); ok && !slices.Contains(list, "S256") {
		return bad("does not support S256 PKCE")
	}
	if list, ok := stringSlice(raw["id_token_signing_alg_values_supported"]); ok && !slices.Contains(list, "RS256") {
		return bad("does not support RS256 ID tokens")
	}
	methods, ok := stringSlice(raw["token_endpoint_auth_methods_supported"])
	switch {
	case !ok || slices.Contains(methods, authBasic):
		m.TokenAuthMethod = authBasic
	case slices.Contains(methods, authPost):
		m.TokenAuthMethod = authPost
	default:
		return bad("supports no usable client authentication method")
	}
	return m, nil
}

func stringSlice(v any) ([]string, bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// getJSON GETs a JSON object, optionally with a bearer token.
func (ps *Providers) getJSON(ctx context.Context, url, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%w: bad URL", ErrProviderResponse)
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := ps.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProviderResponse, redact(err))
	}
	body, err := readAll(resp)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProviderResponse, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrProviderResponse, resp.StatusCode)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: malformed JSON", ErrProviderResponse)
	}
	return nil
}

// redact keeps the class of a transport error without its text (which may
// name URLs with query parameters).
func redact(err error) error {
	switch {
	case errors.Is(err, ErrNetworkPolicy):
		return ErrNetworkPolicy
	case errors.Is(err, ErrResponseTooLarge):
		return ErrResponseTooLarge
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		return context.Canceled
	}
	return errors.New("request failed")
}

// ttlCache is a small bounded map with per-entry expiry. Expired entries are
// never returned; past the bound the oldest entry is evicted.
type ttlCache[V any] struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	now   func() time.Time
	items map[string]ttlEntry[V]
	seq   uint64
}

type ttlEntry[V any] struct {
	v   V
	exp time.Time
	seq uint64
}

func newTTLCache[V any](max int, ttl time.Duration, now func() time.Time) *ttlCache[V] {
	return &ttlCache[V]{max: max, ttl: min(ttl, maxCacheTTL), now: now, items: map[string]ttlEntry[V]{}}
}

func (c *ttlCache[V]) get(k string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[k]
	if !ok || !c.now().Before(e.exp) {
		delete(c.items, k)
		var zero V
		return zero, false
	}
	return e.v, true
}

func (c *ttlCache[V]) put(k string, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	c.items[k] = ttlEntry[V]{v: v, exp: c.now().Add(c.ttl), seq: c.seq}
	for len(c.items) > c.max {
		oldest, first := "", true
		var oseq uint64
		for key, e := range c.items {
			if first || e.seq < oseq {
				oldest, oseq, first = key, e.seq, false
			}
		}
		delete(c.items, oldest)
	}
}

func (c *ttlCache[V]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// cachedSigningKey preserves the raw issuer extension without changing generic
// OIDC's key policy. go-jose intentionally drops unknown JWK fields.
type cachedSigningKey struct {
	Key    jose.JSONWebKey
	issuer json.RawMessage
}

func (k *cachedSigningKey) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &k.Key); err != nil {
		return err
	}
	var extension struct {
		Issuer json.RawMessage `json:"issuer"`
	}
	if err := json.Unmarshal(data, &extension); err != nil {
		return err
	}
	k.issuer = extension.Issuer
	return nil
}

// keySet is one fetched JWKS with the generation that fetched it.
type keySet struct {
	keys []cachedSigningKey
	gen  uint64
}

type keyFetch struct {
	done chan struct{}
	set  *keySet
	err  error
}

// keyCache caches provider signing keys and coalesces refreshes: callers
// that saw the same generation share one fetch; a failed fetch never
// replaces a valid entry.
type keyCache struct {
	ps       *Providers
	sets     *ttlCache[*keySet]
	mu       sync.Mutex
	inflight map[string]*keyFetch
	gen      uint64
}

// key returns the signing key for kid ("" when the token names none).
func (kc *keyCache) key(ctx context.Context, ck, jwksURL, kid string) (*jose.JSONWebKey, error) {
	selected, err := kc.selectKey(ctx, ck, jwksURL, func(set *keySet) (*cachedSigningKey, error) { return pickKey(set.keys, kid, nil) })
	if err != nil {
		return nil, err
	}
	return &selected.Key, nil
}

// selectKey shares one bounded cache and refresh/coalescing algorithm between
// strategies. Selection always runs again for each token, including cache hits.
func (kc *keyCache) selectKey(ctx context.Context, ck, jwksURL string, pick func(*keySet) (*cachedSigningKey, error)) (*cachedSigningKey, error) {
	set, ok := kc.sets.get(ck)
	var seen uint64
	if ok {
		if k, err := pick(set); err == nil {
			return k, nil
		} else if !errors.Is(err, errUnknownKID) {
			return nil, err
		}
		seen = set.gen
	}
	set, err := kc.refresh(ctx, ck, jwksURL, seen)
	if err != nil {
		return nil, err
	}
	return pick(set)
}

func (kc *keyCache) refresh(ctx context.Context, ck, jwksURL string, seen uint64) (*keySet, error) {
	kc.mu.Lock()
	if cur, ok := kc.sets.get(ck); ok && cur.gen != seen {
		kc.mu.Unlock()
		return cur, nil // someone refreshed since we looked
	}
	if f, ok := kc.inflight[ck]; ok {
		kc.mu.Unlock()
		select {
		case <-f.done:
			return f.set, f.err
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %w", ErrProviderResponse, ctx.Err())
		}
	}
	f := &keyFetch{done: make(chan struct{})}
	kc.inflight[ck] = f
	kc.mu.Unlock()

	var jwks struct {
		Keys []cachedSigningKey `json:"keys"`
	}
	err := kc.ps.getJSON(ctx, jwksURL, "", &jwks)
	if err == nil && (len(jwks.Keys) == 0 || len(jwks.Keys) > maxJWKSKeys) {
		err = fmt.Errorf("%w: JWKS has no keys or more than %d", ErrProviderResponse, maxJWKSKeys)
	}
	kc.mu.Lock()
	if err == nil {
		kc.gen++
		f.set = &keySet{keys: jwks.Keys, gen: kc.gen}
		kc.sets.put(ck, f.set)
	}
	f.err = err
	delete(kc.inflight, ck)
	kc.mu.Unlock()
	close(f.done)
	return f.set, f.err
}

var errUnknownKID = fmt.Errorf("%w: no signing key for the token", ErrProviderResponse)

// pickKey selects the RS256 signing key for kid. Without a kid exactly one
// candidate must exist.
func pickKey(keys []cachedSigningKey, kid string, eligible func(*cachedSigningKey) bool) (*cachedSigningKey, error) {
	var found *cachedSigningKey
	matched := false
	for i := range keys {
		entry := &keys[i]
		k := &entry.Key
		if !k.Valid() || !k.IsPublic() || (k.Use != "" && k.Use != "sig") || (k.Algorithm != "" && k.Algorithm != string(jose.RS256)) {
			continue
		}
		if _, isRSA := k.Key.(*rsa.PublicKey); !isRSA {
			continue
		}
		if kid != "" && k.KeyID != kid {
			continue
		}
		matched = true
		if eligible != nil && !eligible(entry) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: ambiguous signing key", ErrProviderResponse)
		}
		found = entry
	}
	if found != nil {
		return found, nil
	}
	if matched {
		return nil, fmt.Errorf("%w: signing key issuer mismatch", ErrProviderResponse)
	}
	return nil, errUnknownKID
}

// unsupportedProvider rejects unknown strategies before any provider I/O.
type unsupportedProvider struct{}

func (unsupportedProvider) AuthorizationURL(StartInput) (string, error) { return "", ErrInvalidConfig }
func (unsupportedProvider) Exchange(context.Context, ExchangeInput) (ProviderResult, error) {
	return ProviderResult{}, ErrInvalidConfig
}
