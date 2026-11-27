package federation

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation/oauth1sig"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/federation/script"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// maxOAuth1Response bounds a request-token or access-token response.
const maxOAuth1Response = 16 << 10

// maxOAuth1ContextFields bounds the access-token response fields passed to a
// profile script.
const maxOAuth1ContextFields = 16

// oauth1Endpoints are the OAuth 1.0a endpoints of cfg with the fixture
// rewrite applied. The request-token URL is used only at Begin; the sealed
// attempt keeps the authorization and access-token URLs.
func (ps *Providers) oauth1Endpoints(cfg Config) (requestToken string, e Endpoints) {
	o := cfg.OAuth1
	e = Endpoints{AuthorizationURL: ps.socialURL(cfg.Strategy, o.UserAuthorizationURL), TokenURL: ps.socialURL(cfg.Strategy, o.AccessTokenURL)}
	return ps.socialURL(cfg.Strategy, o.RequestTokenURL), e
}

// oauth1Credentials builds the signing credentials from the opened secret.
func oauth1Credentials(cfg Config, secret, token, tokenSecret string) (oauth1sig.Credentials, error) {
	c := oauth1sig.Credentials{ConsumerKey: cfg.ClientID, Token: token, TokenSecret: tokenSecret}
	if cfg.OAuth1.SignatureMethod == oauth1sig.RSASHA1 {
		key, err := oauth1sig.ParsePrivateKey(secret)
		if err != nil {
			return oauth1sig.Credentials{}, ErrConnectionUnusable
		}
		c.RSAKey = key
	} else {
		c.ConsumerSecret = secret
	}
	return c, nil
}

// oauth1Post sends one signed POST with an empty body and returns the
// form-encoded answer. It never retries; errors carry no token or body.
func (ps *Providers) oauth1Post(ctx context.Context, rawURL string, c oauth1sig.Credentials, extra map[string]string) (url.Values, error) {
	h, err := oauth1sig.Header(c, http.MethodPost, rawURL, nil, extra, oauth1sig.Nonce(), strconv.FormatInt(ps.now().Unix(), 10))
	if err != nil {
		return nil, fmt.Errorf("%w: oauth1 signing", ErrInvalidConfig)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: oauth1 endpoint", ErrInvalidConfig)
	}
	req.Header.Set("Authorization", h)
	req.Header.Set("Accept", "application/x-www-form-urlencoded, application/json;q=0.5")
	resp, err := ps.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: oauth1 request: %w", ErrProviderResponse, redact(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOAuth1Response+1))
	if err != nil || len(body) > maxOAuth1Response {
		return nil, fmt.Errorf("%w: oauth1 response unreadable or too large", ErrProviderResponse)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: oauth1 endpoint status %d", ErrProviderResponse, resp.StatusCode)
	}
	v, err := url.ParseQuery(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, fmt.Errorf("%w: oauth1 response is not form-encoded", ErrProviderResponse)
	}
	for _, vs := range v {
		if len(vs) != 1 {
			return nil, fmt.Errorf("%w: oauth1 response repeats a parameter", ErrProviderResponse)
		}
	}
	return v, nil
}

// oauth1RequestToken obtains temporary credentials for callback. The
// provider must confirm the callback (OAuth 1.0a).
func (ps *Providers) oauth1RequestToken(ctx context.Context, cfg Config, rawURL, secret, callback string) (token, tokenSecret string, err error) {
	c, err := oauth1Credentials(cfg, secret, "", "")
	if err != nil {
		return "", "", err
	}
	v, err := ps.oauth1Post(ctx, rawURL, c, map[string]string{"oauth_callback": callback})
	if err != nil {
		return "", "", err
	}
	token, tokenSecret = v.Get("oauth_token"), v.Get("oauth_token_secret")
	if token == "" || tokenSecret == "" || v.Get("oauth_callback_confirmed") != "true" || len(token) > maxTokenBytes || len(tokenSecret) > maxTokenBytes {
		return "", "", fmt.Errorf("%w: oauth1 request-token response is incomplete or unconfirmed", ErrProviderResponse)
	}
	return token, tokenSecret, nil
}

// oauth1AuthorizeURL appends the request token to the authorization URL,
// keeping its configured query.
func oauth1AuthorizeURL(raw, token string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return "", fmt.Errorf("%w: oauth1 authorization endpoint", ErrInvalidConfig)
	}
	q := u.Query()
	q.Set("oauth_token", token)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// checkOAuth1Callback binds an OAuth 1.0a callback to its sealed attempt: the
// callback's oauth_token must equal the sealed request token (LR39b-9).
func checkOAuth1Callback(cfg Config, p CallbackParams, pr proof) error {
	if (cfg.OAuth1 != nil) != p.OAuth1 {
		return ErrCallbackRejected
	}
	if cfg.OAuth1 == nil {
		return nil
	}
	if pr.OAuth1Token == "" || pr.OAuth1Secret == "" || subtle.ConstantTimeCompare([]byte(pr.OAuth1Token), []byte(p.State)) != 1 {
		return ErrCallbackRejected
	}
	return nil
}

// oauth1Provider redeems the verifier for token credentials, then maps the
// profile: Twitter's verify_credentials, or the connection's script.
type oauth1Provider struct{ ps *Providers }

func (oauth1Provider) AuthorizationURL(StartInput) (string, error) {
	return "", errors.New("federation: oauth1 authorization starts with a request token")
}

func (p oauth1Provider) Exchange(ctx context.Context, in ExchangeInput) (ProviderResult, error) {
	cfg := in.Config
	twitter := cfg.Strategy == rules.Twitter
	if !twitter && p.ps.scripts == nil {
		return ProviderResult{}, ErrScriptUnavailable
	}
	if in.Code == "" || in.OAuth1Token == "" || in.OAuth1Secret == "" {
		return ProviderResult{}, ErrCallbackRejected
	}
	c, err := oauth1Credentials(cfg, in.ClientSecret, in.OAuth1Token, in.OAuth1Secret)
	if err != nil {
		return ProviderResult{}, err
	}
	v, err := p.ps.oauth1Post(ctx, in.Endpoints.TokenURL, c, map[string]string{"oauth_verifier": in.Code})
	if err != nil {
		return ProviderResult{}, err
	}
	token, secret := v.Get("oauth_token"), v.Get("oauth_token_secret")
	if token == "" || secret == "" || len(token) > maxTokenBytes || len(secret) > maxTokenBytes {
		return ProviderResult{}, fmt.Errorf("%w: oauth1 access-token response is incomplete", ErrProviderResponse)
	}
	tokens := TokenSet{AccessToken: token, TokenSecret: secret, TokenType: "oauth1"}
	c.Token, c.TokenSecret = token, secret
	if twitter {
		profile, err := p.ps.twitterOAuth1Profile(ctx, in, c)
		if err != nil {
			return ProviderResult{}, err
		}
		return ProviderResult{Profile: profile, Tokens: tokens}, nil
	}
	sctx := map[string]any{}
	for k, vs := range v {
		if k == "oauth_token" || k == "oauth_token_secret" || len(sctx) >= maxOAuth1ContextFields || len(k) > 64 || len(vs[0]) > 1024 {
			continue
		}
		sctx[k] = vs[0]
	}
	raw, err := p.ps.scripts.Execute(ctx, script.Request{TenantID: in.Cache.TenantID, ConnectionID: in.Cache.ConnectionID, Source: cfg.Script,
		AccessToken: token, TokenSecret: secret, OAuth1: &c, Context: sctx})
	switch {
	case errors.Is(err, script.ErrUnavailable):
		return ProviderResult{}, fmt.Errorf("%w: %w", ErrScriptUnavailable, err)
	case err != nil:
		return ProviderResult{}, fmt.Errorf("%w: %w", ErrProviderResponse, err)
	}
	profile, err := NormalizeProfile(raw)
	if err != nil {
		return ProviderResult{}, err
	}
	return ProviderResult{Profile: profile, Tokens: tokens}, nil
}

// parseOAuth1Callback reads an OAuth 1.0a callback: oauth_token with
// oauth_verifier, or denied=<request token>. Neither may be mixed with the
// OAuth 2.0 parameters.
func parseOAuth1Callback(q url.Values, p CallbackParams) (CallbackParams, error) {
	if p.State != "" || p.Code != "" || p.Error != "" || p.IDToken != "" {
		return CallbackParams{}, ErrCallbackRejected
	}
	if d := q.Get("denied"); d != "" {
		if q.Has("oauth_token") || q.Has("oauth_verifier") {
			return CallbackParams{}, ErrCallbackRejected
		}
		return CallbackParams{State: d, Error: "access_denied", OAuth1: true}, nil
	}
	token, verifier := q.Get("oauth_token"), q.Get("oauth_verifier")
	if token == "" || verifier == "" {
		return CallbackParams{}, ErrCallbackRejected
	}
	return CallbackParams{State: token, Code: verifier, OAuth1: true}, nil
}

// beginOAuth1 starts an OAuth 1.0a login: it obtains a request token for the
// callback, keys the attempt by that token (the callback's oauth_token plays
// the role of state) and seals the token secret in the attempt proof.
func (s *FlowService) beginOAuth1(ctx context.Context, in BeginInput, conn *store.Connection, cfg Config, key CacheKey) (*Begun, error) {
	creds, err := OpenCredentials(s.Wrapper, conn.TenantID, conn.ID, conn.FederationSecretsSealed)
	if err != nil {
		return nil, ErrConnectionUnusable
	}
	requestURL, endpoints := s.Providers.oauth1Endpoints(cfg)
	callback := strings.TrimSuffix(in.Origin, "/") + CallbackPath
	token, secret, err := s.Providers.oauth1RequestToken(ctx, cfg, requestURL, creds.ClientSecret, callback)
	if err != nil {
		return nil, err
	}
	stateHash := StateHash(token)
	sealed, err := s.sealProof(conn.TenantID, stateHash, proof{Verifier: randomToken(), Nonce: randomToken(), Endpoints: &endpoints, OAuth1Token: token, OAuth1Secret: secret})
	if err != nil {
		return nil, err
	}
	epoch, err := s.Store.Federation().IdentityEpoch(ctx, conn.TenantID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	expires := now.Add(attemptTTL)
	if in.Txn.ExpiresAt.Before(expires) {
		expires = in.Txn.ExpiresAt
	}
	cookie := randomToken()
	a := &store.FederationAttempt{
		StateHash: stateHash, TenantID: conn.TenantID, TransactionID: in.Txn.ID, ConnectionID: conn.ID,
		Revision: key.Revision, IdentityEpoch: epoch, CookieHash: CookieHash(cookie), Origin: in.Origin,
		CallbackURL: callback, Endpoints: endpoints, SealedProof: sealed, ExpiresAt: expires,
		Status: store.AttemptPending, CreatedAt: now,
	}
	if err := s.Store.Federation().CreateAttempt(ctx, a); err != nil {
		return nil, err
	}
	u, err := oauth1AuthorizeURL(endpoints.AuthorizationURL, token)
	if err != nil {
		return nil, err
	}
	return &Begun{URL: u, CookieName: AttemptCookiePrefix + stateHash[:16], CookieValue: cookie, ExpiresAt: expires}, nil
}

// twitterOAuth1Profile reads verify_credentials (Task 4).
func (ps *Providers) twitterOAuth1Profile(ctx context.Context, in ExchangeInput, c oauth1sig.Credentials) (Profile, error) {
	return Profile{}, fmt.Errorf("%w: twitter oauth1 is not wired yet", ErrConnectionUnusable)
}
