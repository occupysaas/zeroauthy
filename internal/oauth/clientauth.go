// internal/oauth/clientauth.go
package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/clientcred"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const authFailed = "client authentication failed"

// clientAssertionType is the only client_assertion_type accepted (RFC 7523 §2.2).
const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Bounds checked before the unverified subject is read; clientcred.Verify
// enforces them again.
const (
	maxClientAssertionBytes = 2048
	maxAssertionSubjectLen  = 64
)

// authenticateClient implements token endpoint client authentication
// (RFC 6749 §2.3). The method used must be the one the client is
// registered with. Failures share one description so responses do not
// reveal which part was wrong; the reason is logged instead.
func (h *Handlers) authenticateClient(ctx context.Context, r *http.Request, form url.Values, tenantID string) (*store.Client, *Error) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	if !hasBasic && r.Header.Get("Authorization") != "" {
		// A present but unusable Authorization header must not fall through
		// to body credentials: that would silently pick one method.
		h.log().InfoContext(ctx, "client authentication failed: malformed Authorization header", "tenant", tenantID)
		return nil, invalidClient(authFailed, true)
	}
	if form.Has("client_assertion") || form.Has("client_assertion_type") {
		if hasBasic || form.Has("client_secret") {
			return nil, invalidRequest("use only one client authentication method")
		}
		return h.authenticateAssertion(ctx, r, form, tenantID)
	}
	if hasBasic {
		// RFC 6749 §2.3.1: credentials are form-urlencoded before base64.
		id, err1 := url.QueryUnescape(basicID)
		secret, err2 := url.QueryUnescape(basicSecret)
		if err1 != nil || err2 != nil {
			return nil, invalidClient(authFailed, true)
		}
		basicID, basicSecret = id, secret
		if form.Get("client_secret") != "" {
			return nil, invalidRequest("use only one client authentication method")
		}
		if id := form.Get("client_id"); id != "" && id != basicID {
			return nil, invalidRequest("client_id does not match the HTTP Basic credentials")
		}
	}

	clientID, method, secret := form.Get("client_id"), store.AuthMethodNone, ""
	switch {
	case hasBasic:
		clientID, method, secret = basicID, store.AuthMethodClientSecretBasic, basicSecret
	case form.Get("client_secret") != "":
		method, secret = store.AuthMethodClientSecretPost, form.Get("client_secret")
	}
	if clientID == "" {
		return nil, invalidClient(authFailed, hasBasic)
	}

	c, err := h.Store.Clients().Get(ctx, tenantID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		h.log().InfoContext(ctx, "client authentication failed: unknown client", "tenant", tenantID, "client_id", clientID)
		return nil, invalidClient(authFailed, hasBasic)
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load client", "tenant", tenantID, "client_id", clientID, "err", err)
		return nil, serverError()
	}
	if c.TokenEndpointAuthMethod != method {
		h.log().InfoContext(ctx, "client authentication failed: method mismatch",
			"tenant", tenantID, "client_id", clientID, "registered", c.TokenEndpointAuthMethod, "used", method)
		return nil, invalidClient(authFailed, hasBasic)
	}
	if method == store.AuthMethodNone {
		return c, nil
	}
	valid, busy := h.secretValid(ctx, c, secret)
	if busy {
		h.log().WarnContext(ctx, "client authentication refused: too many concurrent secret verifications", "tenant", tenantID, "client_id", clientID)
		return nil, secretVerificationBusy()
	}
	if !valid {
		h.log().InfoContext(ctx, "client authentication failed: bad secret", "tenant", tenantID, "client_id", clientID)
		return nil, invalidClient(authFailed, hasBasic)
	}
	return c, nil
}

// authenticateAssertion is private_key_jwt (RFC 7523 §2.2, OIDC Core §9).
// The client is found by the assertion's unverified sub, and only the
// credentials listed in its PrivateKeyJWTCredentials are tried. Every
// failure is the shared invalid_client; the reason goes to the server log,
// never the assertion.
func (h *Handlers) authenticateAssertion(ctx context.Context, r *http.Request, form url.Values, tenantID string) (*store.Client, *Error) {
	fail := func(reason string, args ...any) (*store.Client, *Error) {
		h.log().InfoContext(ctx, "client authentication failed: "+reason, append([]any{"tenant", tenantID}, args...)...)
		return nil, invalidClient(authFailed, false)
	}
	if form.Get("client_assertion_type") != clientAssertionType {
		return fail("unsupported client_assertion_type")
	}
	raw := form.Get("client_assertion")
	if raw == "" || len(raw) > maxClientAssertionBytes {
		return fail("client_assertion missing or too long")
	}
	res, ok := tenant.FromContext(r.Context())
	if !ok || res.Tenant == nil || res.Tenant.ID != tenantID {
		return fail("no resolved tenant for the assertion audience")
	}
	if !store.ClientCredentialsAvailable(ctx, h.Store) {
		return fail("store lacks client credentials")
	}
	clientID, ok := unverifiedSubject(raw)
	if !ok {
		return fail("client_assertion is not a readable signed JWT")
	}
	if id := form.Get("client_id"); id != "" && id != clientID {
		return nil, invalidRequest("client_id does not match the client assertion")
	}
	c, err := h.Store.Clients().Get(ctx, tenantID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return fail("unknown client", "client_id", clientID)
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load client", "tenant", tenantID, "client_id", clientID, "err", err)
		return nil, serverError()
	}
	if c.TokenEndpointAuthMethod != "" || c.PrivateKeyJWTCredentials == nil {
		return fail("method mismatch", "client_id", clientID, "registered", c.TokenEndpointAuthMethod, "used", store.AuthMethodPrivateKeyJWT)
	}
	all, err := h.Store.ClientCredentials().List(ctx, tenantID, clientID)
	if err != nil {
		h.log().ErrorContext(ctx, "load client credentials", "tenant", tenantID, "client_id", clientID, "err", err)
		return nil, serverError()
	}
	// Only this client's private_key_jwt credentials: never one enabled
	// only for signed request objects.
	var creds []*store.ClientCredential
	for _, cr := range all {
		if cr.ClientID == clientID && slices.Contains(c.PrivateKeyJWTCredentials, cr.ID) {
			creds = append(creds, cr)
		}
	}
	_, err = clientcred.Verify(clientcred.VerifyInput{
		Raw: raw, ClientID: clientID, Purpose: clientcred.Assertion, Credentials: creds, Now: h.now(),
		// LR35-3: the issuer of the host that received the request, or the
		// exact URL of the endpoint.
		Audiences: []string{res.Issuer(), res.Origin() + r.URL.Path},
		UseJTI: func(jti string, exp time.Time) error {
			return h.Store.ClientCredentials().UseJTI(ctx, tenantID, clientID, jti, exp)
		},
	})
	if err != nil {
		return fail("invalid client assertion", "client_id", clientID, "used", store.AuthMethodPrivateKeyJWT, "reason", err.Error())
	}
	return c, nil
}

// unverifiedSubject reads sub from a compact JWS without verifying it; it
// only selects the client whose keys then verify the assertion.
func unverifiedSubject(raw string) (string, bool) {
	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.PS256})
	if err != nil {
		return "", false
	}
	var claims struct {
		Sub any `json:"sub"`
	}
	if json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims) != nil {
		return "", false
	}
	sub, ok := claims.Sub.(string)
	if !ok || sub == "" || len(sub) > maxAssertionSubjectLen {
		return "", false
	}
	return sub, true
}

// secretValid checks secret against the client's unexpired secrets: a sealed
// one is opened and compared in constant time, a legacy one is verified
// against its hash. A sealed secret that does not open (wrong master key,
// corrupt row) fails closed and is logged. busy reports that a legacy hash
// could not be checked because LegacySecretSlots were all taken.
func (h *Handlers) secretValid(ctx context.Context, c *store.Client, secret string) (valid, busy bool) {
	now := h.now()
	for _, s := range c.Secrets {
		if s.ExpiresAt != nil && !now.Before(*s.ExpiresAt) {
			continue
		}
		if s.Sealed != nil {
			plain, err := keys.OpenClientSecret(h.Wrapper, c.TenantID, c.ClientID, s.Sealed)
			if err != nil {
				h.log().ErrorContext(ctx, "open client secret", "tenant", c.TenantID, "client_id", c.ClientID, "err", err)
				continue
			}
			// Comparing digests keeps the time independent of the length too.
			want, got := sha256.Sum256([]byte(plain)), sha256.Sum256([]byte(secret))
			if subtle.ConstantTimeCompare(want[:], got[:]) == 1 {
				return true, false
			}
			continue
		}
		release, ok := h.LegacySecretSlots.Acquire(ctx)
		if !ok {
			busy = true
			continue
		}
		ok, err := secrets.Verify(s.Hash, secret)
		release()
		if err == nil && ok {
			return true, false
		}
	}
	return false, busy
}

// secretVerificationBusy is Auth0's throttling error:
// https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy/custom-rate-limit-policies
func secretVerificationBusy() *Error {
	return &Error{Status: http.StatusTooManyRequests, Code: "too_many_requests", Description: "Rate limit exceeded."}
}
