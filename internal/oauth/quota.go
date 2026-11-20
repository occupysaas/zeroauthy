package oauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/quotarules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type quotaResponseKey struct{}
type quotaResponse struct{ headers http.Header }

func (q *quotaResponse) apply(w http.ResponseWriter) {
	for k, values := range q.headers {
		w.Header()[k] = slices.Clone(values)
	}
}
func quotaSubjects(c *store.Client, org *store.Organization, tn *store.Tenant) []store.QuotaSubject {
	var client, organization *store.TokenQuota
	if tn.DefaultTokenQuota != nil {
		client = tn.DefaultTokenQuota.Clients
		organization = tn.DefaultTokenQuota.Organizations
	}
	if c.TokenQuota != nil {
		client = c.TokenQuota
	}
	if org != nil && org.TokenQuota != nil {
		organization = org.TokenQuota
	}
	var out []store.QuotaSubject
	if client != nil {
		out = append(out, store.QuotaSubject{Kind: "client", ID: c.ClientID, Quota: *client})
	}
	if org != nil && organization != nil {
		out = append(out, store.QuotaSubject{Kind: "organization", ID: org.ID, Quota: *organization})
	}
	return out
}
func quotaHeader(states []store.QuotaState, kind string, now time.Time) string {
	var parts []string
	for _, s := range states {
		if s.Subject.Kind != kind {
			continue
		}
		for _, b := range s.Buckets {
			parts = append(parts, fmt.Sprintf("b=%s;q=%d;r=%d;t=%d", b.Name, b.Limit, b.Remaining, quotaSeconds(b.Reset, now)))
		}
	}
	return strings.Join(parts, ",")
}
func quotaSeconds(reset, now time.Time) int64 {
	return max(0, int64((reset.Sub(now)+time.Second-1)/time.Second))
}
func publishQuota(ctx context.Context, states []store.QuotaState, now time.Time) {
	q, _ := ctx.Value(quotaResponseKey{}).(*quotaResponse)
	if q == nil {
		return
	}
	q.headers = make(http.Header)
	for _, kind := range []string{"client", "organization"} {
		if value := quotaHeader(states, kind, now); value != "" {
			name := "Auth0-Client-Quota-Limit"
			if kind == "organization" {
				name = "Auth0-Organization-Quota-Limit"
			}
			q.headers.Set(name, value)
		}
	}
	var exhausted *store.QuotaBucket
	for _, s := range states {
		if !s.Exceeded {
			continue
		}
		for _, b := range s.Buckets {
			if b.Remaining == 0 && (exhausted == nil || b.Reset.Before(exhausted.Reset)) {
				copy := b
				exhausted = &copy
			}
		}
	}
	if exhausted != nil {
		q.headers.Set("X-RateLimit-Limit", strconv.Itoa(exhausted.Limit))
		q.headers.Set("X-RateLimit-Remaining", "0")
		q.headers.Set("X-RateLimit-Reset", strconv.FormatInt(exhausted.Reset.Unix(), 10))
		q.headers.Set("Retry-After", strconv.FormatInt(quotaSeconds(exhausted.Reset, now), 10))
	}
}

var errCredentialPolicy = errors.New("client credentials policy changed before issuance")

// finishClientCredentials is the response commit boundary. Signing deliberately
// precedes it: failed signing cannot consume quota, and the key manager must not
// use the outer store while a memory/SQLite transaction holds it exclusively.
func (h *Handlers) finishClientCredentials(ctx context.Context, res tenant.Resolved, c *store.Client, rs *store.ResourceServer, grantID, orgID string, scopes []string, jkt string, lifetime time.Duration) *Error {
	var states []store.QuotaState
	var now time.Time
	var refused string
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		current, err := tx.Clients().Get(ctx, res.Tenant.ID, c.ClientID)
		if err != nil {
			return err
		}
		api, err := tx.ResourceServers().GetByIdentifier(ctx, res.Tenant.ID, rs.Identifier)
		if err != nil {
			return err
		}
		grant, err := tx.ClientGrants().Find(ctx, res.Tenant.ID, c.ClientID, rs.Identifier, store.SubjectTypeClient)
		if err != nil {
			return err
		}
		if grant.ID != grantID || current.TokenEndpointAuthMethod == store.AuthMethodNone || !slices.Contains(current.GrantTypes, "client_credentials") {
			return errCredentialPolicy
		}
		if d := access.Decide(access.Input{Flow: access.ClientCredentials, Client: current, API: api, ClientGrant: grant}); d.Err != nil {
			return errCredentialPolicy
		}
		if err = orglogin.CheckMachineGrant(ctx, tx, res.Tenant.ID, grant, orgID); err != nil {
			return err
		}
		allowed := grant.EffectiveScopes(api.Scopes)
		for _, s := range scopes {
			if !slices.Contains(allowed, s) || !slices.ContainsFunc(api.Scopes, func(v store.Scope) bool { return v.Value == s }) {
				return errCredentialPolicy
			}
		}
		currentLifetime := time.Duration(api.TokenLifetime) * time.Second
		if currentLifetime <= 0 {
			currentLifetime = DefaultAccessTokenLifetime
		}
		if api.ID != rs.ID || api.SigningAlg != rs.SigningAlg || api.TokenDialect != rs.TokenDialect || !bytes.Equal(api.SigningSecretSealed, rs.SigningSecretSealed) || currentLifetime != lifetime {
			return errCredentialPolicy
		}
		proof, failure := accessProof(ctx, current, api)
		if failure != nil {
			return failure
		}
		if proof != jkt {
			return errCredentialPolicy
		}
		tn, err := tx.Tenants().Get(ctx, res.Tenant.ID)
		if err != nil {
			return err
		}
		var org *store.Organization
		if orgID != "" {
			org, err = tx.Organizations().Get(ctx, res.Tenant.ID, orgID)
			if err != nil {
				return err
			}
		}
		defaults, err := quotarules.DefaultsOf(tn)
		if err != nil {
			return err
		}
		tn.DefaultTokenQuota = defaults
		subjects := quotaSubjects(current, org, tn)
		if len(subjects) == 0 {
			return nil
		}
		if err = store.CheckRefreshTokensIISupport(ctx, tx); err != nil {
			return err
		}
		now = h.now().UTC()
		states, err = tx.TokenQuotas().Consume(ctx, res.Tenant.ID, subjects, now)
		if err != nil {
			return err
		}
		for _, s := range states {
			if s.Exceeded && refused == "" {
				refused = "Client quota exceeded"
				if s.Subject.Kind == "organization" {
					refused = "Organization quota exceeded"
				}
			}
		}
		return nil
	})
	var oauthErr *Error
	if errors.As(err, &oauthErr) {
		return oauthErr
	}
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, orglogin.ErrNotMember) || errors.Is(err, errCredentialPolicy) {
		return accessDenied("the client grant is no longer eligible")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "commit client credentials", "tenant", res.Tenant.ID, "err", err)
		return serverError()
	}
	publishQuota(ctx, states, now)
	if refused != "" {
		return &Error{Status: 429, Code: "too_many_requests", Description: refused}
	}
	for _, s := range states {
		for _, b := range s.Buckets {
			for _, pct := range b.CrossedThresholds {
				e := logs.Event{TenantID: res.Tenant.ID, Type: "token_quota_consumption_warning", ClientID: c.ClientID, Date: now, Description: fmt.Sprintf("%s token quota reached %d%% for %s", s.Subject.Kind, pct, b.Name)}
				if s.Subject.Kind == "organization" {
					e.OrganizationID = s.Subject.ID
				}
				logs.RecordEvent(ctx, h.Recorder, e)
			}
		}
	}
	return nil
}
