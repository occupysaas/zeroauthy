package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/dpop"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func accessProof(ctx context.Context, c *store.Client, rs *store.ResourceServer) (string, *Error) {
	p := dpop.FromContext(ctx)
	has := p != nil && p.JKT != ""
	public := c.TokenEndpointAuthMethod == store.AuthMethodNone
	allowed := rs == nil
	required := c.RequireProofOfPossession
	if rs != nil && rs.ProofOfPossession != nil {
		policy := rs.ProofOfPossession
		allowed = policy.Mechanism == "dpop"
		required = required || (policy.Required && (policy.RequiredFor != "public_clients" || public))
	}
	if required && (!has || !allowed) {
		return "", &Error{Status: 400, Code: "invalid_dpop_proof", Description: "a proof is required for this request"}
	}
	// These server resources intentionally remain Bearer-only.
	if rs != nil && (rs.IsSystem || rs.Identifier == tenant.OperatorAudience) {
		if required {
			return "", invalidRequest("sender constraints are unavailable for this audience")
		}
		return "", nil
	}
	if has && allowed {
		return p.JKT, nil
	}
	return "", nil
}
func (h *Handlers) verifyDPoP(w http.ResponseWriter, r *http.Request, res tenant.Resolved, c *store.Client, form url.Values) *Error {
	*r = *r.WithContext(context.WithValue(r.Context(), proofMintKey{}, &proofMint{}))
	expected := ""
	online := false
	aud := form.Get("audience")
	grant := form.Get("grant_type")
	switch grant {
	case "authorization_code":
		ac, e := h.Store.AuthCodes().Get(r.Context(), res.Tenant.ID, secrets.HashToken(form.Get("code")))
		if e == nil && ac.ClientID == c.ClientID && res.CheckOrigin(ac.Origin) == nil {
			expected = ac.DPoPJKT
			online = slices.Contains(ac.Scopes, "online_access")
			if online {
				rs, lookup := h.Store.ResourceServers().GetByIdentifier(r.Context(), res.Tenant.ID, ac.Audience)
				if lookup != nil && !errors.Is(lookup, store.ErrNotFound) {
					return serverError()
				}
				sess, lookup := onlineSession(r.Context(), h.Store, res, ac.UserID, ac.SessionID, h.now().UTC())
				if lookup != nil && !errors.Is(lookup, errOnlineSession) {
					return serverError()
				}
				online = onlineEligible(c, rs, sess)
			}
			aud = ac.Audience
		} else if e != nil && !errors.Is(e, store.ErrNotFound) {
			return serverError()
		}
	case GrantDeviceCode:
		// Device exchange uses its stored approval, never an exchange-supplied
		// audience. Check that API before Poll can consume an approved code.
		dc, e := h.Store.DeviceCodes().Get(r.Context(), res.Tenant.ID, secrets.HashToken(form.Get("device_code")))
		if e == nil && dc.ClientID == c.ClientID && res.CheckOrigin(dc.Origin) == nil {
			aud = dc.Audience
		} else if e != nil && !errors.Is(e, store.ErrNotFound) {
			return serverError()
		}
	case "refresh_token":
		rt, e := h.Store.RefreshTokens().GetByTokenHash(r.Context(), res.Tenant.ID, secrets.HashToken(form.Get("refresh_token")))
		if e == nil && rt.ClientID == c.ClientID && res.CheckOrigin(rt.Origin) == nil {
			expected = rt.DPoPJKT
			online = rt.Access == "online"
			if aud == "" {
				aud = rt.Audience
			}
		} else if e != nil && !errors.Is(e, store.ErrNotFound) {
			return serverError()
		}
	default:
		if aud == "" {
			aud = res.Tenant.DefaultAudience
		}
	}
	supplied := len(r.Header.Values("DPoP")) > 0
	if supplied {
		service := h.DPoP
		if service == nil {
			service = &dpop.Service{Store: h.Store, Wrapper: h.Wrapper, Now: h.Now}
		}
		p, e := service.Verify(r.Context(), r, res, dpop.AuthorizationServer, c.TokenEndpointAuthMethod == store.AuthMethodNone, "", expected)
		if e != nil {
			if e.Nonce != "" {
				w.Header().Set("DPoP-Nonce", e.Nonce)
			}
			if e.Internal {
				return serverError()
			}
			return &Error{Status: 400, Code: e.Code, Description: "the proof could not be accepted"}
		}
		if p.Nonce != "" {
			w.Header().Set("DPoP-Nonce", p.Nonce)
		}
		ctx := dpop.WithProof(r.Context(), &dpop.Proof{JKT: p.JKT})
		for _, v := range r.Header.Values("DPoP") {
			ctx = logscrub.WithCredentials(ctx, v)
		}
		*r = *r.WithContext(ctx)
	} else if expected != "" || c.RequireProofOfPossession || (online && c.TokenEndpointAuthMethod == store.AuthMethodNone) {
		return &Error{Status: 400, Code: "invalid_dpop_proof", Description: "a proof is required for this request"}
	}
	// Bound source validation precedes consumption even when no proof was supplied.
	if aud != "" {
		rs, e := h.Store.ResourceServers().GetByIdentifier(r.Context(), res.Tenant.ID, aud)
		if e == nil {
			_, failure := accessProof(r.Context(), c, rs)
			return failure
		}
		if !errors.Is(e, store.ErrNotFound) {
			return serverError()
		}
	}
	return nil
}
func refreshProof(ctx context.Context, res tenant.Resolved, rs *store.ResourceServer) string {
	p := dpop.FromContext(ctx)
	if p == nil {
		return ""
	}
	strict := false
	if v, ok := res.Tenant.SettingsExtra["dpop_strict_refresh_token_binding"].(bool); ok {
		strict = v
	}
	if strict || rs == nil || (rs.ProofOfPossession != nil && rs.ProofOfPossession.Mechanism == "dpop") {
		return p.JKT
	}
	return ""
}

// proofMint records the exact access binding signed before the final policy lock.
// It is request-local and never contains a proof or credential.
type proofMint struct {
	clientID, audience, jkt string
}
type proofMintKey struct{}

func recordProofMint(ctx context.Context, c *store.Client, rs *store.ResourceServer, jkt string) {
	p, _ := ctx.Value(proofMintKey{}).(*proofMint)
	if p == nil {
		return
	}
	p.clientID, p.jkt = c.ClientID, jkt
	p.audience = ""
	if rs != nil {
		p.audience = rs.Identifier
	}
}
func checkProofMint(ctx context.Context, tx store.Store, tid string) error {
	p, _ := ctx.Value(proofMintKey{}).(*proofMint)
	if p == nil || p.clientID == "" {
		return nil
	}
	c, e := tx.Clients().Get(ctx, tid, p.clientID)
	if e != nil {
		return e
	}
	var rs *store.ResourceServer
	if p.audience != "" {
		rs, e = tx.ResourceServers().GetByIdentifier(ctx, tid, p.audience)
		if errors.Is(e, store.ErrNotFound) && mfa.APIAudience(ctx, tx, tid, p.audience) {
			rs = mfa.APIResourceServer(tid, p.audience)
			e = nil
		}
		if e != nil {
			return e
		}
	}
	jkt, failure := accessProof(ctx, c, rs)
	if failure != nil || jkt != p.jkt {
		return errors.New("oauth: proof policy changed during issuance")
	}
	return nil
}
