package oauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const nativeAppleSubjectType = "http://auth0.com/oauth/token-type/apple-authz-code"
const nativeAppleDisabled = "Native Social Login is not enabled for this client"

// nativeKinds are the reserved native subject token types (Plan 39a Apple,
// Plan 39b Google and Facebook).
var nativeKinds = map[string]string{
	nativeAppleSubjectType:               federation.NativeKindApple,
	federation.NativeGoogleSubjectType:   federation.NativeKindGoogle,
	federation.NativeFacebookSubjectType: federation.NativeKindFacebook,
}

func isNativeSubjectType(t string) bool { _, ok := nativeKinds[t]; return ok }

// nativeLabels name the connection in the generic invalid_grant text.
var nativeLabels = map[string]string{federation.NativeKindApple: "Apple", federation.NativeKindGoogle: "Google", federation.NativeKindFacebook: "Facebook"}

func (h *Handlers) nativeAppleExchange(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (*authapi.TokenResponse, *Error) {
	return h.nativeExchange(ctx, res, c, form, federation.NativeKindApple)
}

// nativeExchange signs a user in with a native social token of kind.
func (h *Handlers) nativeExchange(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values, kind string) (response *authapi.TokenResponse, failure *Error) {
	code := form.Get("subject_token")
	ctx = logscrub.WithCredentials(ctx, code, form.Get("user_profile"))
	logs.AddCredentials(ctx, code, form.Get("user_profile"))
	var conn *store.Connection
	var uid string
	defer func() {
		if failure != nil && failure.Code == "mfa_required" {
			return
		}
		event := "secte"
		if failure != nil {
			event = "fecte"
		}
		h.exchangeEvent(ctx, res, c, event, conn, uid, nil)
	}()
	if h.Federation == nil || !federation.NativeEnabled(c, kind) {
		return nil, invalidRequest(nativeAppleDisabled)
	}
	if code == "" {
		return nil, invalidRequest("subject_token is required")
	}
	if form.Get("actor_token") != "" || form.Get("actor_token_type") != "" {
		return nil, invalidRequest("actor tokens are not supported for native social login")
	}
	var userProfile *federation.AppleUser
	var facebookUser *federation.FacebookUser
	var err error
	switch kind {
	case federation.NativeKindApple:
		if userProfile, err = federation.ParseAppleUser(form.Get("user_profile")); err != nil {
			return nil, invalidRequest("user_profile must be a JSON object of at most 1 KiB with valid names")
		}
	case federation.NativeKindFacebook:
		if facebookUser, err = federation.ParseFacebookUser(form.Get("user_profile")); err != nil {
			return nil, invalidRequest("user_profile must be a JSON object of at most 2 KiB of strings")
		}
	}
	tid := res.Tenant.ID
	// List's documented order is LOWER(name), id in every built-in store. The
	// client has no separate connection order: choose the first usable Apple.
	for page := 0; conn == nil; page++ {
		cs, total, err := h.Store.Connections().List(ctx, tid, store.ConnectionFilter{Strategies: []string{federation.NativeStrategy(kind)}}, store.Page{Offset: page * 100, Limit: 100})
		if err != nil {
			return nil, serverError()
		}
		for _, candidate := range cs {
			if len(federation.SocialChoices(c, []*store.Connection{candidate}, true)) > 0 {
				conn = candidate
				break
			}
		}
		if conn != nil {
			break
		}
		if (page+1)*100 >= total {
			break
		}
	}
	if conn == nil {
		return nil, invalidRequest(nativeAppleDisabled)
	}
	aud := form.Get("audience")
	if aud == "" {
		aud = res.Tenant.DefaultAudience
	}
	// Each host has its own My Account audience (LR42a-10).
	if id, ok := tenant.APIIdentifier(res, aud); ok {
		aud = id
	} else {
		return nil, accessDenied("unknown audience")
	}
	if h.isMFAAudience(ctx, tid, aud) {
		return nil, accessDenied("native social login cannot issue tokens for the MFA API")
	}
	if aud != "" {
		if _, err := h.Store.ResourceServers().GetByIdentifier(ctx, tid, aud); errors.Is(err, store.ErrNotFound) {
			return nil, accessDenied("unknown audience")
		} else if err != nil {
			return nil, serverError()
		}
	}
	rs, lifetime, oerr := h.audienceFor(ctx, tid, aud)
	if oerr != nil {
		return nil, oerr
	}
	// Native cannot prompt for consent.
	if rs != nil && !rs.SkipConsentForVerifiableFirstPartyClients {
		return nil, accessDenied("the API must allow skipping user consent for first-party applications")
	}
	requested := strings.Fields(form.Get("scope"))
	d, oerr := h.decide(ctx, tid, access.Password, c, rs, userScopes(requested, rs, offlineAllowed(c, rs)))
	if oerr != nil {
		return nil, oerr
	}
	org, oerr := h.machineOrganization(ctx, res, form)
	if oerr != nil {
		return nil, oerr
	}
	orgID := ""
	if org != nil {
		orgID = org.ID
	}
	params := map[string]string{}
	if orgID != "" {
		params[store.TxnParamOrgID] = orgID
		params[store.TxnParamOrgMode] = "fixed"
	}
	oc, err := orglogin.Load(ctx, h.Store, tid, params)
	if err != nil {
		return nil, invalidGrant("the organization grant is no longer eligible")
	}
	if orgID == "" && c.OrganizationUsage == store.OrgUsageRequire || orgID != "" && c.OrganizationUsage != store.OrgUsageAllow && c.OrganizationUsage != store.OrgUsageRequire {
		return nil, invalidGrant("the organization grant is no longer eligible")
	}
	if orgID != "" {
		if _, ok := oc.Connections[conn.ID]; !ok {
			return nil, invalidGrant("the organization grant is no longer eligible")
		}
	}
	svc := h.protectionService()
	spend := func(ctx context.Context, flow string) error {
		decision, err := svc.Begin(ctx, protection.Attempt{Tenant: res.Tenant, Connection: conn, IP: clientIPFrom(ctx), Flow: flow})
		if err != nil {
			return err
		}
		if !decision.Allowed {
			return errNativeRateLimit
		}
		return svc.Finish(ctx, decision.Receipt, "failure")
	}
	if err := spend(ctx, "social-login"); err != nil {
		if errors.Is(err, errNativeRateLimit) {
			return nil, tooManyRequests()
		}
		return nil, serverError()
	}
	user, binding, err := h.Federation.NativeLogin(ctx, federation.NativeAppleInput{Kind: kind, Client: c, Connection: conn, Code: code, User: userProfile, FacebookUser: facebookUser,
		BeforeProvision: func(ctx context.Context) error { return spend(ctx, "social-signup") },
		CommitIdentity: func(ctx context.Context, tx store.Store, u *store.User, current *store.Connection) error {
			fresh, err := tx.Clients().Get(ctx, tid, c.ClientID)
			if err != nil {
				return err
			}
			if orgID == "" && fresh.OrganizationUsage == store.OrgUsageRequire || orgID != "" && fresh.OrganizationUsage != store.OrgUsageAllow && fresh.OrganizationUsage != store.OrgUsageRequire {
				return errOrganizationGrant
			}
			if orgID != "" {
				currentOrg, err := orglogin.Load(ctx, tx, tid, params)
				if err != nil {
					return err
				}
				if err = orglogin.CheckMemberClient(ctx, tx, tid, orgID, c.ClientID); err != nil {
					return err
				}
				if err = orglogin.CheckMembership(ctx, tx, currentOrg, u.UserID, current.ID); err != nil {
					return err
				}
				_, err = pendingOrganization(ctx, tx, tid, u.UserID, orgID, current.ID, fresh, true)
				return err
			}
			return nil
		},
	})
	if err != nil {
		if errors.Is(err, errNativeRateLimit) {
			return nil, tooManyRequests()
		}
		// Never surface or log provider error text: it may echo a code or token.
		switch {
		case errors.Is(err, federation.ErrProviderResponse), errors.Is(err, federation.ErrNetworkPolicy), errors.Is(err, federation.ErrAttemptStale), errors.Is(err, federation.ErrConnectionUnusable), errors.Is(err, federation.ErrUserBlocked), errors.Is(err, federation.ErrEmailRequired), errors.Is(err, federation.ErrIdentityConflict), errors.Is(err, orglogin.ErrNotMember), errors.Is(err, errOrganizationGrant), errors.Is(err, store.ErrNotFound):
			return nil, invalidGrant("Error from " + nativeLabels[kind] + " connection")
		default:
			h.log().ErrorContext(ctx, "native social login could not complete", "tenant", tid, "kind", kind)
			return nil, serverError()
		}
	}
	uid = user.UserID
	pendingMembership := false
	if orgID != "" {
		member, e := h.Store.Organizations().IsMember(ctx, tid, orgID, uid)
		if e != nil {
			return nil, serverError()
		}
		pendingMembership = !member
	}
	org, err = pendingOrganization(ctx, h.Store, tid, uid, orgID, conn.ID, c, pendingMembership)
	if err != nil {
		return nil, invalidGrant("the organization grant is no longer eligible")
	}
	ctx = logs.WithEvent(ctx, logs.Event{UserID: uid, UserName: user.Name, Connection: conn.Name, ConnectionID: conn.ID, Strategy: conn.Strategy, StrategyType: logs.StrategyType(conn.Strategy)})
	eff, oerr := h.postLogin(ctx, res, c, loginFlow{pendingMembership: pendingMembership, organizationID: orgID, user: user, connection: conn, rs: rs, protocol: actions.ProtocolTokenExchange, requested: requested, target: requested})
	if oerr != nil {
		return nil, oerr
	}
	before := d.Scopes
	if eff != nil && eff.Target != nil {
		d, oerr = h.decide(ctx, tid, access.Password, c, rs, userScopes(eff.Target.Scopes, rs, offlineAllowed(c, rs)))
		if oerr != nil {
			return nil, oerr
		}
	}
	ceiling := actions.CeilingOf(d.Scopes, before)
	now := h.now().UTC()
	flow := firstFactorTokens{PendingMembership: pendingMembership, Organization: org, ConnectionID: conn.ID, Native: binding}
	if _, err := h.Federation.CheckNative(ctx, h.Store, binding); err != nil {
		return nil, invalidGrant("the native login is no longer eligible")
	}
	if required := h.passwordMFA(ctx, res, c, user, conn, aud, d.Scopes, ceiling, eff, now, flow); required != nil {
		return nil, required
	}
	resp, write, oerr := h.preparePasswordTokens(ctx, res, c, user, rs, lifetime, aud, d.Scopes, ceiling, eff, now, time.Time{}, flow)
	if oerr != nil {
		return nil, oerr
	}
	version := user.Version
	ctx, flushMembership := orglogin.StageMembershipEvents(ctx)
	err = h.mintCheckedTx(ctx, tid, uid, &version, func(tx store.Store) error {
		if _, err := h.Federation.CheckNative(ctx, tx, binding); err != nil {
			return err
		}
		return checkPendingOrganization(ctx, tx, tid, uid, orgID, conn.ID, c.ClientID, pendingMembership, true)
	}, write)
	flushMembership(err)
	if err != nil {
		return nil, invalidGrant("the native login is no longer eligible")
	}

	return resp, nil
}

var errNativeRateLimit = errors.New("oauth: native social login rate limit")
