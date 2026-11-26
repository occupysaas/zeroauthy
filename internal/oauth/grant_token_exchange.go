package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/claims"
	"github.com/zeroauthy/zeroauthy/internal/gen/authapi"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/signupactions"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
)

// GrantTokenExchange serves custom token exchange and reserved native social types.
const GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// customAuthentication is the only token exchange profile type, and the value
// a client's token_exchange.allow_any_profile_of_type must hold.
const customAuthentication = "custom_authentication"

// tokenExchangeBlocked is the description of a throttled exchange (our wording).
const tokenExchangeBlocked = "Too many token exchange attempts from this address. Wait a while before trying again."

// issuedTokenTypeAccessToken is the issued_token_type of every custom token
// exchange response.
const issuedTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

// noExchangeUser answers an Action whose selected user cannot be used: a
// missing user, or a user_id owned by another connection.
const noExchangeUser = "the user selected for this token exchange cannot be used"

func tooManyAttempts() *Error {
	return &Error{Status: http.StatusTooManyRequests, Code: "too_many_attempts", Description: tokenExchangeBlocked}
}

// tokenExchange implements custom token exchange (RFC 8693 with a token
// exchange profile). Order: client checks, profile, API, throttle, the
// profile's Action, user resolution, post-login, tokens. The subject and
// actor tokens are credentials: they are masked in every log of the request.
func (h *Handlers) tokenExchange(ctx context.Context, res tenant.Resolved, c *store.Client, form url.Values) (response *authapi.TokenResponse, failure *Error) {
	if form.Get("subject_token_type") == nativeAppleSubjectType {
		return h.nativeAppleExchange(ctx, res, c, form)
	}
	subject, actorToken := form.Get("subject_token"), form.Get("actor_token")
	ctx = logscrub.WithCredentials(ctx, subject, actorToken)
	logs.AddCredentials(ctx, subject, actorToken)
	var eventConn *store.Connection
	var eventUserID string
	var eventActor map[string]any
	defer func() {
		code := "secte"
		if failure != nil {
			code = "fecte"
		}
		h.exchangeEvent(ctx, res, c, code, eventConn, eventUserID, eventActor)
	}()
	tid := res.Tenant.ID
	if !c.IsFirstParty {
		return nil, unauthorizedClient("custom token exchange is not available to third-party applications")
	}
	if !slices.Contains(c.TokenExchangeTypes, customAuthentication) {
		return nil, unauthorizedClient("the application does not allow custom token exchange")
	}
	subjectType, actorType := form.Get("subject_token_type"), form.Get("actor_token_type")
	if subject == "" || subjectType == "" {
		return nil, invalidRequest("subject_token and subject_token_type are required")
	}
	if (actorToken == "") != (actorType == "") {
		return nil, invalidRequest("actor_token and actor_token_type must be sent together")
	}
	profile, err := h.Store.ClientCredentials().GetProfileByType(ctx, tid, subjectType)
	if errors.Is(err, store.ErrNotFound) || err == nil && profile.Type != customAuthentication {
		return nil, invalidRequest("no token exchange profile matches subject_token_type")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load token exchange profile", "tenant", tid, "err", err)
		return nil, serverError()
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
	if id := tenant.MyAccountIdentifier(res.Tenant); id != "" && aud == id {
		return nil, accessDenied("custom token exchange cannot issue tokens for the My Account API")
	}
	var rs *store.ResourceServer
	lifetime := DefaultAccessTokenLifetime
	if aud != "" {
		if h.isMFAAudience(ctx, tid, aud) {
			return nil, accessDenied("custom token exchange cannot issue tokens for the MFA API")
		}
		rs, err = h.Store.ResourceServers().GetByIdentifier(ctx, tid, aud)
		if errors.Is(err, store.ErrNotFound) {
			return nil, accessDenied("unknown audience")
		}
		if err != nil {
			h.log().ErrorContext(ctx, "load resource server", "tenant", tid, "err", err)
			return nil, serverError()
		}
		// No consent can be asked for here (C11).
		if !rs.SkipConsentForVerifiableFirstPartyClients {
			return nil, accessDenied("the API must allow skipping user consent for first-party applications")
		}
		if rs.TokenLifetime > 0 {
			lifetime = time.Duration(rs.TokenLifetime) * time.Second
		}
	}
	requested := strings.Fields(form.Get("scope"))
	d, oerr := h.decide(ctx, tid, access.Password, c, rs, userScopes(requested, rs, offlineAllowed(c, rs)))
	if oerr != nil {
		return nil, oerr
	}
	requestOrg, oerr := h.machineOrganization(ctx, res, form)
	if oerr != nil {
		return nil, oerr
	}

	// The suspicious-IP stage is checked before the Action runs. Only a
	// rejected subject token spends the attempt; every other outcome gives it back.
	svc := h.protectionService()
	decision, err := svc.Begin(ctx, protection.Attempt{Tenant: res.Tenant, IP: clientIPFrom(ctx), Flow: protection.FlowCustomTokenExchange})
	if err != nil {
		h.log().ErrorContext(ctx, "protection admission", "tenant", tid, "err", err)
		return nil, serverError()
	}
	if !decision.Allowed {
		return nil, tooManyAttempts()
	}
	outcome := "refund"
	defer func() {
		if err := svc.Finish(ctx, decision.Receipt, outcome); err != nil {
			h.log().ErrorContext(ctx, "protection completion", "tenant", tid, "err", err)
			// Issued tokens are already committed: keep the response. An
			// unrecorded attempt settles as a failure after the store's
			// pending lifetime.
			if outcome != "success" {
				response, failure = nil, serverError()
			}
		}
	}()

	if h.Actions == nil {
		h.log().ErrorContext(ctx, "custom token exchange: the Actions runtime is unavailable", "tenant", tid)
		return nil, serverError()
	}
	result, err := h.Actions.CustomTokenExchange(ctx, actions.TokenExchangeInput{
		Tenant: res, Client: c, Resource: rs, Organization: requestOrg,
		SubjectToken: subject, SubjectTokenType: subjectType, ActorToken: actorToken, ActorTokenType: actorType,
		RequestedTokenType: form.Get("requested_token_type"), RequestedScopes: requested,
		ActorTokenUser: h.actorTokenUser(ctx, res, actorToken), Request: requestInfoFrom(ctx), ActionID: profile.ActionID,
	})
	var flowErr *actions.ErrFlow
	if errors.As(err, &flowErr) {
		logs.AddExecution(ctx, flowErr.ExecutionID)
	}
	if err != nil {
		if flowErr == nil {
			h.log().ErrorContext(ctx, "run custom-token-exchange Action", "tenant", tid, "err", err)
		}
		return nil, serverError()
	}
	// The trigger contract: a deny wins, and either one ignores the user fields.
	if dn := result.Denied; dn != nil {
		return nil, &Error{Status: http.StatusBadRequest, Code: dn.Code, Description: dn.Reason}
	}
	if result.RejectedSubjectToken {
		outcome = "failure"
		return nil, invalidRequest("the subject token was rejected")
	}

	// The organization is resolved before the user, so a refused one never
	// leaves a created or updated user behind. Membership needs the user and
	// is checked after resolution.
	org := requestOrg
	if result.OrganizationRef != "" {
		selected, oerr := h.organizationByRef(ctx, tid, result.OrganizationRef)
		if oerr != nil {
			return nil, oerr
		}
		if org != nil && org.ID != selected.ID {
			return nil, invalidRequest("the organization parameter differs from the organization the Action selected")
		}
		org = selected
	}
	user, conn, oerr := h.exchangeUser(ctx, res, c, result)
	if oerr != nil {
		return nil, oerr
	}
	eventUserID, eventConn = user.UserID, conn
	ctx = logs.WithEvent(ctx, logs.Event{UserID: user.UserID, UserName: user.Name})
	orgID, connID := "", ""
	if org != nil {
		orgID = org.ID
	}
	if conn != nil {
		connID = conn.ID
	}
	if org, oerr = h.organizationForToken(ctx, tid, user.UserID, orgID, connID, c); oerr != nil {
		return nil, oerr
	}
	if org != nil {
		ctx = logs.WithEvent(ctx, logs.Event{OrganizationID: org.ID, OrganizationName: org.Name})
	}
	if len(result.AppMetadata) > 0 || len(result.UserMetadata) > 0 {
		if user, oerr = h.patchExchangeUser(ctx, tid, user.UserID, &userrules.Patch{
			AppMetadata: metadataPatch(result.AppMetadata), UserMetadata: metadataPatch(result.UserMetadata),
		}); oerr != nil {
			return nil, oerr
		}
	}

	eff, oerr := h.postLogin(ctx, res, c, loginFlow{organizationID: orgID, user: user, connection: conn, rs: rs,
		protocol: actions.ProtocolTokenExchange, requested: requested, target: requested})
	if oerr != nil {
		return nil, oerr
	}
	// No factor can be challenged or enrolled at the token endpoint; redirects
	// and prompts already fail the post-login flow there.
	if mfaRequested(eff) {
		return nil, accessDenied("multifactor authentication cannot be completed in a custom token exchange")
	}
	before := d.Scopes
	if eff != nil && eff.Target != nil {
		if d, oerr = h.decide(ctx, tid, access.Password, c, rs, userScopes(eff.Target.Scopes, rs, offlineAllowed(c, rs))); oerr != nil {
			return nil, oerr
		}
	}
	scopes := d.Scopes
	ceiling := actions.CeilingOf(scopes, before)
	now := h.now().UTC()
	resp, offline, oerr := h.mintUserTokens(ctx, res, c, userTokens{
		organization: org, user: user, rs: rs, lifetime: lifetime, scopes: scopes, authTime: now, effects: eff, actor: result.Actor,
	})
	if oerr != nil {
		return nil, oerr
	}
	// RFC 8693 section 2.2.1: always the access-token type (LR35-15).
	issued := issuedTokenTypeAccessToken
	resp.IssuedTokenType = &issued
	// No refresh token when an actor is set.
	var rt *store.RefreshToken
	if result.Actor == nil && offline && slices.Contains(ceiling, "offline_access") {
		absolute, _ := refreshLifetimes(c.RefreshToken)
		var expiresAt time.Time
		if absolute > 0 {
			expiresAt = now.Add(absolute)
		}
		var raw string
		rt, raw = h.newRefreshToken(ctx, c, tid, refreshGrant{

			organizationID: orgID, organizationConnectionID: connID, origin: res.Origin(),
			familyID: "rtf_" + secrets.RandomString(32), userID: user.UserID,
			audience: aud, scopes: ceiling, authTime: now, expiresAt: expiresAt,
		})
		resp.RefreshToken = &raw
	}
	version := user.Version
	err = h.mintCheckedTx(ctx, tid, user.UserID, &version, func(tx store.Store) error {
		return checkTokenOrganization(ctx, tx, tid, user.UserID, orgID, connID, c.ClientID)
	}, func(tx store.Store) error {
		if rt == nil {
			return nil
		}
		return createInitialRefresh(ctx, tx, rt)
	})
	switch {
	case errors.Is(err, errUserBlocked):
		return nil, invalidGrant("user is blocked")
	case errors.Is(err, errUserChanged):
		return nil, invalidGrant("the user is not allowed to sign in")
	case errors.Is(err, errOrganizationGrant), errors.Is(err, store.ErrNotFound):
		return nil, invalidGrant("the organization grant is no longer eligible")
	case err != nil:
		h.log().ErrorContext(ctx, "store refresh token", "tenant", tid, "err", err)
		return nil, serverError()
	}
	// Login counters update as for any login (C13).
	if err := h.Store.Users().RecordLogin(ctx, tid, user.UserID, now, httpx.CanonicalIP(clientIPFrom(ctx))); err != nil {
		h.log().WarnContext(ctx, "record login", "tenant", tid, "err", err)
	}
	outcome = "success"
	eventActor = result.Actor
	return resp, nil
}

// mfaRequested reports whether the post-login flow asked for a factor:
// challengeWith or enrollWith, or multifactor.enable with a provider other
// than none.
func mfaRequested(eff *actions.Effects) bool {
	if eff == nil || eff.MFA == nil {
		return false
	}
	return eff.MFA.Mode != "" || eff.MFA.Provider != "" && eff.MFA.Provider != "none"
}

func metadataPatch(m map[string]any) userrules.Metadata {
	if len(m) == 0 {
		return userrules.Metadata{}
	}
	return userrules.Metadata{Set: true, Value: m}
}

// exchangeEvent records secte or fecte; a successful exchange with an actor
// carries it in the details.
func (h *Handlers) exchangeEvent(ctx context.Context, res tenant.Resolved, c *store.Client, code string, conn *store.Connection, userID string, actor map[string]any) {
	ri := requestInfoFrom(ctx)
	e := logs.Event{TenantID: res.Tenant.ID, Type: code, Hostname: res.Host, IP: ri.IP, UserAgent: ri.UserAgent, UserID: userID,
		ClientID: c.ClientID, ClientName: c.Name}
	if conn != nil {
		e.Connection, e.ConnectionID, e.Strategy, e.StrategyType = conn.Name, conn.ID, conn.Strategy, logs.StrategyType(conn.Strategy)
	}
	if actor != nil {
		e.Details = map[string]any{"actor": actor}
	}
	logs.RecordEvent(ctx, h.Recorder, e)
}

// exchangeUser resolves the user the Action selected: setUserById names an
// existing, unblocked user of this tenant; setUserByConnection finds the
// user by user_id in a database connection enabled for the client, and
// creates or updates it as the Action's behaviours say. The connection
// returned is the one the organization check uses.
func (h *Handlers) exchangeUser(ctx context.Context, res tenant.Resolved, c *store.Client, r *actions.TokenExchangeResult) (*store.User, *store.Connection, *Error) {
	tid := res.Tenant.ID
	if r.UserID != "" {
		u, err := h.Store.Users().Get(ctx, tid, r.UserID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, invalidRequest(noExchangeUser)
		}
		if err != nil {
			h.log().ErrorContext(ctx, "load user", "tenant", tid, "err", err)
			return nil, nil, serverError()
		}
		if u.Blocked {
			return nil, nil, invalidGrant("user is blocked")
		}
		conn, err := h.userConnection(ctx, tid, u)
		if err != nil {
			h.log().ErrorContext(ctx, "load connection", "tenant", tid, "err", err)
			return nil, nil, serverError()
		}
		return u, conn, nil
	}
	conn, err := h.Store.Connections().GetByName(ctx, tid, r.Connection)
	if errors.Is(err, store.ErrNotFound) || err == nil && !slices.Contains(conn.EnabledClients, c.ClientID) {
		return nil, nil, invalidRequest("the connection selected for this token exchange does not exist or is not enabled for this application")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load connection", "tenant", tid, "err", err)
		return nil, nil, serverError()
	}
	if conn.Strategy != store.StrategyDatabase {
		return nil, nil, invalidRequest("setUserByConnection supports database connections only")
	}
	if identity.IsCustom(conn) && conn.ImportMode {
		return nil, nil, invalidRequest("a custom database connection in import mode supports setUserById only")
	}
	idPart, _ := r.Attributes["user_id"].(string)
	userID := store.StrategyDatabase + "|" + idPart
	u, err := h.Store.Users().Get(ctx, tid, userID)
	switch {
	case err == nil:
		u, oerr := h.existingExchangeUser(ctx, tid, conn, u, idPart, r)
		return u, conn, oerr
	case !errors.Is(err, store.ErrNotFound):
		h.log().ErrorContext(ctx, "load user", "tenant", tid, "err", err)
		return nil, nil, serverError()
	case r.CreationBehavior == actions.CreateNever:
		return nil, nil, invalidRequest(noExchangeUser)
	}
	u, oerr := h.createExchangeUser(ctx, res, c, conn, userID, idPart, r)
	return u, conn, oerr
}

// immutableAttributes cannot change once the user exists (Auth0 documents
// them as not updatable): a supplied value that differs is an error.
var immutableAttributes = []string{"email", "email_verified", "phone_number", "phone_verified", "username"}

func (h *Handlers) existingExchangeUser(ctx context.Context, tid string, conn *store.Connection, u *store.User, idPart string, r *actions.TokenExchangeResult) (*store.User, *Error) {
	own := slices.ContainsFunc(u.Identities, func(id store.Identity) bool {
		return id.Connection == conn.Name && id.Provider == store.StrategyDatabase && id.UserID == idPart && !id.Linked()
	})
	if !own {
		return nil, invalidRequest(noExchangeUser)
	}
	if u.Blocked {
		return nil, invalidGrant("user is blocked")
	}
	current := map[string]any{"email": u.Email, "email_verified": u.EmailVerified, "phone_number": u.PhoneNumber,
		"phone_verified": u.PhoneVerified, "username": u.Username}
	for _, k := range immutableAttributes {
		v, ok := r.Attributes[k]
		if !ok {
			continue
		}
		if s, isString := v.(string); isString && k != "phone_number" {
			v = identity.NormalizeLogin(s)
		}
		if v != current[k] {
			return nil, invalidRequest("attribute " + k + " cannot be changed for an existing user")
		}
	}
	if r.UpdateBehavior != actions.UpdateReplace {
		return u, nil
	}
	p := &userrules.Patch{}
	changed := false
	for k, dst := range map[string]**string{"name": &p.Name, "given_name": &p.GivenName, "family_name": &p.FamilyName, "nickname": &p.Nickname, "picture": &p.Picture} {
		if s, ok := r.Attributes[k].(string); ok {
			*dst, changed = &s, true
		}
	}
	if !changed {
		return u, nil
	}
	return h.patchExchangeUser(ctx, tid, u.UserID, p)
}

// patchExchangeUser applies p to the stored user under its row lock and
// returns the result. A profile or metadata the Action made invalid is a
// server_error: the Action is at fault, not the client.
func (h *Handlers) patchExchangeUser(ctx context.Context, tid, userID string, p *userrules.Patch) (*store.User, *Error) {
	var out *store.User
	err := h.Store.WithTx(ctx, func(tx store.Store) error {
		cur, err := tx.Users().GetForUpdate(ctx, tid, userID)
		if err != nil {
			return err
		}
		userrules.ApplyPatch(cur, p)
		if err := identity.CheckProfile(cur.GivenName, cur.FamilyName, cur.Name, cur.Nickname, cur.Picture); err != nil {
			return err
		}
		if err := userrules.CheckMetadata("user_metadata", cur.UserMetadata); err != nil {
			return err
		}
		if err := userrules.CheckMetadata("app_metadata", cur.AppMetadata); err != nil {
			return err
		}
		cur.UpdatedAt = h.now().UTC()
		if err := tx.Users().Update(ctx, cur); err != nil {
			return err
		}
		out = cur
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalidGrant("the user is not allowed to sign in")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "update token exchange user", "tenant", tid, "err", err)
		return nil, serverError()
	}
	return out, nil
}

// createExchangeUser creates the user through the existing password-less
// user-create path, so pre- and post-user-registration Actions and events
// run as for any creation. A concurrent creation of the same user is used
// as found.
func (h *Handlers) createExchangeUser(ctx context.Context, res tenant.Resolved, c *store.Client, conn *store.Connection, userID, idPart string, r *actions.TokenExchangeResult) (*store.User, *Error) {
	str := func(k string) string { s, _ := r.Attributes[k].(string); return s }
	flag := func(k string) bool { b, _ := r.Attributes[k].(bool); return b }
	in := identity.SignupInput{Email: str("email"), Username: str("username"), PhoneNumber: str("phone_number"),
		EmailVerified: flag("email_verified"), PhoneVerified: flag("phone_verified"),
		GivenName: str("given_name"), FamilyName: str("family_name"), Name: str("name"), Nickname: str("nickname"), Picture: str("picture")}
	email, username, err := identity.CheckSignupProfile(conn, in)
	if err != nil {
		return nil, invalidRequest("the user attributes selected for this token exchange are not valid for the connection")
	}
	if h.Database == nil {
		h.log().ErrorContext(ctx, "custom token exchange: user creation is unavailable", "tenant", res.Tenant.ID)
		return nil, serverError()
	}
	name, nickname := identity.DefaultNames(in.Name, in.Nickname, email, username)
	picture := in.Picture
	if picture == "" {
		picture = identity.DefaultPicture(email)
	}
	now := h.now().UTC()
	u := &store.User{TenantID: res.Tenant.ID, UserID: userID, Email: email, EmailVerified: in.EmailVerified, Username: username,
		PhoneNumber: in.PhoneNumber, PhoneVerified: in.PhoneVerified, Name: name, Nickname: nickname,
		GivenName: in.GivenName, FamilyName: in.FamilyName, Picture: picture,
		Identities: []store.Identity{{Connection: conn.Name, Provider: store.StrategyDatabase, UserID: idPart}},
		CreatedAt:  now, UpdatedAt: now}
	if in.PhoneNumber != "" {
		u.PhoneNormalized = userrules.NormalizePhone(in.PhoneNumber)
	}
	callbacks := signupactions.Callbacks(h.Store, h.Actions, actions.RegistrationInput{Tenant: res, Client: c, Connection: conn, Request: requestInfoFrom(ctx)})
	err = h.Database.CreatePasswordless(ctx, conn, callbacks, u)
	var denied *identity.ErrSignupDenied
	var failed *identity.ErrSignupActionFailed
	switch {
	case errors.Is(err, identity.ErrUserExists):
		found, gerr := h.Store.Users().Get(ctx, res.Tenant.ID, userID)
		if gerr != nil {
			return nil, invalidRequest("a user with these attributes already exists in the connection")
		}
		return h.existingExchangeUser(ctx, res.Tenant.ID, conn, found, idPart, r)
	case errors.As(err, &denied):
		return nil, accessDenied(denied.Description)
	case errors.As(err, &failed):
		return nil, serverError()
	case err != nil:
		h.log().ErrorContext(ctx, "create token exchange user", "tenant", res.Tenant.ID, "err", err)
		return nil, serverError()
	}
	h.event(ctx, res, c, "ss", conn, u.UserID)
	return u, nil
}

// organizationByRef resolves api.authentication.setOrganization: an
// organization ID, else a name.
func (h *Handlers) organizationByRef(ctx context.Context, tid, ref string) (*store.Organization, *Error) {
	if orgrules.ValidID(ref) {
		org, err := h.Store.Organizations().Get(ctx, tid, ref)
		if err == nil {
			return org, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			h.log().ErrorContext(ctx, "load organization", "tenant", tid, "err", err)
			return nil, serverError()
		}
	}
	org, err := h.Store.Organizations().GetByName(ctx, tid, ref)
	if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrOrganizationsIIUnavailable) {
		return nil, invalidRequest("the organization selected for this token exchange does not exist")
	}
	if err != nil {
		h.log().ErrorContext(ctx, "load organization", "tenant", tid, "err", err)
		return nil, serverError()
	}
	return org, nil
}

// actorTokenUser is event.transaction.actor_token_user: the user of an
// actor token that is an unexpired ID token this tenant signed for one of
// its applications. Anything else, an access token included, gives nil; no
// unverified claim is used.
func (h *Handlers) actorTokenUser(ctx context.Context, res tenant.Resolved, raw string) map[string]any {
	if raw == "" || h.Minter == nil || h.Minter.Keys == nil {
		return nil
	}
	tid := res.Tenant.ID
	var std jwt.Claims
	var extra struct {
		Scope    *string `json:"scope"`
		AZP      string  `json:"azp"`
		Grant    string  `json:"gty"`
		ClientID string  `json:"client_id"`
	}
	if h.Minter.Keys.Verify(ctx, tid, raw, &std, &extra) != nil || std.Expiry == nil || std.Subject == "" ||
		std.ValidateWithLeeway(jwt.Expected{Issuer: res.Issuer(), Time: h.now()}, 0) != nil {
		return nil
	}
	// Access tokens carry azp, gty, client_id or scope; ID tokens do not.
	if extra.Scope != nil || extra.AZP != "" || extra.Grant != "" || extra.ClientID != "" || len(std.Audience) != 1 {
		return nil
	}
	if _, err := h.Store.Clients().Get(ctx, tid, std.Audience[0]); err != nil {
		return nil
	}
	u, err := h.Store.Users().Get(ctx, tid, std.Subject)
	if err != nil || u.Blocked {
		return nil
	}
	out := claims.ForUser(u, oidcScopes)
	out["user_id"] = u.UserID
	return out
}
