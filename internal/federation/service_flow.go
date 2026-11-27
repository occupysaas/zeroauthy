package federation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Flow limits (spec §4, §5).
const (
	attemptTTL     = 5 * time.Minute
	callbackBudget = 30 * time.Second
	// MaxCallbackSize bounds both query and form-post callbacks.
	MaxCallbackSize = 16 << 10
	// MaxSAMLCallbackSize bounds a posted SAML response form (Plan 37a).
	MaxSAMLCallbackSize = 2*samlcore.MaxInputBytes + 8192
	// AttemptCookiePrefix names the browser binding cookie of one attempt:
	// the prefix plus the first 16 hex characters of the state hash, so tabs
	// keep independent attempts.
	AttemptCookiePrefix = "za_fed_"
	// CallbackPath is the provider callback on the transaction's origin.
	CallbackPath = "/login/callback"
	proofLabel   = "federation-attempt/v1"
)

// Flow errors. Callers show generic localized copy; none carries provider or
// script text.
var (
	// ErrCallbackRejected: a malformed or unbound callback; no provider
	// request was made.
	ErrCallbackRejected = errors.New("federation: callback rejected")
	// ErrAttemptStale: the attempt was replayed, superseded, expired, or its
	// connection, application, transaction or identity state changed.
	ErrAttemptStale = errors.New("federation: login attempt is no longer valid")
	// ErrProviderDenied: the provider returned an OAuth error.
	ErrProviderDenied = errors.New("federation: provider denied the login")
	// ErrConnectionUnusable: the connection cannot authenticate (disabled,
	// not enabled for the application, missing credentials, runtime).
	ErrConnectionUnusable = errors.New("federation: connection cannot be used to log in")
)

// FlowService drives browser federation: Start persists an attempt and
// returns the provider redirect; Complete claims, exchanges once, validates
// and commits atomically.
type FlowService struct {
	Service
	Store     store.Store
	Providers *Providers
	Log       *slog.Logger
}

// BeginInput binds an attempt to the browser transaction.
type BeginInput struct {
	LoginHint string
	Tenant    *store.Tenant
	// Origin is the transaction's active public origin, e.g.
	// "https://login.example.com"; the callback is Origin + CallbackPath.
	Origin     string
	Txn        *store.AuthTransaction
	Client     *store.Client
	Connection *store.Connection
}

// Begun is a started attempt: redirect the browser to URL after setting the
// cookie CookieName=CookieValue (HttpOnly, Secure, SameSite=None for Apple,
// Lax for other providers, path CallbackPath) until ExpiresAt.
type Begun struct {
	URL, CookieName, CookieValue string
	ExpiresAt                    time.Time
	// Form, when set, is posted to URL by an auto-submitting page (the SAML
	// HTTP-POST binding) instead of a redirect.
	Form url.Values
}

type proof struct {
	Verifier  string     `json:"v"`
	Nonce     string     `json:"n"`
	Endpoints *Endpoints `json:"e,omitempty"`
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// StateHash is the stored form of an upstream state value.
func StateHash(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// CookieHash is the stored form of an attempt cookie value.
func CookieHash(v string) string { return StateHash("cookie:" + v) }

// Begin creates the attempt and returns the provider redirect. Nothing is
// sent upstream except OIDC discovery (bounded, cached).
func (s *FlowService) Begin(ctx context.Context, in BeginInput) (*Begun, error) {
	ctx = events.Enrich(ctx, in.Client, in.Connection)
	conn := in.Connection
	if conn == nil || !access.ConnectionUsable(in.Client, conn) {
		return nil, ErrConnectionUnusable
	}
	if err := RequireMicrosoftConnection(ctx, s.Store, conn); err != nil {
		return nil, err
	}
	if err := RequireGitHubConnection(ctx, s.Store, conn); err != nil {
		return nil, err
	}
	if in.Txn == nil {
		return nil, ErrConnectionUnusable
	}
	oc, err := orglogin.Load(ctx, s.Store, conn.TenantID, in.Txn.Params)
	if err != nil {
		return nil, ErrConnectionUnusable
	}
	if oc.Org != nil {
		if _, ok := oc.Connections[conn.ID]; !ok {
			return nil, ErrConnectionUnusable
		}
	}
	spec := connrules.FromConnection(conn)
	cfg, err := ParseConfig(*spec)
	if err != nil || !cfg.AuthenticationActive || !cfg.Secretless() && len(conn.FederationSecretsSealed) == 0 {
		return nil, ErrConnectionUnusable
	}
	if cfg.Strategy == StrategyOAuth2 {
		if err := s.Providers.scriptsReady(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrConnectionUnusable, err)
		}
	}
	key := CacheKey{TenantID: conn.TenantID, ConnectionID: conn.ID, Revision: conn.FederationRevision}
	var endpoints Endpoints
	issuer := cfg.Issuer
	switch cfg.Strategy {
	case StrategyGoogle, StrategyGoogleApps:
		endpoints, issuer = s.Providers.google()
	case StrategyApple:
		meta, err := s.Providers.AppleMetadata(ctx, key)
		if err != nil {
			return nil, err
		}
		issuer, endpoints = meta.Issuer, meta.Endpoints()
	case StrategyGitHub:
		endpoints, _ = s.Providers.github() // no issuer: GitHub has no ID token
	case StrategyOAuth2:
		endpoints = Endpoints{AuthorizationURL: cfg.AuthorizationURL, TokenURL: cfg.TokenURL, TokenAuthMethod: authPost}
	case StrategySAMLP:
		if cfg.SAML.SignInEndpoint == "" {
			return nil, ErrConnectionUnusable
		}
		endpoints, issuer = Endpoints{AuthorizationURL: cfg.SAML.SignInEndpoint}, cfg.SAML.IdPEntityID
	case StrategyADFS:
		if cfg.ADFS.SignInEndpoint == "" {
			return nil, ErrConnectionUnusable
		}
		endpoints = Endpoints{AuthorizationURL: cfg.ADFS.SignInEndpoint}
	case StrategyAD:
		// Only the Kerberos redirect begins at the provider (Plan 38a).
		if cfg.ADFS == nil {
			return nil, ErrConnectionUnusable
		}
		endpoints = Endpoints{AuthorizationURL: cfg.ADFS.SignInEndpoint}
	case StrategyWindowsLive, StrategyWAAD, StrategyOIDC, StrategyOkta:
		var meta Metadata
		var err error
		if cfg.Strategy == StrategyOIDC || cfg.Strategy == StrategyOkta {
			meta, err = s.Providers.ResolveEnterpriseMetadata(ctx, key, cfg)
		} else {
			meta, err = s.Providers.DiscoverMicrosoft(ctx, key, cfg)
		}
		if err != nil {
			return nil, err
		}
		if cfg.Issuer == "" && (cfg.Strategy == StrategyOIDC || cfg.Strategy == StrategyOkta || cfg.Strategy == StrategyWAAD && !cfg.MicrosoftMultiTenant) {
			rev, err := PinIssuer(ctx, s.Store, conn.TenantID, conn.ID, conn.FederationRevision, meta.Issuer)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrAttemptStale, err)
			}
			cfg.Revision, cfg.Issuer, key.Revision = rev, meta.Issuer, rev
		}
		issuer, endpoints = meta.Issuer, meta.Endpoints()
	default:
		return nil, ErrConnectionUnusable
	}
	now := s.now()
	state, nonce, verifier, cookie := randomToken(), randomToken(), randomToken(), randomToken()
	stateHash := StateHash(state)
	sealed, err := s.sealProof(conn.TenantID, stateHash, proof{Verifier: verifier, Nonce: nonce, Endpoints: &endpoints})
	if err != nil {
		return nil, err
	}
	epoch, err := s.Store.Federation().IdentityEpoch(ctx, conn.TenantID)
	if err != nil {
		return nil, err
	}
	expires := now.Add(attemptTTL)
	if in.Txn.ExpiresAt.Before(expires) {
		expires = in.Txn.ExpiresAt
	}
	callback := strings.TrimSuffix(in.Origin, "/") + CallbackPath
	if cfg.SAML != nil {
		callback = SAMLACSURL(in.Origin, conn.Name)
	}
	a := &store.FederationAttempt{
		StateHash: stateHash, TenantID: conn.TenantID, TransactionID: in.Txn.ID, ConnectionID: conn.ID,
		Revision: key.Revision, IdentityEpoch: epoch, CookieHash: CookieHash(cookie), Origin: in.Origin,
		CallbackURL: callback, Issuer: issuer, Endpoints: endpoints, SealedProof: sealed, ExpiresAt: expires,
		Status: store.AttemptPending, CreatedAt: now,
	}
	if err := s.Store.Federation().CreateAttempt(ctx, a); err != nil {
		return nil, err
	}
	if cfg.ADFS != nil {
		u, err := adfsSignInURL(in.Tenant, conn, cfg, callback, state)
		if err != nil {
			return nil, err
		}
		return &Begun{URL: u, CookieName: AttemptCookiePrefix + stateHash[:16], CookieValue: cookie, ExpiresAt: expires}, nil
	}
	if cfg.SAML != nil {
		u, form, err := s.samlAuthnRequest(ctx, in.Tenant, conn, cfg, callback, state, nonce)
		if err != nil {
			return nil, err
		}
		return &Begun{URL: u, Form: form, CookieName: AttemptCookiePrefix + stateHash[:16], CookieValue: cookie, ExpiresAt: expires}, nil
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if endpoints.PKCEMethod == "plain" {
		challenge = verifier
	}
	u, err := s.Providers.For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: endpoints, CallbackURL: callback,
		State: state, Nonce: nonce, CodeChallenge: challenge, LoginHint: in.LoginHint})
	if err != nil {
		return nil, err
	}
	if cfg.PAR {
		var creds Credentials
		if len(conn.FederationSecretsSealed) > 0 {
			creds, err = OpenCredentials(s.Wrapper, conn.TenantID, conn.ID, conn.FederationSecretsSealed)
			if err != nil {
				return nil, ErrConnectionUnusable
			}
		}
		u, err = s.Providers.PushAuthorization(ctx, u, ExchangeInput{Config: cfg, Endpoints: endpoints, Issuer: issuer, ClientSecret: creds.ClientSecret, ClientAssertion: func(aud string) (string, error) { return ClientAssertion(ctx, s.Store, s.Wrapper, conn, cfg, aud, now) }})
		if err != nil {
			return nil, err
		}
	}
	return &Begun{URL: u, CookieName: AttemptCookiePrefix + stateHash[:16], CookieValue: cookie, ExpiresAt: expires}, nil
}

func (s *FlowService) sealProof(tenantID, stateHash string, p proof) ([]byte, error) {
	plain, _ := json.Marshal(p)
	return keys.SealBound(s.Wrapper, proofLabel, []string{tenantID, stateHash}, plain)
}

func (s *FlowService) openProof(tenantID, stateHash string, sealed []byte) (proof, error) {
	var p proof
	plain, err := keys.OpenBound(s.Wrapper, proofLabel, []string{tenantID, stateHash}, sealed)
	if err != nil || json.Unmarshal(plain, &p) != nil || p.Verifier == "" || p.Nonce == "" {
		return proof{}, errors.New("federation: attempt proof does not open")
	}
	return p, nil
}

// CallbackParams is a parsed provider callback.
type CallbackParams struct {
	State, Code, Error string
	IDToken            string
	// SAMLResponse is a posted SAML response (samlp ACS, Plan 37a).
	SAMLResponse string
	// WResult is a posted WS-Federation token (adfs, Plan 37b).
	WResult  string
	FormPost bool
	// User is untrusted, optional Apple first-authorization name JSON.
	User string
}

// ParseCallback validates URL-encoded query or body fields: at most 16 KiB,
// no duplicate parameters, a state, and exactly one of code and error.
func ParseCallback(rawQuery string) (CallbackParams, error) {
	if len(rawQuery) > MaxCallbackSize {
		return CallbackParams{}, ErrCallbackRejected
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return CallbackParams{}, ErrCallbackRejected
	}
	for _, vs := range q {
		if len(vs) != 1 {
			return CallbackParams{}, ErrCallbackRejected
		}
	}
	p := CallbackParams{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error"), User: q.Get("user"), IDToken: q.Get("id_token")}
	count := 0
	for _, v := range []string{p.Code, p.Error, p.IDToken} {
		if v != "" {
			count++
		}
	}
	if p.State == "" || count != 1 {
		return CallbackParams{}, ErrCallbackRejected
	}
	return p, nil
}

// CompleteInput is one callback.
type CompleteInput struct {
	OnSensitiveValues func(...string) // register upstream values with request log scrubbing
	// OnResolved observes only immutable attribution already established by the flow.
	// It receives no configuration, credentials, transaction or profile objects.
	OnResolved func(logs.Event)
	Tenant     *store.Tenant
	// Origin is the request's resolved public origin; it must equal the
	// attempt's.
	Origin      string
	Params      CallbackParams
	CookieValue string // the attempt cookie; "" when absent
	// RecheckOrigin, when set, runs immediately before the commit
	// transaction (origin/certificate eligibility); no provider call
	// follows it.
	RecheckOrigin func(ctx context.Context) error
	// BeforeProvision, when set, runs before a first login provisions a new
	// user (the registration budget); its error ends the login.
	BeforeProvision func(ctx context.Context) error
	// Commit runs inside the final transaction after every eligibility check
	// and the identity/token writes: it creates the local session and
	// consumes the login transaction through tx.
	// upstream is the SAML IdP session (samlp logins only, else nil), to be
	// carried by the new session for SP single logout.
	Commit func(tx store.Store, user *store.User, txn *store.AuthTransaction, conn *store.Connection, upstream *store.SAMLParticipant) error
}

// Completion is a committed federated login.
type Completion struct {
	UserID, TransactionID, ConnectionID string
	Transaction                         *store.AuthTransaction
	Connection                          *store.Connection
}

// Complete claims the attempt, exchanges the code once, validates the
// provider identity and commits identity, tokens, attempt and session in one
// transaction.
func (s *FlowService) Complete(ctx context.Context, in CompleteInput) (*Completion, error) {
	ctx = logscrub.WithCredentials(logscrub.WithValues(ctx, in.Params.Code, in.Params.IDToken, in.Params.SAMLResponse, in.Params.WResult), in.Params.Code, in.Params.IDToken, in.Params.SAMLResponse, in.Params.WResult)
	if in.CookieValue == "" || in.Tenant == nil {
		return nil, ErrCallbackRejected
	}
	ctx, cancel := context.WithTimeout(ctx, callbackBudget)
	defer cancel()
	stateHash := StateHash(in.Params.State)
	a, err := s.Store.Federation().ClaimAttempt(ctx, in.Tenant.ID, stateHash, CookieHash(in.CookieValue), in.Origin, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrAlreadyUsed), errors.Is(err, store.ErrInvalid):
		return nil, fmt.Errorf("%w: %w", ErrAttemptStale, err)
	case err != nil:
		return nil, err
	}
	conn, txn, client, err := s.eligible(ctx, s.Store, a)
	if err != nil {
		_ = s.Store.Federation().FinishAttempt(ctx, a.TenantID, a.StateHash)
		return nil, err
	}
	actor := logs.Event{TenantID: a.TenantID, ClientID: txn.ClientID, ClientName: client.Name, Connection: conn.Name, ConnectionID: conn.ID, Strategy: conn.Strategy, StrategyType: logs.StrategyType(conn.Strategy), OrganizationID: txn.Params[store.TxnParamOrgID]}
	ctx = events.Enrich(ctx, client, conn)
	ctx = logs.WithEvent(ctx, actor)
	if in.OnResolved != nil {
		in.OnResolved(actor)
	}
	cfg, err := ParseConfig(*connrules.FromConnection(conn))
	if err != nil {
		return nil, ErrConnectionUnusable
	}
	pr, err := s.openProof(a.TenantID, a.StateHash, a.SealedProof)
	if err != nil {
		return nil, ErrAttemptStale
	}
	// Older plugin codecs preserve SealedProof but do not know endpoint fields.
	if pr.Endpoints != nil {
		a.Endpoints = *pr.Endpoints
	} else if cfg.Strategy == StrategyOIDC && a.Endpoints.ResponseType == "" {
		// Pre-enterprise attempts were always code/S256.
		a.Endpoints.ResponseType = "code"
		a.Endpoints.PKCEMethod = "S256"
	}
	front := cfg.Channel == "front_channel"
	if cfg.ADFS != nil {
		if !in.Params.FormPost || in.Params.WResult == "" || in.Params.SAMLResponse != "" || in.Params.Code != "" || in.Params.IDToken != "" {
			return nil, ErrCallbackRejected
		}
	} else if in.Params.WResult != "" {
		return nil, ErrCallbackRejected
	} else if cfg.SAML != nil {
		if !in.Params.FormPost || in.Params.SAMLResponse == "" || in.Params.Code != "" || in.Params.IDToken != "" {
			return nil, ErrCallbackRejected
		}
	} else if in.Params.SAMLResponse != "" {
		return nil, ErrCallbackRejected
	} else if front {
		if !in.Params.FormPost || a.Endpoints.ResponseType != "id_token" || in.Params.Code != "" {
			return nil, ErrCallbackRejected
		}
	} else if in.Params.IDToken != "" || in.Params.FormPost && cfg.Strategy != StrategyApple {
		return nil, ErrCallbackRejected
	}
	if in.Params.Error != "" {
		_ = s.Store.Federation().FinishAttempt(ctx, a.TenantID, a.StateHash)
		return nil, ErrProviderDenied
	}
	var creds Credentials
	if len(conn.FederationSecretsSealed) > 0 {
		creds, err = OpenCredentials(s.Wrapper, conn.TenantID, conn.ID, conn.FederationSecretsSealed)
		if err != nil {
			return nil, fmt.Errorf("%w: credentials", ErrConnectionUnusable)
		}
	} else if !cfg.Secretless() {
		return nil, ErrConnectionUnusable
	}
	var appleUser *AppleUser
	if cfg.Strategy == StrategyApple && slices.Contains(cfg.Scopes, "name") {
		// Optional malformed/oversized names must never break authentication.
		// Eligibility above ties these scopes to this attempt's revision.
		appleUser, _ = ParseAppleUser(in.Params.User)
	}
	exchange := ExchangeInput{
		DecryptIDToken: func(raw string) (string, error) {
			list, e := EnsureKeys(ctx, s.Store, s.Wrapper, conn, "encryption", cfg.EncAlg, in.Tenant.CanonicalHost, s.now())
			if e != nil {
				return "", e
			}
			return decryptIDToken(raw, list, func(k *store.ConnectionKey) (crypto.Signer, error) { return OpenConnectionKey(s.Wrapper, k) }, cfg.EncAlg, cfg.EncEncs)
		},
		ClientAssertion: func(aud string) (string, error) {
			return ClientAssertion(ctx, s.Store, s.Wrapper, conn, cfg, aud, s.now())
		},
		Config: cfg, Cache: CacheKey{TenantID: conn.TenantID, ConnectionID: conn.ID, Revision: a.Revision},
		Endpoints: a.Endpoints, Issuer: a.Issuer, CallbackURL: a.CallbackURL, Code: in.Params.Code,
		CodeVerifier: pr.Verifier, Nonce: pr.Nonce, ClientSecret: creds.ClientSecret, Now: s.now(), AppleUser: appleUser,
	}
	var res ProviderResult
	var assertion *samlAssertion
	if cfg.ADFS != nil {
		assertion, err = s.adfsValidate(in.Tenant, conn, cfg, in.Params.WResult)
		if err == nil {
			res = assertion.Result
		}
	} else if cfg.SAML != nil {
		assertion, err = s.samlValidate(ctx, in.Tenant, conn, cfg, in.Origin, samlRequestID(pr.Nonce), in.Params.SAMLResponse)
		if err == nil {
			res = assertion.Result
		}
	} else if front {
		claims, e := s.Providers.validateIDToken(ctx, exchange, a.Endpoints, TokenSet{IDToken: in.Params.IDToken})
		if e != nil {
			return nil, e
		}
		sub, _ := claims["sub"].(string)
		profile, e := mappedProfile(cfg, conn.ID, sub, claims, nil, TokenSet{})
		if e != nil {
			return nil, e
		}
		res = ProviderResult{Profile: profile}
	} else {
		res, err = s.Providers.For(cfg).Exchange(ctx, exchange)
	}
	if err != nil {
		return nil, err // the attempt stays claimed: never retried
	}
	values := []string{res.Tokens.AccessToken, res.Tokens.RefreshToken, res.Tokens.IDToken, creds.ClientSecret, in.Params.IDToken}
	ctx = logscrub.WithCredentials(logscrub.WithValues(ctx, values...), values...)
	if in.OnSensitiveValues != nil {
		in.OnSensitiveValues(values...)
	}
	if in.BeforeProvision != nil {
		if _, err := s.Store.Users().FindByIdentity(ctx, conn.TenantID, conn.ID, res.Profile.Subject); errors.Is(err, store.ErrNotFound) {
			if err := in.BeforeProvision(ctx); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}
	if in.RecheckOrigin != nil {
		if err := in.RecheckOrigin(ctx); err != nil {
			return nil, fmt.Errorf("%w: origin no longer eligible", ErrAttemptStale)
		}
	}
	var out *Completion
	commit := func() error {
		return orglogin.WithMembershipEvents(ctx, s.Store, func(ctx context.Context, tx store.Store) error {
			cur, err := tx.Federation().GetAttempt(ctx, a.TenantID, a.StateHash)
			if err != nil || cur.Status != store.AttemptClaimed || cur.Superseded {
				return ErrAttemptStale
			}
			epoch, err := tx.Federation().IdentityEpoch(ctx, a.TenantID)
			if err != nil {
				return err
			}
			if epoch != a.IdentityEpoch {
				return fmt.Errorf("%w: identities changed during login", ErrAttemptStale)
			}
			conn, txn, _, err = s.eligible(ctx, tx, a)
			if err != nil {
				return err
			}
			user, created, err := s.resolveIdentity(ctx, tx, conn, res, func() error {
				if txn.Params[orglogin.InvitationIDParam] == "" {
					return nil
				}
				// The supported is_signup_enabled contract applies only to database
				// connections. First-provider invitation provisioning therefore fails
				// closed; an existing separately provisioned provider user may accept.
				if conn.Strategy != store.StrategyDatabase || conn.DisableSignup {
					return ErrConnectionUnusable
				}
				link, e := tx.Organizations().GetConnection(ctx, a.TenantID, txn.Params[store.TxnParamOrgID], conn.ID)
				if e != nil {
					return e
				}
				if !link.IsSignupEnabled {
					return ErrConnectionUnusable
				}
				return nil
			})
			if err != nil {
				return err
			}
			if in.OnResolved != nil {
				in.OnResolved(logs.Enrich(ctx, logs.Event{UserID: user.UserID, UserName: user.Name}))
			}
			if created && txn.Params[orglogin.InvitationIDParam] != "" {
				txn.Params[orglogin.InvitationSignupParam] = "1"
				if err := orglogin.SaveInvitationTransaction(ctx, tx, txn, s.now()); err != nil {
					return err
				}
			}
			oc, e := orglogin.Load(ctx, tx, a.TenantID, txn.Params)
			if e != nil {
				return e
			}
			if oc.Org != nil {
				e = orglogin.CheckMemberClient(ctx, tx, a.TenantID, oc.Org.ID, txn.ClientID)
			}
			if e == nil && txn.Params[orglogin.InvitationIDParam] == "" {
				e = orglogin.CheckMembership(ctx, tx, oc, user.UserID, conn.ID)
			}
			if e != nil && !errors.Is(e, orglogin.ErrNotMember) {
				return e
			}
			if front {
				if err := tx.Federation().DeleteTokens(ctx, store.FederatedIdentityKey{TenantID: conn.TenantID, ConnectionID: conn.ID, Subject: res.Profile.Subject}); err != nil {
					return err
				}
			}
			if assertion != nil {
				if err := useSAMLAssertion(ctx, tx, conn, assertion, s.now()); err != nil {
					return err
				}
			}
			if err := tx.Federation().FinishAttempt(ctx, a.TenantID, a.StateHash); err != nil {
				return ErrAttemptStale
			}
			if in.Commit != nil {
				var upstream *store.SAMLParticipant
				if assertion != nil {
					upstream = assertion.upstream(conn)
				}
				if err := in.Commit(tx, user, txn, conn, upstream); err != nil {
					return err
				}
			}
			out = &Completion{UserID: user.UserID, TransactionID: txn.ID, ConnectionID: conn.ID, Transaction: txn, Connection: conn}
			return nil
		})
	}
	err = commit()
	if errors.Is(err, store.ErrConflict) {
		err = commit() // a concurrent first login provisioned the user
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// eligible rechecks, through st, that the attempt's connection is unchanged
// and usable, its login transaction is current, and the application still
// has the connection enabled.
func (s *FlowService) eligible(ctx context.Context, st store.Store, a *store.FederationAttempt) (*store.Connection, *store.AuthTransaction, *store.Client, error) {
	conn, err := st.Connections().Get(ctx, a.TenantID, a.ConnectionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil, fmt.Errorf("%w: connection deleted", ErrAttemptStale)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if err := RequireMicrosoftConnection(ctx, st, conn); err != nil {
		return nil, nil, nil, err
	}
	if conn.FederationRevision != a.Revision {
		return nil, nil, nil, fmt.Errorf("%w: connection changed", ErrAttemptStale)
	}
	txn, err := st.AuthTransactions().Get(ctx, a.TenantID, a.TransactionID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !s.now().Before(txn.ExpiresAt)) {
		return nil, nil, nil, fmt.Errorf("%w: login transaction ended", ErrAttemptStale)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := st.Clients().Get(ctx, a.TenantID, txn.ClientID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !access.ConnectionUsable(client, conn)) {
		return nil, nil, nil, fmt.Errorf("%w: application no longer uses the connection", ErrAttemptStale)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	// Recheck the grant before any local identity, token or session write.
	// Authorization continuation also checks it, but runs after session commit.
	grant := "authorization_code"
	switch txn.Params[store.TxnParamFlow] {
	case store.TxnFlowDevice:
		grant = "urn:ietf:params:oauth:grant-type:device_code"
	case store.TxnFlowCIBA:
		grant = "urn:openid:params:grant-type:ciba"
	}
	if !slices.Contains(client.GrantTypes, grant) {
		return nil, nil, nil, fmt.Errorf("%w: application grant disabled", ErrAttemptStale)
	}
	if cfg, err := ParseConfig(*connrules.FromConnection(conn)); err != nil || !cfg.AuthenticationActive {
		return nil, nil, nil, ErrConnectionUnusable
	}
	return conn, txn, client, nil
}

// SocialChoices returns the federated connections an application can log in
// with, by name. A connection whose show_as_button is explicitly false is
// omitted unless includeHidden (explicit selection still works); one that
// never named it is shown.
func SocialChoices(client *store.Client, conns []*store.Connection, includeHidden bool) []*store.Connection {
	var out []*store.Connection
	for _, c := range conns {
		// ad connections take a username and password, never a button.
		if !IsFederated(c.Strategy) || c.Strategy == StrategyAD || !access.ConnectionUsable(client, c) {
			continue
		}
		spec := connrules.FromConnection(c)
		cfg, err := ParseConfig(*spec)
		if err != nil || !cfg.Secretless() && len(c.FederationSecretsSealed) == 0 {
			continue
		}
		if active, ok := spec.Authentication["active"].(bool); ok && !active {
			continue
		}
		if !includeHidden && spec.ShowAsButton != nil && !*spec.ShowAsButton {
			continue
		}
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b *store.Connection) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// ButtonLabel is the text a connection's button shows.
func ButtonLabel(c *store.Connection) string {
	if d := connrules.FromConnection(c).DisplayName; d != "" {
		return d
	}
	switch c.Strategy {
	case StrategyWindowsLive:
		return "Microsoft personal account"
	case StrategyWAAD:
		return "Microsoft work or school account"
	case StrategyGoogle:
		return "Google"
	case StrategyGoogleApps:
		return "Google Workspace"
	case StrategyGitHub:
		return "GitHub"
	}
	return c.Name
}

// IsFederated reports whether strategy is federated.
func IsFederated(strategy string) bool {
	return rules.IsFederated(strategy)
}

// CompleteFrontChannel shares state claiming, nonce validation and atomic
// identity/session commit with the authorization-code callback.
type FrontChannelInput struct{ State, IDToken, Error, ErrorDescription string }

func (s *FlowService) CompleteFrontChannel(ctx context.Context, in CompleteInput, fc FrontChannelInput) (*Completion, error) {
	in.Params = CallbackParams{State: fc.State, IDToken: fc.IDToken, Error: fc.Error, FormPost: true}
	return s.Complete(ctx, in)
}
