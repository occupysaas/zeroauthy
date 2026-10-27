package federation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Flow limits (spec §4, §5).
const (
	attemptTTL      = 5 * time.Minute
	callbackBudget  = 30 * time.Second
	maxCallbackSize = 16 << 10
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
	Tenant *store.Tenant
	// Origin is the transaction's active public origin, e.g.
	// "https://login.example.com"; the callback is Origin + CallbackPath.
	Origin     string
	Txn        *store.AuthTransaction
	Client     *store.Client
	Connection *store.Connection
}

// Begun is a started attempt: redirect the browser to URL after setting the
// cookie CookieName=CookieValue (HttpOnly, Secure, SameSite=Lax, path
// CallbackPath) until ExpiresAt.
type Begun struct {
	URL, CookieName, CookieValue string
	ExpiresAt                    time.Time
}

type proof struct {
	Verifier string `json:"v"`
	Nonce    string `json:"n"`
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
	conn := in.Connection
	if conn == nil || !access.ConnectionUsable(in.Client, conn) {
		return nil, ErrConnectionUnusable
	}
	if err := RequireMicrosoftConnection(ctx, s.Store, conn); err != nil {
		return nil, err
	}
	spec := connrules.FromConnection(conn)
	cfg, err := ParseConfig(*spec)
	if err != nil || !cfg.AuthenticationActive || len(conn.FederationSecretsSealed) == 0 {
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
	case StrategyGoogle:
		endpoints, issuer = s.Providers.google()
	case StrategyOAuth2:
		endpoints = Endpoints{AuthorizationURL: cfg.AuthorizationURL, TokenURL: cfg.TokenURL, TokenAuthMethod: authPost}
	case StrategyWindowsLive, StrategyWAAD, StrategyOIDC:
		var meta Metadata
		var err error
		if cfg.Strategy == StrategyOIDC {
			meta, err = s.Providers.Discover(ctx, key, cfg.DiscoveryURL, cfg.Issuer)
		} else {
			meta, err = s.Providers.DiscoverMicrosoft(ctx, key, cfg)
		}
		if err != nil {
			return nil, err
		}
		if cfg.Issuer == "" && (cfg.Strategy == StrategyOIDC || cfg.Strategy == StrategyWAAD && !cfg.MicrosoftMultiTenant) {
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
	sealed, err := s.sealProof(conn.TenantID, stateHash, proof{Verifier: verifier, Nonce: nonce})
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
	a := &store.FederationAttempt{
		StateHash: stateHash, TenantID: conn.TenantID, TransactionID: in.Txn.ID, ConnectionID: conn.ID,
		Revision: key.Revision, IdentityEpoch: epoch, CookieHash: CookieHash(cookie), Origin: in.Origin,
		CallbackURL: callback, Issuer: issuer, Endpoints: endpoints, SealedProof: sealed, ExpiresAt: expires,
		Status: store.AttemptPending, CreatedAt: now,
	}
	if err := s.Store.Federation().CreateAttempt(ctx, a); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(verifier))
	u, err := s.Providers.For(cfg).AuthorizationURL(StartInput{Config: cfg, Endpoints: endpoints, CallbackURL: callback,
		State: state, Nonce: nonce, CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:])})
	if err != nil {
		return nil, err
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
}

// ParseCallback validates a raw callback query: at most 16 KiB, no duplicate
// parameters, a state, and exactly one of code and error.
func ParseCallback(rawQuery string) (CallbackParams, error) {
	if len(rawQuery) > maxCallbackSize {
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
	p := CallbackParams{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error")}
	if p.State == "" || (p.Code == "") == (p.Error == "") {
		return CallbackParams{}, ErrCallbackRejected
	}
	return p, nil
}

// CompleteInput is one callback.
type CompleteInput struct {
	Tenant *store.Tenant
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
	Commit func(tx store.Store, user *store.User, txn *store.AuthTransaction, conn *store.Connection) error
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
	conn, txn, _, err := s.eligible(ctx, s.Store, a)
	if err != nil {
		_ = s.Store.Federation().FinishAttempt(ctx, a.TenantID, a.StateHash)
		return nil, err
	}
	if in.Params.Error != "" {
		_ = s.Store.Federation().FinishAttempt(ctx, a.TenantID, a.StateHash)
		return nil, ErrProviderDenied
	}
	cfg, err := ParseConfig(*connrules.FromConnection(conn))
	if err != nil {
		return nil, ErrConnectionUnusable
	}
	creds, err := OpenCredentials(s.Wrapper, conn.TenantID, conn.ID, conn.FederationSecretsSealed)
	if err != nil {
		return nil, fmt.Errorf("%w: credentials", ErrConnectionUnusable)
	}
	pr, err := s.openProof(a.TenantID, a.StateHash, a.SealedProof)
	if err != nil {
		return nil, ErrAttemptStale
	}
	res, err := s.Providers.For(cfg).Exchange(ctx, ExchangeInput{
		Config: cfg, Cache: CacheKey{TenantID: conn.TenantID, ConnectionID: conn.ID, Revision: a.Revision},
		Endpoints: a.Endpoints, Issuer: a.Issuer, CallbackURL: a.CallbackURL, Code: in.Params.Code,
		CodeVerifier: pr.Verifier, Nonce: pr.Nonce, ClientSecret: creds.ClientSecret, Now: s.now(),
	})
	if err != nil {
		return nil, err // the attempt stays claimed: never retried
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
		return s.Store.WithTx(ctx, func(tx store.Store) error {
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
			user, err := s.ResolveIdentity(ctx, tx, conn, res)
			if err != nil {
				return err
			}
			if err := tx.Federation().FinishAttempt(ctx, a.TenantID, a.StateHash); err != nil {
				return ErrAttemptStale
			}
			if in.Commit != nil {
				if err := in.Commit(tx, user, txn, conn); err != nil {
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
	if txn.Params[authz.ParamFlow] == authz.FlowDevice {
		grant = "urn:ietf:params:oauth:grant-type:device_code"
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
		if !IsFederated(c.Strategy) || !access.ConnectionUsable(client, c) || len(c.FederationSecretsSealed) == 0 {
			continue
		}
		spec := connrules.FromConnection(c)
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
	}
	return c.Name
}

// IsFederated reports whether strategy is federated.
func IsFederated(strategy string) bool {
	return rules.IsFederated(strategy)
}
