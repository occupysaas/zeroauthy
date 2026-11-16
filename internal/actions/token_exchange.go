package actions

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// ErrNoUserSelected reports a custom-token-exchange Action that did not call
// exactly one of authentication.setUserById and setUserByConnection (once).
var ErrNoUserSelected = errors.New("actions: the Action must call exactly one of setUserById or setUserByConnection, once")

// Documented values of setUserByConnection's options (C14 defaults first).
const (
	CreateIfNotExists = "create_if_not_exists"
	CreateNever       = "none"
	UpdateNever       = "none"
	UpdateReplace     = "replace"
)

// TokenExchangeInput is one custom token exchange.
type TokenExchangeInput struct {
	Tenant       tenant.Resolved
	Client       *store.Client
	Resource     *store.ResourceServer
	Organization *store.Organization
	// SubjectToken and ActorToken are credentials: they are masked in Action
	// logs and every server log of the flow.
	SubjectToken, SubjectTokenType, ActorToken, ActorTokenType, RequestedTokenType string
	RequestedScopes                                                                []string
	// ActorTokenUser is the user of a valid same-tenant ID-token actor, already
	// validated by the caller. It is placed in the event only when non-nil and
	// an actor token is present.
	ActorTokenUser map[string]any
	Request        RequestInfo
	// ActionID is the profile's bound Action. Exactly that deployed Action
	// runs; trigger bindings are not consulted.
	ActionID string
}

// DenyError is api.access.deny: the exchange fails with Code (400).
type DenyError struct{ Code, Reason string }

func (e *DenyError) Error() string {
	return fmt.Sprintf("actions: access denied (%s): %s", e.Code, e.Reason)
}

// TokenExchangeResult is what the Action selected. When Denied or
// RejectedSubjectToken is set, ignore the user fields; Denied wins over
// RejectedSubjectToken. The Action creates and
// looks up no user: the caller resolves UserID, or Connection plus
// Attributes, and applies the rest.
type TokenExchangeResult struct {
	// UserID is setUserById.
	UserID string
	// Connection, Attributes, CreationBehavior and UpdateBehavior are
	// setUserByConnection, behaviours defaulted.
	Connection                       string
	Attributes                       map[string]any
	CreationBehavior, UpdateBehavior string
	OrganizationRef                  string
	Actor                            map[string]any
	AppMetadata, UserMetadata        map[string]any // a nil value deletes the key
	Denied                           *DenyError
	// RejectedSubjectToken is access.rejectInvalidSubjectToken.
	RejectedSubjectToken bool
}

// CustomTokenExchange runs the profile's Action (in.ActionID, deployed) as
// the custom-token-exchange trigger. A deny or a rejected subject token is a
// result, not an error. An Action that is missing, undeployed, of another
// trigger or of another tenant is ErrActionNotFound.
func (e *Engine) CustomTokenExchange(ctx context.Context, in TokenExchangeInput) (*TokenExchangeResult, error) {
	tenantID := in.Tenant.Tenant.ID
	const trigger = TriggerCustomTokenExchange
	a, err := e.Store.Actions().GetAction(ctx, tenantID, in.ActionID)
	if errors.Is(err, store.ErrNotFound) || err == nil && (a.Trigger != trigger || a.DeployedVersionID == "") {
		return nil, e.unrecorded(tenantID, trigger, ErrActionNotFound)
	}
	if err != nil {
		return nil, e.unrecorded(tenantID, trigger, err)
	}
	v, err := e.Store.Actions().GetVersion(ctx, tenantID, a.ID, a.DeployedVersionID)
	if err != nil {
		return nil, e.unrecorded(tenantID, trigger, err)
	}
	// The tokens are credentials: mask them in Action logs and errors, and in
	// every server log line that carries this context.
	sensitive := map[string]string{}
	for name, value := range map[string]string{"subject_token": in.SubjectToken, "actor_token": in.ActorToken} {
		if value != "" {
			ctx = logscrub.WithCredentials(ctx, value)
			logs.AddCredentials(ctx, value)
			sensitive[name] = value
		}
	}
	f := &flow{tenantID: tenantID, trigger: trigger, handler: handlerFor(trigger), hostname: in.Tenant.Host,
		units: []unit{{name: a.Name, actionID: a.ID, versionKey: v.ID, code: v.Code, buildID: v.BuildID, secrets: v.Secrets, moduleRefs: v.Modules}},
		acc:   newAccum(trigger, nil, nil, false), cache: e.caches.get(tenantID, trigger), redactor: customdb.NewRedactor(sensitive)}
	f.event = func() map[string]any { return tokenExchangeEvent(&in) }
	f.validate = func(*Effects) error {
		// A deny or a rejection ends the exchange without a user.
		if f.acc.denied != nil || f.acc.cte.rejected || f.acc.cte.userCalls == 1 {
			return nil
		}
		return ErrNoUserSelected
	}
	res, err := e.run(ctx, f, nil)
	if err != nil {
		return nil, err
	}
	out := f.acc.cte.result
	out.AppMetadata, out.UserMetadata = maps.Clone(res.Effects.AppMetadata), maps.Clone(res.Effects.UserMetadata)
	out.RejectedSubjectToken = f.acc.cte.rejected
	if d := res.Denied; d != nil {
		out.Denied = &DenyError{Code: d.Code, Reason: d.Reason}
	}
	return &out, nil
}

// cteAccum is the custom-token-exchange selection accumulated from
// validated commands.
type cteAccum struct {
	result    TokenExchangeResult
	userCalls int
	rejected  bool
}

// selectUser records the selection. The call count rises with every call, so
// a second call (of either kind) fails the flow.
func (c *cteAccum) selectUser(id, connection string, attrs map[string]any, creation, update string) {
	c.userCalls++
	c.result.UserID, c.result.Connection, c.result.Attributes = id, connection, attrs
	c.result.CreationBehavior, c.result.UpdateBehavior = creation, update
}
