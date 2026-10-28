package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const continueLabel = "action-continue/v1"
const continueLifetime = 15 * time.Minute
const maxRedirects = 5

// ErrInvalidContinue never exposes whether a state exists or why it failed.
var ErrInvalidContinue = errors.New("actions: invalid continuation state")

// Pinned source and sealed secrets are retained rather than looking up bindings
// again: deploying or deleting Actions cannot change a suspended login.
type continueUnit struct {
	Name, ActionID, VersionKey, Code, BuildID string
	Secrets                                   []store.ActionSecret
}
type continuePayload struct {
	Input                   PostLoginInput
	Units                   []continueUnit
	Roles                   []roleJSON
	Effects                 Effects
	Target                  []string
	Position, RedirectCount int
	Remaining               time.Duration
}

func continuationOf(f *flow) map[string]string {
	if f.input == nil {
		return nil
	}
	return f.input.Continuation
}

func (e *Engine) suspend(ctx context.Context, st store.Store, f *flow, index int) (*Redirect, error) {
	if f.input == nil || f.input.Session == nil || f.input.Session.ID == "" || f.input.User == nil {
		return nil, fmt.Errorf("actions: redirect requires a login session")
	}
	if f.redirectCount >= maxRedirects {
		return nil, fmt.Errorf("actions: too many redirects")
	}
	if f.remaining <= 0 {
		return nil, ErrTimeout
	}
	p := continuePayload{Input: *f.input, Roles: f.roles, Effects: f.acc.eff, Target: f.acc.target, Position: f.position + index, RedirectCount: f.redirectCount + 1, Remaining: f.remaining}
	for _, u := range f.units[index:] {
		p.Units = append(p.Units, continueUnit{Name: u.name, ActionID: u.actionID, VersionKey: u.versionKey, Code: u.code, BuildID: u.buildID, Secrets: u.secrets})
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	state := secrets.RandomString(43)
	hash := secrets.HashToken(state)
	sessID := f.input.Session.ID
	sealed, err := keys.SealBound(e.Secrets, continueLabel, []string{f.tenantID, hash, sessID, f.input.Tenant.Origin()}, plain)
	if err != nil {
		return nil, err
	}
	now := e.now()
	c := &store.ContinueState{TenantID: f.tenantID, StateHash: hash, SessionID: sessID, Sealed: sealed, CreatedAt: now, ExpiresAt: now.Add(continueLifetime)}
	if err = st.Actions().CreateContinue(ctx, c); err != nil {
		return nil, err
	}
	u, _ := url.Parse(f.acc.redirect.URL)
	q := u.Query()
	for k, v := range f.acc.redirect.Query {
		q.Set(k, v)
	}
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return &Redirect{URL: u.String(), Query: map[string]string{"state": state}}, nil
}

// ContinuePostLogin consumes a single-use, session-, tenant- and origin-bound
// continuation, resumes the redirecting Action, then executes its pinned tail.
func (e *Engine) ContinuePostLogin(ctx context.Context, tenantID, state string, sess *store.LoginSession, req RequestInfo) (*Result, error) {
	if state == "" || len(state) > 512 || sess == nil || sess.ID == "" || sess.TenantID != tenantID {
		return nil, ErrInvalidContinue
	}
	c, err := e.Store.Actions().ConsumeContinue(ctx, tenantID, secrets.HashToken(state), e.now())
	if err != nil || c.SessionID != sess.ID {
		return nil, ErrInvalidContinue
	}
	origin := req.Origin
	if origin == "" && req.Hostname != "" {
		origin = "https://" + tenant.NormalizeHost(req.Hostname)
	}
	plain, err := keys.OpenBound(e.Secrets, continueLabel, []string{tenantID, c.StateHash, sess.ID, origin}, c.Sealed)
	if err != nil {
		return nil, ErrInvalidContinue
	}
	var p continuePayload
	if json.Unmarshal(plain, &p) != nil || len(p.Units) == 0 || p.Input.Session == nil || p.Input.Session.ID != sess.ID || p.Input.User == nil || p.Input.User.UserID != sess.UserID || p.Input.Tenant.Tenant == nil || p.Input.Tenant.Tenant.ID != tenantID || p.Input.Tenant.Origin() != origin || p.RedirectCount < 1 || p.RedirectCount > maxRedirects || p.Remaining <= 0 {
		return nil, ErrInvalidContinue
	}
	// Keep the original flow/event snapshot, with the current request and session.
	p.Input.Request, p.Input.Session = req, sess
	f := &flow{tenantID: tenantID, trigger: TriggerPostLogin, handler: "onContinuePostLogin", hostname: p.Input.Tenant.Host, input: &p.Input,
		roles: p.Roles, acc: newAccum(TriggerPostLogin, p.Target, nil, true), cache: e.caches.get(tenantID, TriggerPostLogin), redirectCount: p.RedirectCount, position: p.Position, state: state, remaining: p.Remaining}
	f.acc.eff = p.Effects
	for _, u := range p.Units {
		f.units = append(f.units, unit{name: u.Name, actionID: u.ActionID, versionKey: u.VersionKey, code: u.Code, buildID: u.BuildID, secrets: u.Secrets})
	}
	names := make([]string, len(f.roles))
	for i, r := range f.roles {
		names[i] = r.Name
	}
	f.event = func() map[string]any { return postLoginEvent(&p.Input, names, f.acc) }
	return e.run(ctx, f, p.Input.User)
}

// PurgeContinue drops abandoned and expired suspended flows. Held metadata is
// only inside the sealed payload and is discarded with it.
func PurgeContinue(ctx context.Context, st store.Store, now time.Time) (int, error) {
	return st.Actions().PurgeContinue(ctx, now)
}
