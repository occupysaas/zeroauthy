package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const resetContinueLabel = "action-reset-continue/v1"

// resetStatePrefix marks states issued by the reset page, so /continue can
// dispatch without a store read. Post-login states never carry it.
const resetStatePrefix = "rst_"

// IsResetState reports whether a continue state was issued by a reset flow.
func IsResetState(state string) bool { return strings.HasPrefix(state, resetStatePrefix) }

// resetBinding is the stored owner of a reset continuation: the page cookie,
// never a login session ID.
func resetBinding(pageCookie string) string { return "reset:" + secrets.HashToken(pageCookie) }

type resetContinuePayload struct {
	Input                   ResetChallengeInput
	Units                   []continueUnit
	ResultURL               string
	Position, RedirectCount int
	Remaining               time.Duration
}

// ResetPostChallenge runs the blocking password-reset-post-challenge flow for
// a valid, unspent ticket. An empty Result means no Action is bound; the
// caller records a pass only for a completed flow (ExecutionID set, no
// denial or redirect).
func (e *Engine) ResetPostChallenge(ctx context.Context, in ResetChallengeInput) (*Result, error) {
	tenantID := in.Tenant.Tenant.ID
	bound, err := e.Store.Actions().Bindings(ctx, tenantID, TriggerResetPostChallenge)
	if err != nil {
		return nil, e.unrecorded(tenantID, TriggerResetPostChallenge, err)
	}
	if len(bound) == 0 {
		return &Result{}, nil
	}
	if in.Prepare != nil {
		if err := in.Prepare(ctx, &in); err != nil {
			return nil, e.unrecorded(tenantID, TriggerResetPostChallenge, err)
		}
	}
	if in.Ticket == nil || in.Ticket.TokenHash == "" || in.User == nil {
		return nil, e.unrecorded(tenantID, TriggerResetPostChallenge, errors.New("missing reset ticket or user"))
	}
	f := &flow{tenantID: tenantID, trigger: TriggerResetPostChallenge, handler: handlerFor(TriggerResetPostChallenge), hostname: in.Tenant.Host,
		units: pinned(bound), acc: newAccum(TriggerResetPostChallenge, nil, nil, in.CanRedirect), cache: e.caches.get(tenantID, TriggerResetPostChallenge), reset: &in}
	f.event = func() map[string]any { return resetChallengeEvent(&in, f.acc) }
	return e.run(ctx, f, nil)
}

func (e *Engine) suspendReset(ctx context.Context, st store.Store, f *flow, index int) (*Redirect, error) {
	in := f.reset
	if in.Ticket == nil || in.Ticket.TokenHash == "" || in.PageCookie == "" || in.User == nil {
		return nil, fmt.Errorf("actions: redirect requires the reset page")
	}
	if err := suspendable(f); err != nil {
		return nil, err
	}
	p := resetContinuePayload{Input: *in, ResultURL: f.acc.resultURL, Position: f.position + index, RedirectCount: f.redirectCount + 1, Remaining: f.remaining}
	var err error
	if p.Units, err = continueUnits(ctx, st, f, index); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	state := resetStatePrefix + secrets.RandomString(43)
	sealed, err := keys.SealBound(e.Secrets, resetContinueLabel, []string{f.tenantID, secrets.HashToken(state), in.Ticket.TokenHash, secrets.HashToken(in.PageCookie), in.Tenant.Origin()}, plain)
	if err != nil {
		return nil, err
	}
	return e.storeContinue(ctx, st, f, state, resetBinding(in.PageCookie), sealed)
}

// ContinueResetChallenge consumes a single-use reset continuation bound to the
// tenant, the ticket hash, the reset page cookie and the origin, resumes the
// redirecting Action with onContinuePostChallenge, then runs the pinned tail.
// The caller re-checks the ticket and records the pass.
func (e *Engine) ContinueResetChallenge(ctx context.Context, tenantID, state, ticketHash, pageCookie string, req RequestInfo) (*Result, error) {
	if !IsResetState(state) || len(state) > 512 || ticketHash == "" || pageCookie == "" {
		return nil, ErrInvalidContinue
	}
	c, err := e.Store.Actions().ConsumeContinue(ctx, tenantID, secrets.HashToken(state), resetBinding(pageCookie), e.now())
	if err != nil {
		return nil, ErrInvalidContinue
	}
	origin := requestOrigin(req)
	plain, err := keys.OpenBound(e.Secrets, resetContinueLabel, []string{tenantID, c.StateHash, ticketHash, secrets.HashToken(pageCookie), origin}, c.Sealed)
	if err != nil {
		return nil, ErrInvalidContinue
	}
	var p resetContinuePayload
	if json.Unmarshal(plain, &p) != nil || len(p.Units) == 0 || p.Input.Ticket == nil || p.Input.Ticket.TokenHash != ticketHash || p.Input.User == nil ||
		p.Input.Tenant.Tenant == nil || p.Input.Tenant.Tenant.ID != tenantID || p.Input.Tenant.Origin() != origin || p.RedirectCount < 1 || p.RedirectCount > maxRedirects || p.Remaining <= 0 {
		return nil, ErrInvalidContinue
	}
	p.Input.Request, p.Input.PageCookie = req, pageCookie
	in := &p.Input
	f := &flow{tenantID: tenantID, trigger: TriggerResetPostChallenge, handler: triggerSpecs[TriggerResetPostChallenge].ContinueHandler, hostname: in.Tenant.Host, reset: in,
		acc: newAccum(TriggerResetPostChallenge, nil, nil, in.CanRedirect), cache: e.caches.get(tenantID, TriggerResetPostChallenge), redirectCount: p.RedirectCount, position: p.Position, state: state, remaining: p.Remaining}
	f.acc.resultURL = p.ResultURL
	for _, u := range p.Units {
		if len(u.ModuleVersions) != len(u.Modules) {
			return nil, ErrInvalidContinue
		}
		f.units = append(f.units, unit{name: u.Name, actionID: u.ActionID, versionKey: u.VersionKey, code: u.Code, buildID: u.BuildID, secrets: u.Secrets, moduleRefs: u.Modules, moduleVersions: u.ModuleVersions})
	}
	f.event = func() map[string]any { return resetChallengeEvent(in, f.acc) }
	return e.run(ctx, f, nil)
}

// PasswordChanged queues post-change-password through tx, the transaction
// that changed the password; the caller has already set
// User.LastPasswordReset there. A full queue drops the job with a log line
// and keeps the change. A nil engine queues nothing.
func PasswordChanged(ctx context.Context, tx store.Store, e *Engine, t tenant.Resolved, user *store.User, conn *store.Connection, req RequestInfo) error {
	if e == nil || user == nil {
		return nil
	}
	in := PostChangePasswordInput{Tenant: t, User: user, Connection: conn, Request: req}
	err := e.Enqueue(ctx, tx, AsyncJob{TenantID: t.Tenant.ID, Trigger: TriggerPostChangePassword, Input: postChangePasswordEvent(&in)})
	if errors.Is(err, store.ErrPrecondition) {
		e.log().WarnContext(ctx, "post-change-password Action job dropped", "tenant", t.Tenant.ID, "user_id", user.UserID, "error", err)
		return nil
	}
	return err
}
