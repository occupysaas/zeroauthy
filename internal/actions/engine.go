package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/userrules"
)

// flowBudget is Auth0's limit for one trigger flow (all its Actions).
var flowBudget = time.Duration(actionsrules.Inventory().Limits["flow_budget_seconds"]) * time.Second

var (
	// ErrDraftNotBuilt: the test endpoint's draft has no built dependencies
	// (400 at the Management API, D-0053).
	ErrDraftNotBuilt = errors.New("actions: the draft's dependencies are not built")
	// ErrActionNotFound: no such Action in the tenant (404).
	ErrActionNotFound = errors.New("actions: Action not found")
	// ErrInvalidPayload: a test payload that is not a JSON object (400).
	ErrInvalidPayload = errors.New("actions: test payload must be a JSON object")
	// ErrActionError reports an Action that threw or rejected.
	ErrActionError = errors.New("actions: the Action failed")
	// ErrTimeout reports a flow over its budget.
	ErrTimeout = errors.New("actions: the flow exceeded its time limit")
)

// TargetEdit is the target scope set after the flow's transaction edits.
type TargetEdit struct{ Scopes []string }

// RBACSnapshot preserves effective permissions, while token issuance still
// evaluates the current API definition and application policy.
type RBACSnapshot struct {
	Audience    string   `json:"audience"`
	Permissions []string `json:"permissions"`
}

// Effects are a flow's validated, accumulated results. Claims are filtered
// during minting. Metadata patches commit only when the flow completes.
type Effects struct {
	// RBAC is fixed before the first Action. Management API assignments made
	// by an Action affect the next issuance, including across redirects/code exchange.
	RBAC                      *RBACSnapshot
	AccessClaims, IDClaims    map[string]any
	AddScopes, RemoveScopes   []string
	Target                    *TargetEdit
	AppMetadata, UserMetadata map[string]any
	TxnMetadata               map[string]any
	// Ceiling is set by callers, not the engine: the authorized scopes
	// before the flow's target-scope edits, the refresh family's ceiling
	// (spec §7) when it differs from the issued scopes. Nil: the issued
	// scopes are the ceiling.
	Ceiling []string
}

// Denial is access.deny or validation.error. Code is "access_denied" for a
// post-login deny, the validation.error code, or the credentials-exchange
// deny code.
type Denial struct{ Code, Reason string }

// Redirect is a recorded api.redirect.sendUserTo (spec §8).
type Redirect struct {
	URL   string
	Query map[string]string
}

// Result is the outcome of a flow that did not fail.
type Result struct {
	Effects      Effects
	Denied       *Denial
	Redirect     *Redirect
	ExecutionID  string
	Continuation map[string]string
}

// ErrFlow is a failed flow: no code or token may be issued. ExecutionID
// names its execution record; it is for operators and the hosted error
// page, never for OAuth error_description.
type ErrFlow struct {
	ExecutionID string
	Cause       error
	// Continuation is trusted caller context from a resumed, opened state.
	Continuation map[string]string
}

func (e *ErrFlow) Error() string {
	return fmt.Sprintf("actions: flow failed (execution %s): %v", e.ExecutionID, e.Cause)
}
func (e *ErrFlow) Unwrap() error { return e.Cause }

// Engine runs Action flows.
type Engine struct {
	Store   store.Store
	Runner  *noderunner.Pool
	Builds  *build.Manager
	Secrets keys.Wrapper // opens Action secrets (keys.OpenActionSecret)
	Now     func() time.Time
	Log     *slog.Logger
	// FlowBudget bounds one trigger flow; 0 means Auth0's 20 s.
	FlowBudget time.Duration

	caches caches
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

func (e *Engine) budget() time.Duration {
	if e.FlowBudget > 0 {
		return e.FlowBudget
	}
	return flowBudget
}

// roleJSON is a role as api.roles returns it.
type roleJSON struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// wireRequest is the runner.mjs request; the Pool adds "id".
type wireRequest struct {
	VersionKey string                 `json:"version_key"`
	Code       string                 `json:"code"`
	DepsRoot   string                 `json:"deps_root"`
	Handler    string                 `json:"handler"`
	Event      map[string]any         `json:"event"`
	Secrets    map[string]string      `json:"secrets"`
	Cache      map[string]cacheRecord `json:"cache"`
	Roles      []roleJSON             `json:"roles"`
	State      map[string]any         `json:"state"`
	Hostname   string                 `json:"hostname"`
}

type wireResponse struct {
	Commands []command `json:"commands"`
	Logs     []string  `json:"logs"`
	Error    *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// unit is one Action to run: a pinned deployed version, or a draft.
type unit struct {
	name, actionID, versionKey, code, buildID string
	secrets                                   []store.ActionSecret
}

// flow is one trigger execution in progress.
type flow struct {
	tenantID, trigger, handler, hostname string
	units                                []unit
	roles                                []roleJSON
	acc                                  *accum
	event                                func() map[string]any
	cache                                *actionCache
	deadline                             time.Time
	input                                *PostLoginInput
	redirectCount, position              int
	state                                string
	remaining                            time.Duration
}

// stepOut is what one Action produced, masked.
type stepOut struct {
	commands []command
	logs     []string
	red      *customdb.Redactor
}

func handlerFor(trigger string) string {
	if trigger == TriggerCredentialsExchange {
		return "onExecuteCredentialsExchange"
	}
	return "onExecutePostLogin"
}

// PostLogin runs the tenant's post-login flow.
func (e *Engine) PostLogin(ctx context.Context, in PostLoginInput) (*Result, error) {
	tenantID := in.Tenant.Tenant.ID
	bound, err := e.Store.Actions().Bindings(ctx, tenantID, TriggerPostLogin)
	if err != nil {
		return nil, e.unrecorded(tenantID, TriggerPostLogin, err)
	}
	if len(bound) == 0 {
		return &Result{}, nil
	}
	if in.Prepare != nil {
		if err := in.Prepare(ctx, &in); err != nil {
			return nil, e.unrecorded(tenantID, TriggerPostLogin, err)
		}
	}
	// event.transaction.id names this login; a redirect's sealed input keeps it.
	if in.Transaction.ID == "" {
		in.Transaction.ID = secrets.RandomString(24)
	}
	var roles []roleJSON
	if in.User != nil {
		if roles, err = e.roleSnapshot(ctx, tenantID, in.User.UserID); err != nil {
			return nil, e.unrecorded(tenantID, TriggerPostLogin, err)
		}
	}
	names := make([]string, len(roles))
	for i, r := range roles {
		names[i] = r.Name
	}
	f := &flow{tenantID: tenantID, trigger: TriggerPostLogin, handler: handlerFor(TriggerPostLogin), hostname: in.Tenant.Host,
		units: pinned(bound), roles: roles, acc: newAccum(TriggerPostLogin, in.TargetScopes, nil, in.CanRedirect),
		cache: e.caches.get(tenantID, TriggerPostLogin), input: &in}
	if in.User != nil && in.ResourceServer != nil && !in.ResourceServer.IsSystem && in.ResourceServer.EnforcePolicies {
		snapshot, err := e.Store.RBAC().Snapshot(ctx, tenantID, in.User.UserID, in.ResourceServer.Identifier)
		if err != nil {
			return nil, e.unrecorded(tenantID, TriggerPostLogin, err)
		}
		if snapshot == nil || snapshot.API == nil {
			return nil, e.unrecorded(tenantID, TriggerPostLogin, errors.New("missing RBAC snapshot"))
		}
		f.acc.eff.RBAC = &RBACSnapshot{Audience: in.ResourceServer.Identifier, Permissions: append([]string{}, snapshot.Permissions...)}
	}
	f.event = func() map[string]any { return postLoginEvent(&in, names, f.acc) }
	return e.run(ctx, f, in.User)
}

// CredentialsExchange runs the tenant's credentials-exchange flow.
func (e *Engine) CredentialsExchange(ctx context.Context, in CredentialsInput) (*Result, error) {
	tenantID := in.Tenant.Tenant.ID
	bound, err := e.Store.Actions().Bindings(ctx, tenantID, TriggerCredentialsExchange)
	if err != nil {
		return nil, e.unrecorded(tenantID, TriggerCredentialsExchange, err)
	}
	if len(bound) == 0 {
		return &Result{}, nil
	}
	f := &flow{tenantID: tenantID, trigger: TriggerCredentialsExchange, handler: handlerFor(TriggerCredentialsExchange),
		hostname: in.Tenant.Host, units: pinned(bound), acc: newAccum(TriggerCredentialsExchange, in.TargetScopes, nil, false),
		cache: e.caches.get(tenantID, TriggerCredentialsExchange)}
	f.event = func() map[string]any { return credentialsEvent(&in, f.acc) }
	return e.run(ctx, f, nil)
}

// unrecorded fails a flow that could not start (no execution record).
func (e *Engine) unrecorded(tenantID, trigger string, err error) error {
	e.log().Warn("actions flow failed before it started", "tenant", tenantID, "trigger", trigger, "error", err)
	return &ErrFlow{Cause: err}
}

// pinned turns one Bindings snapshot into the flow's fixed Action list.
func pinned(bound []store.BoundVersion) []unit {
	out := make([]unit, len(bound))
	for i, b := range bound {
		out[i] = unit{name: b.Action.Name, actionID: b.Action.ID, versionKey: b.Version.ID, code: b.Version.Code,
			buildID: b.Version.BuildID, secrets: b.Version.Secrets}
	}
	return out
}

// roleSnapshot reads the user's direct roles once (Plan 26 store).
func (e *Engine) roleSnapshot(ctx context.Context, tenantID, userID string) ([]roleJSON, error) {
	out := []roleJSON{}
	for page := 0; page < 1000; page++ {
		res, err := e.Store.RBAC().UserRoles(ctx, tenantID, userID, store.RBACPage{Page: page, PerPage: 100})
		if errors.Is(err, store.ErrNotFound) {
			return []roleJSON{}, nil
		}
		if err != nil {
			return nil, err
		}
		for _, r := range res.Items {
			out = append(out, roleJSON{ID: r.ID, Name: r.Name, Description: r.Description})
		}
		if len(res.Items) == 0 || len(out) >= res.Total {
			break
		}
	}
	return out, nil
}

// errorID classifies a failure for the execution record.
func errorID(err error) string {
	switch {
	case errors.Is(err, ErrUnsupported):
		return "unsupported_api"
	case errors.Is(err, ErrInvalidCommand):
		return "invalid_api_call"
	case errors.Is(err, ErrRedirectNotAllowed):
		return "redirect_not_allowed"
	case errors.Is(err, ErrTimeout):
		return "timeout"
	case errors.Is(err, ErrClaimsTooLarge):
		return "claims_too_large"
	case errors.Is(err, ErrActionError):
		return "runtime_error"
	case errors.Is(err, build.ErrNotBuilt), errors.Is(err, build.ErrCorruptArtifact):
		return "build_error"
	}
	return "internal_error"
}

// run executes f's Actions in order, then commits metadata and writes the
// execution record. Any failure fails the whole flow closed.
func (e *Engine) run(ctx context.Context, f *flow, user *store.User) (*Result, error) {
	execID := newExecutionID()
	budget := f.remaining
	if budget == 0 {
		budget = e.budget()
	}
	f.deadline = time.Now().Add(budget)
	fctx, cancel := context.WithDeadline(ctx, f.deadline)
	defer cancel()
	ex := &store.Execution{TenantID: f.tenantID, ID: execID, Trigger: f.trigger, Status: "final", CreatedAt: e.now()}
	var failure error
	failed := ""
	for i, u := range f.units {
		started := e.now()
		_, err := e.step(fctx, f, u, f.event())
		r := store.ExecutionResult{ActionName: u.name, StartedAt: started, EndedAt: e.now()}
		if err != nil {
			r.ErrorID, r.ErrorMsg = errorID(err), err.Error()
			failure, failed = err, u.name
		}
		ex.Results = append(ex.Results, r)
		if failure == nil && f.acc.denied == nil && f.acc.redirect != nil {
			f.remaining = time.Until(f.deadline)
			var redirect *Redirect
			err := e.Store.WithTx(fctx, func(tx store.Store) error {
				var err error
				redirect, err = e.suspend(fctx, tx, f, i)
				if err != nil {
					return err
				}
				ex.Status, ex.UpdatedAt = "suspended", e.now()
				return tx.Actions().CreateExecution(fctx, ex)
			})
			if err == nil {
				return &Result{Redirect: redirect, ExecutionID: execID, Continuation: continuationOf(f)}, nil
			}
			ex.Status = "final"
			failure, failed = err, u.name
			ex.Results[len(ex.Results)-1].ErrorID = errorID(err)
			ex.Results[len(ex.Results)-1].ErrorMsg = err.Error()
		}
		// Only the redirecting Action resumes onContinuePostLogin; the tail
		// always starts with onExecutePostLogin.
		f.handler = handlerFor(f.trigger)
		if failure != nil || f.acc.denied != nil {
			break
		}
	}
	ex.UpdatedAt = e.now()
	// Metadata commits at flow end on success, deny or validation.error and
	// is discarded on failure (spec §6), atomically with the execution
	// record. The record is written even when the flow's deadline passed.
	wctx, wcancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer wcancel()
	var commitErr, recordErr error
	if failure == nil && hasMetadata(user, &f.acc.eff) {
		recordErr = e.Store.WithTx(wctx, func(tx store.Store) error {
			if commitErr = e.commitMetadata(wctx, tx, f.tenantID, user, &f.acc.eff); commitErr != nil {
				return commitErr
			}
			return tx.Actions().CreateExecution(wctx, ex)
		})
	} else {
		recordErr = e.Store.Actions().CreateExecution(wctx, ex)
	}
	switch {
	case commitErr != nil:
		// The transaction rolled back: record the flow as failed instead.
		failure = fmt.Errorf("actions: committing metadata: %w", commitErr)
		last := &ex.Results[len(ex.Results)-1]
		last.ErrorID, last.ErrorMsg = "internal_error", "the flow's metadata could not be committed"
		failed = last.ActionName
		if err := e.Store.Actions().CreateExecution(wctx, ex); err != nil {
			e.log().Warn("actions: recording a failed execution", "tenant", f.tenantID, "execution_id", execID, "error", err)
		}
	case recordErr != nil && failure == nil:
		failure = fmt.Errorf("actions: recording the execution: %w", recordErr)
	case recordErr != nil:
		e.log().Warn("actions: recording a failed execution", "tenant", f.tenantID, "execution_id", execID, "error", recordErr)
	}
	if failure != nil {
		e.log().Warn("actions flow failed", "tenant", f.tenantID, "trigger", f.trigger, "action", failed,
			"execution_id", execID, "error", failure.Error())
		return nil, &ErrFlow{ExecutionID: execID, Cause: failure, Continuation: continuationOf(f)}
	}
	if d := f.acc.denied; d != nil {
		e.log().Info("actions flow denied", "tenant", f.tenantID, "trigger", f.trigger,
			"action", ex.Results[len(ex.Results)-1].ActionName, "execution_id", execID, "code", d.Code)
	}
	return &Result{Effects: f.acc.eff, Denied: f.acc.denied, ExecutionID: execID, Continuation: continuationOf(f)}, nil
}

func hasMetadata(user *store.User, eff *Effects) bool {
	return user != nil && (len(eff.AppMetadata) > 0 || len(eff.UserMetadata) > 0)
}

// commitMetadata merges the flow's metadata into the user through the
// PATCH /api/v2/users/{id} rules, inside the caller's transaction tx.
func (e *Engine) commitMetadata(ctx context.Context, tx store.Store, tenantID string, user *store.User, eff *Effects) error {
	patch := metadataPatch(eff)
	for _, m := range []struct {
		name string
		v    userrules.Metadata
	}{{"user_metadata", patch.UserMetadata}, {"app_metadata", patch.AppMetadata}} {
		if err := userrules.CheckMetadata(m.name, m.v.Value); err != nil {
			return err
		}
	}
	cur, err := tx.Users().GetForUpdate(ctx, tenantID, user.UserID)
	if err != nil {
		return err
	}
	userrules.ApplyPatch(cur, patch)
	cur.UpdatedAt = e.now()
	return tx.Users().Update(ctx, cur)
}

// step runs one Action and applies its commands to f.acc. Its errors are
// masked with the Action's secrets.
func (e *Engine) step(ctx context.Context, f *flow, u unit, event map[string]any) (*stepOut, error) {
	remaining := time.Until(f.deadline)
	if remaining <= 0 {
		return nil, ErrTimeout
	}
	root, err := e.Builds.Ensure(ctx, f.tenantID, u.buildID)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ErrTimeout
		}
		return nil, fmt.Errorf("actions: dependencies of %q: %w", u.name, err)
	}
	vals := make(map[string]string, len(u.secrets))
	for _, s := range u.secrets {
		v, err := keys.OpenActionSecret(e.Secrets, f.tenantID, u.actionID, s.Name, s.Sealed)
		if err != nil {
			return nil, fmt.Errorf("actions: secret %q of %q does not open", s.Name, u.name)
		}
		vals[s.Name] = v
	}
	// Ensure may have waited on a build lock past the deadline; dispatching
	// now would hit the runner's watchdog and kill the tenant's process.
	if ctx.Err() != nil || time.Until(f.deadline) <= 0 {
		return nil, ErrTimeout
	}
	red := customdb.NewRedactor(vals)
	req := wireRequest{VersionKey: u.versionKey, Code: u.code, DepsRoot: root, Handler: f.handler, Event: event,
		Secrets: vals, Cache: f.cache.snapshot(e.now()), Roles: f.roles,
		State: map[string]any{"canRedirect": f.acc.canRedirect, "state": f.state}, Hostname: f.hostname}
	if req.Roles == nil {
		req.Roles = []roleJSON{}
	}
	raw, err := e.Runner.CallWith(ctx, f.tenantID, req, noderunner.CallOptions{
		// At least 1 ms: a zero Budget would mean the Pool's 20 s default.
		Budget: max(time.Until(f.deadline), time.Millisecond),
		Prepare: func(state any) {
			if ps, ok := state.(*procState); ok {
				ps.add(red)
			}
		},
		LogAttrs: []any{"action", u.name},
	})
	switch {
	case errors.Is(err, noderunner.ErrTimeout), err != nil && ctx.Err() != nil:
		return nil, ErrTimeout
	case err != nil:
		return nil, fmt.Errorf("actions: runner: %w", err)
	}
	var resp wireResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("actions: invalid runner response")
	}
	out := &stepOut{commands: resp.Commands, logs: red.RedactAll(resp.Logs), red: red}
	// An unsupported call fails the flow even when the Action caught it.
	for _, c := range resp.Commands {
		if c.Op == "unsupported" {
			err := f.acc.apply(c)
			return out, &maskedError{msg: red.RedactLine(err.Error()), err: err}
		}
	}
	if resp.Error != nil {
		return out, fmt.Errorf("%w: %s", ErrActionError, red.RedactLine(resp.Error.Message))
	}
	f.acc.cache = nil
	for _, c := range resp.Commands {
		if err := f.acc.apply(c); err != nil {
			return out, &maskedError{msg: red.RedactLine(err.Error()), err: err}
		}
	}
	// Oversized claims fail at the Action that made them (spec §7).
	for _, m := range []map[string]any{f.acc.eff.AccessClaims, f.acc.eff.IDClaims} {
		if err := checkClaimsSize(m); err != nil {
			return out, err
		}
	}
	f.cache.apply(e.now(), f.acc.cache)
	f.acc.cache = nil
	return out, nil
}

// maskedError keeps a cause for errors.Is with its message masked.
type maskedError struct {
	msg string
	err error
}

func (m *maskedError) Error() string { return m.msg }
func (m *maskedError) Unwrap() error { return m.err }

// testCommand is a recorded command in a test response.
type testCommand struct {
	Op   string            `json:"op"`
	Args []json.RawMessage `json:"args"`
}

// testError is the error of a test run.
type testError struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// testOutput is the test endpoint's payload (spec §4): what the draft
// recorded, its console output and error, and its duration.
type testOutput struct {
	Commands   []testCommand `json:"commands"`
	Logs       []string      `json:"logs"`
	Error      *testError    `json:"error,omitempty"`
	DurationMS int64         `json:"duration_ms"`
	// ExecutionID references this run only; no record is written.
	ExecutionID string `json:"execution_id"`
}

// Test runs an Action's built draft once against payload (its event) as a
// dry run: commands, redirects and denials are recorded, not applied; the
// cache is a throwaway one; fetch is real; nothing is written. api.roles
// reads the tenant user's real roles when payload.user.user_id exists.
// ErrActionNotFound and ErrDraftNotBuilt report a request the caller must
// refuse; the Action's own failure is reported in the payload. Secret
// values are masked everywhere in the payload.
func (e *Engine) Test(ctx context.Context, tenantID, actionID string, payload json.RawMessage) (json.RawMessage, error) {
	a, err := e.Store.Actions().GetAction(ctx, tenantID, actionID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrActionNotFound
	}
	if err != nil {
		return nil, err
	}
	b, err := e.Store.Actions().GetBuild(ctx, tenantID, a.DraftBuildID)
	if errors.Is(err, store.ErrNotFound) || err == nil && b.Status != store.BuildBuilt {
		return nil, ErrDraftNotBuilt
	}
	if err != nil {
		return nil, err
	}
	event := map[string]any{}
	if len(payload) > 0 && string(payload) != "null" {
		if err := json.Unmarshal(payload, &event); err != nil || event == nil {
			return nil, ErrInvalidPayload
		}
	}
	roles := []roleJSON{}
	if u, ok := event["user"].(map[string]any); ok {
		if id, ok := u["user_id"].(string); ok && id != "" {
			if roles, err = e.roleSnapshot(ctx, tenantID, id); err != nil {
				return nil, err
			}
		}
	}
	authz, _ := event["authorization"].(map[string]any)
	if authz == nil {
		authz = map[string]any{}
		event["authorization"] = authz
	}
	if _, ok := authz["roles"]; !ok {
		names := make([]string, len(roles))
		for i, r := range roles {
			names[i] = r.Name
		}
		authz["roles"] = names
	}
	var target []string
	if txn, ok := event["transaction"].(map[string]any); ok {
		if ts, ok := txn["target_scopes"].([]any); ok {
			for _, s := range ts {
				if str, ok := s.(string); ok {
					target = append(target, str)
				}
			}
		}
	}
	f := &flow{tenantID: tenantID, trigger: a.Trigger, handler: handlerFor(a.Trigger), roles: roles,
		acc:   newAccum(a.Trigger, target, nil, a.Trigger == TriggerPostLogin),
		cache: newActionCache(), deadline: time.Now().Add(e.budget())}
	if t, err := e.Store.Tenants().Get(ctx, tenantID); err == nil {
		f.hostname = t.CanonicalHost
	}
	fctx, cancel := context.WithDeadline(ctx, f.deadline)
	defer cancel()
	start := time.Now()
	u := unit{name: a.Name, actionID: a.ID, versionKey: "draft:" + a.ID, code: a.Code, buildID: a.DraftBuildID, secrets: a.Secrets}
	st, err := e.step(fctx, f, u, event)
	if errors.Is(err, build.ErrNotBuilt) {
		return nil, ErrDraftNotBuilt
	}
	if err != nil && st == nil && !errors.Is(err, ErrTimeout) && !errors.Is(err, build.ErrCorruptArtifact) {
		return nil, err
	}
	out := testOutput{Commands: []testCommand{}, Logs: []string{}, DurationMS: time.Since(start).Milliseconds(), ExecutionID: newExecutionID()}
	var red *customdb.Redactor
	if st != nil {
		red = st.red
		out.Logs = append(out.Logs, st.logs...)
		for _, c := range st.commands {
			out.Commands = append(out.Commands, testCommand(c))
		}
	}
	if err != nil {
		out.Error = &testError{ID: errorID(err), Message: err.Error()}
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return red.RedactJSON(raw), nil
}

// PurgeExecutions deletes execution records older than the 10-day
// retention; the jobs worker runs it periodically.
func PurgeExecutions(ctx context.Context, st store.Store, now time.Time) (int, error) {
	days := actionsrules.Inventory().Limits["execution_retention_days"]
	return st.Actions().PurgeExecutions(ctx, now.Add(-time.Duration(days)*24*time.Hour))
}

func newExecutionID() string { return "exe_" + secrets.RandomString(24) }
