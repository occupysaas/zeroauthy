package dbconn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func signupActions(t *testing.T, e *env, code string) *actionstest.Env {
	t.Helper()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	a := actionstest.NewOffline(t, e.st, w)
	if code != "" {
		a.Bind(t, e.tenantID, actions.TriggerPreUserRegistration, a.Deploy(t, e.tenantID, actions.TriggerPreUserRegistration, "pre", code))
	}
	e.h.Actions = a.Engine
	return a
}

// Missing registration hooks would accept denied signups and lose metadata.
func TestSignupPreRegistration(t *testing.T) {
	for _, tc := range []struct {
		name, code     string
		status         int
		wantCode, desc string
	}{
		{"metadata", `api.user.setUserMetadata('plan','action'); api.user.setAppMetadata('tier','paid');`, 200, "", ""},
		{"deny", `api.access.deny('operator reason','Inscription refusée');`, 400, "extensibility_error", "Inscription refusée"},
		{"validation", `api.validation.error('bad_signup','Profil refusé');`, 400, "bad_signup", "Profil refusé"},
		{"validation_access_denied", `api.validation.error('access_denied','Profil refusé');`, 400, "access_denied", "Profil refusé"},
		{"throw", `throw new Error('PRIVATE-secret');`, 400, "extensibility_error", "Unable to complete signup."},
		{"unsupported", `try { api.user.setUserId('custom'); } catch (_) {}`, 400, "extensibility_error", "Unable to complete signup."},
		{"invalid_metadata", `api.user.setAppMetadata('$bad',true);`, 400, "extensibility_error", "Unable to complete signup."},
		{"timeout", `while(true){}`, 400, "extensibility_error", "Unable to complete signup."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.strict = false
			a := signupActions(t, e, `exports.onExecutePreUserRegistration = (event,api) => { if(event.user.user_id || event.request.body.password || event.transaction) throw Error('bad event'); `+tc.code+` };`)
			if tc.name == "timeout" {
				a.Engine.FlowBudget = 100 * time.Millisecond
			}
			post := a.Deploy(t, e.tenantID, actions.TriggerPostUserRegistration, "post", `exports.onExecutePostUserRegistration=()=>{};`)
			a.Bind(t, e.tenantID, actions.TriggerPostUserRegistration, post)
			status, body, raw := e.post(t, "/dbconnections/signup", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"signup@acme.test","password":"a good password 1"}`)
			if status != tc.status {
				t.Fatalf("status %d: %s", status, raw)
			}
			u, err := e.st.Users().FindByLogin(context.Background(), e.tenantID, "Username-Password-Authentication", "signup@acme.test")
			if tc.status == 200 {
				if err != nil || u.UserMetadata["plan"] != "action" || u.AppMetadata["tier"] != "paid" {
					t.Fatalf("metadata: %+v %v", u, err)
				}
			} else {
				if body["name"] != "ExtensibilityError" || body["code"] != tc.wantCode || body["description"] != tc.desc || body["statusCode"] != float64(400) || strings.Contains(raw, "PRIVATE") {
					t.Fatalf("body: %s", raw)
				}
				if !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("denied user: %+v %v", u, err)
				}
				jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 100)
				if err != nil || len(jobs) != 0 {
					t.Fatalf("denied jobs: %v %v", jobs, err)
				}
			}
		})
	}
}

// Post-registration must snapshot the committed user and fail independently.
func TestSignupPostRegistration(t *testing.T) {
	e := newEnv(t)
	a := signupActions(t, e, "")
	a.Bind(t, e.tenantID, actions.TriggerPostUserRegistration, a.Deploy(t, e.tenantID, actions.TriggerPostUserRegistration, "post", `exports.onExecutePostUserRegistration=(event)=>{ if(!event.user.user_id || event.request.body.password) throw Error('invalid snapshot'); throw Error('later failure'); };`))
	status, _, raw := e.post(t, "/dbconnections/signup", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"post@acme.test","password":"a good password 1"}`)
	if status != 200 {
		t.Fatalf("signup %d %s", status, raw)
	}
	jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs %+v %v", jobs, err)
	}
	if u, err := e.st.Users().FindByLogin(context.Background(), e.tenantID, "Username-Password-Authentication", "post@acme.test"); err != nil || u.UserID == "" {
		t.Fatalf("committed user %v %v", u, err)
	}
	done := a.Engine.RunJob(context.Background(), &jobs[0])
	if done == nil || done.Status != "failed" || len(done.ExecutionIDs) != 1 {
		t.Fatalf("post outcome %+v", done)
	}
	ex, err := e.st.Actions().GetExecution(context.Background(), e.tenantID, done.ExecutionIDs[0])
	if err != nil || len(ex.Results) != 1 || !strings.Contains(ex.Results[0].ErrorMsg, "later failure") {
		t.Fatalf("post snapshot failed incorrectly: %+v %v", ex, err)
	}
}

func TestSignupPreRegistrationLegacy(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		status     int
	}{
		{"metadata", `api.user.setUserMetadata('plan','action');api.user.setAppMetadata('tier','paid');`, 200},
		{"deny", `api.access.deny('private','Refusé');`, 400},
		{"throw", `throw Error('PRIVATE-secret');`, 400},
		{"unsupported", `try {api.user.setUserId('custom')} catch (_) {}`, 400},
		{"timeout", `while(true){}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			a := signupActions(t, e, `exports.onExecutePreUserRegistration=(event,api)=>{`+tc.code+`};`)
			if tc.name == "timeout" {
				a.Engine.FlowBudget = 100 * time.Millisecond
			}
			a.Bind(t, e.tenantID, actions.TriggerPostUserRegistration, a.Deploy(t, e.tenantID, actions.TriggerPostUserRegistration, "post", `exports.onExecutePostUserRegistration=()=>{};`))
			var created map[string]any
			e.scripts.Funcs[store.ScriptGetUser] = func([]any) (any, error) { return nil, nil }
			e.scripts.Funcs[store.ScriptCreate] = func(args []any) (any, error) { created = args[0].(map[string]any); return nil, nil }
			e.scripts.Funcs[store.ScriptLogin] = func([]any) (any, error) {
				return map[string]any{"user_id": "legacy-signup", "email": "legacy-action@acme.test", "user_metadata": map[string]any{"script": "yes"}}, nil
			}
			status, _, raw := e.post(t, "/dbconnections/signup", "application/json", `{"client_id":"app","connection":"Legacy-DB","email":"legacy-action@acme.test","password":"a good password 1","user_metadata":{"submitted":"yes"}}`)
			if status != tc.status {
				t.Fatalf("signup %d %s", status, raw)
			}
			u, err := e.st.Users().FindByLogin(context.Background(), e.tenantID, "Legacy-DB", "legacy-action@acme.test")
			if tc.status == 200 {
				if created == nil || created["app_metadata"] != nil || created["user_metadata"].(map[string]any)["plan"] != "action" {
					t.Fatalf("legacy create %v", created)
				}
				if err != nil || u.AppMetadata["tier"] != "paid" || u.UserMetadata["plan"] != "action" {
					t.Fatalf("legacy stored %+v %v", u, err)
				}
			} else {
				if created != nil || !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("failed legacy created=%v stored=%v err=%v", created, u, err)
				}
				jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
				if err != nil || len(jobs) != 0 {
					t.Fatalf("failed legacy jobs %v %v", jobs, err)
				}
			}
		})
	}
}

func TestSignupPreRegistrationDuplicate(t *testing.T) {
	e := newEnv(t)
	a := signupActions(t, e, `exports.onExecutePreUserRegistration=(event,api)=>{api.user.setAppMetadata('should_not_persist',true);};`)
	a.Bind(t, e.tenantID, actions.TriggerPostUserRegistration, a.Deploy(t, e.tenantID, actions.TriggerPostUserRegistration, "post", `exports.onExecutePostUserRegistration=()=>{};`))
	status, body, raw := e.post(t, "/dbconnections/signup", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"alice@acme.test","password":"a good password 1"}`)
	if status != 409 || body["error"] != "user_exists" {
		t.Fatalf("duplicate %d %s", status, raw)
	}
	u, _ := e.st.Users().FindByLogin(context.Background(), e.tenantID, "Username-Password-Authentication", "alice@acme.test")
	if u.AppMetadata["should_not_persist"] != nil {
		t.Fatalf("duplicate metadata %+v", u)
	}
	jobs, _ := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
	if len(jobs) != 0 {
		t.Fatalf("duplicate jobs %v", jobs)
	}
}

func TestSignupPostRegistrationPendingCap(t *testing.T) {
	e := newEnv(t)
	a := signupActions(t, e, "")
	a.Bind(t, e.tenantID, actions.TriggerPostUserRegistration, a.Deploy(t, e.tenantID, actions.TriggerPostUserRegistration, "post", `exports.onExecutePostUserRegistration=()=>{};`))
	ctx := context.Background()
	now := time.Now()
	for i := 0; i < actionsrules.Inventory().Limits["job_pending_per_tenant"]; i++ {
		if err := e.st.Actions().EnqueueJob(ctx, &store.ActionJob{TenantID: e.tenantID, ID: fmt.Sprintf("existing-%d", i), Trigger: actions.TriggerPostUserRegistration, Status: "pending", NextAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	status, _, raw := e.post(t, "/dbconnections/signup", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"cap@acme.test","password":"a good password 1"}`)
	if status != 200 || !strings.Contains(e.logs.String(), "job dropped") {
		t.Fatalf("cap %d %s logs=%s", status, raw, e.logs)
	}
	if _, err := e.st.Users().FindByLogin(ctx, e.tenantID, "Username-Password-Authentication", "cap@acme.test"); err != nil {
		t.Fatalf("cap user %v", err)
	}
}

type rollbackSignupStore struct{ store.Store }

func (s rollbackSignupStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error {
		if err := fn(tx); err != nil {
			return err
		}
		return errors.New("injected commit failure")
	})
}

func TestSignupPostRegistrationRollback(t *testing.T) {
	e := newEnv(t)
	a := signupActions(t, e, "")
	a.Bind(t, e.tenantID, actions.TriggerPostUserRegistration, a.Deploy(t, e.tenantID, actions.TriggerPostUserRegistration, "post", `exports.onExecutePostUserRegistration=()=>{};`))
	e.h.Database.Store = rollbackSignupStore{e.st}
	status, _, raw := e.post(t, "/dbconnections/signup", "application/json", `{"client_id":"app","connection":"Username-Password-Authentication","email":"rollback@acme.test","password":"a good password 1"}`)
	if status != 500 {
		t.Fatalf("rollback response %d %s", status, raw)
	}
	if _, err := e.st.Users().FindByLogin(context.Background(), e.tenantID, "Username-Password-Authentication", "rollback@acme.test"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rollback user %v", err)
	}
	jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("rollback jobs %v %v", jobs, err)
	}
}
