package mgmt_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (e *usersEnv) actionJobs(t *testing.T) []store.ActionJob {
	t.Helper()
	jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
	if err != nil {
		t.Fatal(err)
	}
	return jobs
}

// PATCH /users/{id} with a password records last_password_reset and queues
// post-change-password with the change; the Action's outcome is not the
// response's.
func TestPostChangePasswordManagement(t *testing.T) {
	e := newUsersEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	ae.Bind(t, e.tn.ID, actions.TriggerPostChangePassword, ae.Deploy(t, e.tn.ID, actions.TriggerPostChangePassword, "pcp",
		`exports.onExecutePostChangePassword=(event)=>{throw Error('pcp '+event.user.user_id+' '+event.connection.name+' '+(event.request.body.password===undefined));};`))
	id := e.mustCreate(t, map[string]any{"email": "pw@x.test"})["user_id"].(string)
	if jobs := e.actionJobs(t); len(jobs) != 0 {
		t.Fatalf("create queued %+v", jobs)
	}
	// Other fields queue nothing.
	if rec, _ := e.patch(t, id, map[string]any{"name": "Renamed"}); rec.Code != 200 {
		t.Fatalf("patch name = %d %s", rec.Code, rec.Body)
	}
	if jobs := e.actionJobs(t); len(jobs) != 0 {
		t.Fatalf("name patch queued %+v", jobs)
	}
	if u, _ := e.st.Users().Get(context.Background(), e.tn.ID, id); u.LastPasswordReset != nil {
		t.Fatalf("name patch set last_password_reset %v", u.LastPasswordReset)
	}
	if rec, _ := e.patch(t, id, map[string]any{"password": "another horse 2"}); rec.Code != 200 {
		t.Fatalf("patch password = %d %s", rec.Code, rec.Body)
	}
	u, err := e.st.Users().Get(context.Background(), e.tn.ID, id)
	if err != nil || u.LastPasswordReset == nil || !u.LastPasswordReset.Equal(u.UpdatedAt) {
		t.Fatalf("user %+v %v", u, err)
	}
	jobs := e.actionJobs(t)
	if len(jobs) != 1 || jobs[0].Trigger != actions.TriggerPostChangePassword {
		t.Fatalf("jobs %+v", jobs)
	}
	if got := ae.Engine.RunJob(context.Background(), &jobs[0]); got == nil || got.Status != "failed" {
		t.Fatalf("job %+v", got)
	}
	if want := "pcp " + id + " " + dbConn + " true"; !strings.Contains(ae.Logs.String(), want) {
		t.Fatalf("event logs lack %q: %s", want, ae.Logs)
	}
}

// A custom database change_password that reports no change queues nothing.
func TestPostChangePasswordManagementCustomDBNotChanged(t *testing.T) {
	e := newUsersEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	ae.Bind(t, e.tn.ID, actions.TriggerPostChangePassword, ae.Deploy(t, e.tn.ID, actions.TriggerPostChangePassword, "pcp", `exports.onExecutePostChangePassword=()=>{};`))
	changed := false
	conn, _ := e.legacy(t, "Legacy-Db", false, map[string]func([]any) (any, error){
		store.ScriptChangePassword: func([]any) (any, error) { return changed, nil },
	})
	id := e.legacyUser(t, conn, "L9", "legacy@x.test")
	if rec, _ := e.patch(t, id, map[string]any{"password": "another horse 2"}); rec.Code != 400 {
		t.Fatalf("not changed = %d %s", rec.Code, rec.Body)
	}
	if jobs := e.actionJobs(t); len(jobs) != 0 {
		t.Fatalf("not changed queued %+v", jobs)
	}
	changed = true
	if rec, _ := e.patch(t, id, map[string]any{"password": "another horse 2"}); rec.Code != 200 {
		t.Fatalf("changed = %d %s", rec.Code, rec.Body)
	}
	if jobs := e.actionJobs(t); len(jobs) != 1 {
		t.Fatalf("changed jobs %+v", jobs)
	}
}
