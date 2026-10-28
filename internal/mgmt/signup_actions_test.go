package mgmt_test

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
)

// Management creates bypass registration hooks even when the tenant binds a deny.
func TestSignupPostRegistrationManagementBypass(t *testing.T) {
	e := newUsersEnv(t)
	ae := actionstest.NewOffline(t, e.st, e.w)
	e.h.Actions = ae.Engine
	ae.Bind(t, e.tn.ID, actions.TriggerPreUserRegistration, ae.Deploy(t, e.tn.ID, actions.TriggerPreUserRegistration, "deny", `exports.onExecutePreUserRegistration=(event,api)=>api.access.deny('no','Denied');`))
	ae.Bind(t, e.tn.ID, actions.TriggerPostUserRegistration, ae.Deploy(t, e.tn.ID, actions.TriggerPostUserRegistration, "post", `exports.onExecutePostUserRegistration=()=>{throw Error('must not run')};`))
	counts := &actionstest.Counts{}
	e.h.Store = actionstest.CountingStore{Store: e.st, Counts: counts}
	out := e.mustCreate(t, map[string]any{"email": "management@x.test"})
	if out["email"] != "management@x.test" {
		t.Fatalf("created %v", out)
	}
	if counts.Snapshot()["Actions.Bindings"] != 0 || counts.Snapshot()["Actions.CreateExecution"] != 0 {
		t.Fatalf("management ran signup hooks %v", counts.Snapshot())
	}
	jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("management jobs %v %v", jobs, err)
	}
}
