package jobs

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// Bulk imports bypass signup Actions and do not enqueue post-registration work.
func TestSignupPostRegistrationImportBypass(t *testing.T) {
	e := newImpEnv(t, memory.New())
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	ae := actionstest.NewOffline(t, e.st, w)
	ae.Bind(t, impTenant, actions.TriggerPreUserRegistration, ae.Deploy(t, impTenant, actions.TriggerPreUserRegistration, "deny", `exports.onExecutePreUserRegistration=(event,api)=>api.access.deny('no','Denied');`))
	ae.Bind(t, impTenant, actions.TriggerPostUserRegistration, ae.Deploy(t, impTenant, actions.TriggerPostUserRegistration, "post", `exports.onExecutePostUserRegistration=()=>{throw Error('must not run')};`))
	e.newJob(fileOf(t, []any{map[string]any{"email": "import@x.test"}}), nil)
	j, lease := e.claim("worker")
	counts := &actionstest.Counts{}
	st := actionstest.CountingStore{Store: e.st, Counts: counts}
	got, errs := e.finish(e.importer(), st, j, lease)
	if got.Status != store.JobCompleted || len(errs) != 0 {
		t.Fatalf("import %+v %v", got, errs)
	}
	if _, err := e.st.Users().FindByLogin(context.Background(), impTenant, impConn, "import@x.test"); err != nil {
		t.Fatal(err)
	}
	if counts.Snapshot()["Actions.Bindings"] != 0 || counts.Snapshot()["Actions.CreateExecution"] != 0 {
		t.Fatalf("import ran signup hooks %v", counts.Snapshot())
	}
	jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("import jobs %v %v", jobs, err)
	}
}
