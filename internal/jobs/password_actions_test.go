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

// Bulk imports that set password hashes do not fire post-change-password.
func TestPostChangePasswordImportBypass(t *testing.T) {
	e := newImpEnv(t, memory.New())
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{6}, 32))
	ae := actionstest.NewOffline(t, e.st, w)
	ae.Bind(t, impTenant, actions.TriggerPostChangePassword, ae.Deploy(t, impTenant, actions.TriggerPostChangePassword, "pcp", `exports.onExecutePostChangePassword=()=>{throw Error('must not run')};`))
	e.mustCreate(&store.User{UserID: "auth0|hashless", Email: "hashless@x.test",
		Identities: []store.Identity{{Connection: impConn, Provider: "auth0", UserID: "hashless"}}})
	records := []any{
		map[string]any{"email": "fresh@x.test", "password_hash": bcryptHash},
		map[string]any{"email": "hashless@x.test", "password_hash": bcryptHash},
	}
	j, errs := e.run(e.importer(), fileOf(t, records), map[string]any{ParamUpsert: true, ParamSendCompletionEmail: false})
	if j.Status != store.JobCompleted || len(errs) != 0 || j.Summary.Inserted != 1 || j.Summary.Updated != 1 {
		t.Fatalf("import %+v %v", j, errs)
	}
	for _, email := range []string{"fresh@x.test", "hashless@x.test"} {
		if u := e.user(email); u.LastPasswordReset != nil {
			t.Fatalf("%s last_password_reset %v", email, u.LastPasswordReset)
		}
	}
	jobs, err := e.st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Hour), time.Minute, 10)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("import jobs %v %v", jobs, err)
	}
}
