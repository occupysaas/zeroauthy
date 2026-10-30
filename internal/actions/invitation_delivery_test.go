package actions

import (
	"bytes"
	"context"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
	"time"
)

func TestOrganizationInvitationDeliveryQueue(t *testing.T) {
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{9}, 32))
	e := &Engine{Store: st, Secrets: w}
	if err := st.Tenants().Create(context.Background(), &store.Tenant{ID: "t", Name: "queue-test"}); err != nil {
		t.Fatal(err)
	}
	err := st.WithTx(context.Background(), func(tx store.Store) error {
		return e.EnqueueInvitation(context.Background(), tx, InvitationDelivery{TenantID: "t", OrganizationID: "org_o", InvitationID: "uinv_i", ClientID: "c", InviterName: "private inviter"})
	})
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := st.Actions().ClaimJobs(context.Background(), time.Now().Add(time.Second), time.Minute, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("%v %v", jobs, err)
	}
	if bytes.Contains(jobs[0].Sealed, []byte("private inviter")) {
		t.Fatal("unsealed payload")
	}
	next := e.RunJob(context.Background(), &jobs[0])
	if next == nil || next.Status != "done" {
		t.Fatalf("missing invitation must suppress delivery: %v", next)
	}
}

func TestInvitationEmailCorruptEnvelope(t *testing.T) {
	st := memory.New()
	if err := st.Tenants().Create(context.Background(), &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{9}, 32))
	e := &Engine{Store: st, Secrets: w}
	j := &store.ActionJob{TenantID: "t", ID: "ajob_bad", Trigger: InvitationDeliveryTrigger, Status: "pending", Sealed: []byte("untrusted-private-ticket"), Attempts: 1}
	n := e.RunJob(context.Background(), j)
	if n == nil || n.Status != "failed" || len(n.ExecutionIDs) != 1 {
		t.Fatal("corrupt envelope must fail without panic or retry")
	}
	ex, err := st.Actions().GetExecution(context.Background(), "t", n.ExecutionIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range ex.Results {
		if r.ErrorMsg != "actions: invalid job envelope" {
			t.Fatal("unsafe corrupt-envelope diagnostic")
		}
	}
}
