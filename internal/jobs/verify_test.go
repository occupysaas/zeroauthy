package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type fakeSender struct {
	calls []string
	err   error
}

func (f *fakeSender) SendVerification(_ context.Context, _ string, u *store.User, clientID string) error {
	f.calls = append(f.calls, u.UserID+"/"+clientID)
	return f.err
}

func TestVerifyEmail(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Users().Create(ctx, &store.User{TenantID: "t1", UserID: "auth0|u1", Email: "a@example.test"}); err != nil {
		t.Fatal(err)
	}
	job := func(user string) *store.Job {
		return &store.Job{TenantID: "t1", ID: "job_x", Params: map[string]any{"user_id": user, "client_id": "app"}}
	}
	s := &fakeSender{}
	status, details, err := VerifyEmail{Sender: s}.Run(ctx, st, job("auth0|u1"), nil)
	if status != store.JobCompleted || details != "" || err != nil || len(s.calls) != 1 || s.calls[0] != "auth0|u1/app" {
		t.Errorf("run = %v %q %v, calls %v", status, details, err, s.calls)
	}
	if status, _, err := (VerifyEmail{Sender: s}).Run(ctx, st, job("auth0|gone"), nil); status != store.JobFailed || err != nil || len(s.calls) != 1 {
		t.Errorf("deleted user: %v %v, calls %v", status, err, s.calls)
	}
	s.err = errors.New("smtp down")
	if _, _, err := (VerifyEmail{Sender: s}).Run(ctx, st, job("auth0|u1"), nil); err == nil {
		t.Error("a send error was swallowed")
	}
	if status, _, err := (VerifyEmail{}).Run(ctx, st, job("auth0|u1"), nil); status != store.JobCompleted || err != nil {
		t.Errorf("no sender: %v %v", status, err)
	}
}
