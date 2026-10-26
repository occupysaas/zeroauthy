package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type fakeSender struct {
	calls []string
	err   error
}

func (f *fakeSender) SendVerification(_ context.Context, _ string, u *store.User, clientID, host string) error {
	f.calls = append(f.calls, u.UserID+"/"+clientID+"@"+host)
	return f.err
}

func TestVerifyEmail(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t1", Name: "t1", CanonicalHost: "t1.example.test"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().Create(ctx, &store.User{TenantID: "t1", UserID: "auth0|u1", Email: "a@example.test"}); err != nil {
		t.Fatal(err)
	}
	job := func(user string) *store.Job {
		return &store.Job{TenantID: "t1", ID: "job_x", Params: map[string]any{"user_id": user, "client_id": "app"}}
	}
	s := &fakeSender{}
	status, details, err := VerifyEmail{Sender: s}.Run(ctx, st, job("auth0|u1"), nil)
	if status != store.JobCompleted || details != "" || err != nil || len(s.calls) != 1 || s.calls[0] != "auth0|u1/app@t1.example.test" {
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

// A job sends on the domain chosen when it was created, after rechecking that
// the domain is still usable; it never falls back to another host.
func TestVerifyEmailOrigin(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t1", Name: "t1", CanonicalHost: "t1.example.test"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().Create(ctx, &store.User{TenantID: "t1", UserID: "auth0|u1", Email: "a@example.test"}); err != nil {
		t.Fatal(err)
	}
	d := &store.CustomDomain{TenantID: "t1", ID: "cd_1", Domain: "id.t1.test", Type: customdomain.TypeManaged, Generation: 1,
		Status: customdomain.StatusReady, Lifecycle: customdomain.LifecycleActive, ActiveCertificateKey: "cert/job-origin"}
	if err := st.CustomDomains().Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: d.Domain, TenantID: "t1", DomainID: d.ID, Generation: 1, Kind: store.HostPublic, Active: true}); err != nil {
		t.Fatal(err)
	}
	asset := &store.TLSAsset{Key: d.ActiveCertificateKey, Kind: store.TLSAssetCertificate, TenantID: d.TenantID, DomainID: d.ID, Generation: d.Generation, PublicData: store.TLSPublicData{Version: 1, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}}
	if err := st.TLSAssets().Put(ctx, asset, 0); err != nil {
		t.Fatal(err)
	}
	job := &store.Job{TenantID: "t1", ID: "job_x", Params: map[string]any{"user_id": "auth0|u1", "selected_origin": "id.t1.test"}}
	s := &fakeSender{}
	if status, _, err := (VerifyEmail{Sender: s}).Run(ctx, st, job, nil); status != store.JobCompleted || err != nil || s.calls[0] != "auth0|u1/@id.t1.test" {
		t.Fatalf("selected = %v %v %v", status, err, s.calls)
	}
	asset, _ = st.TLSAssets().Get(ctx, asset.Key)
	asset.PublicData.NotAfter = time.Now().Add(-time.Second)
	if err := st.TLSAssets().Put(ctx, asset, asset.Revision); err != nil {
		t.Fatal(err)
	}
	if status, details, err := (VerifyEmail{Sender: s}).Run(ctx, st, job, nil); status != store.JobFailed || err != nil || details == "" || len(s.calls) != 1 {
		t.Fatalf("expired certificate: %s %q %v calls=%v", status, details, err, s.calls)
	}
	d.Status, d.Lifecycle = customdomain.StatusPending, customdomain.LifecycleSuspended
	if err := st.CustomDomains().Update(ctx, d, d.Revision); err != nil {
		t.Fatal(err)
	}
	status, details, err := (VerifyEmail{Sender: s}).Run(ctx, st, job, nil)
	if status != store.JobFailed || err != nil || details == "" || len(s.calls) != 1 {
		t.Fatalf("unusable = %v %q %v %v", status, details, err, s.calls)
	}
	legacy := &store.Job{TenantID: "t1", ID: "job_y", Params: map[string]any{"user_id": "auth0|u1"}}
	if status, _, err := (VerifyEmail{Sender: s}).Run(ctx, st, legacy, nil); status != store.JobCompleted || err != nil || s.calls[1] != "auth0|u1/@t1.example.test" {
		t.Fatalf("legacy = %v %v %v", status, err, s.calls)
	}
}
