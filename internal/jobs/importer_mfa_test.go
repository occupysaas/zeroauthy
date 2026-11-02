package jobs

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"strings"
	"testing"
	"time"
)

func TestImportMFAFactors(t *testing.T) {
	e := newImpEnv(t, memory.New())
	p := e.importer()
	j, errs := e.run(p, fileOf(t, []any{map[string]any{"email": "mfa@example.test", "mfa_factors": []any{map[string]any{"email": map[string]any{"value": "factor@example.test"}}, map[string]any{"phone": map[string]any{"value": "+123456789"}}}}, map[string]any{"email": "bad@example.test", "name": "SECRET-INVALID-MATERIAL", "app_metadata": map[string]any{"note": "SECRET-INVALID-MATERIAL"}, "mfa_factors": []any{map[string]any{"totp": map[string]any{"secret": "SECRET-INVALID-MATERIAL"}}}}}), nil)
	if j.Summary.Inserted != 1 || j.Summary.Failed != 1 || len(errs) != 1 {
		t.Fatalf("%+v %v", j.Summary, errs)
	}
	u := e.user("mfa@example.test")
	a, err := e.st.MFA().ListAuthenticators(context.Background(), impTenant, u.UserID)
	if err != nil || len(a) != 2 || !a[0].Confirmed || !a[1].Confirmed {
		t.Fatal(a, err)
	}
	b := fileOf(t, errs)
	if strings.Contains(string(b), "SECRET-INVALID-MATERIAL") {
		t.Fatal("import errors expose MFA secret")
	}
}
func TestImportMFAInputSealedBindingAndRetry(t *testing.T) {
	e := newImpEnv(t, memory.New())
	p := e.importer()
	raw := fileOf(t, []any{map[string]any{"email": "totp@example.test", "mfa_factors": []any{map[string]any{"totp": map[string]any{"secret": "JBSWY3DPEHPK3PXP"}}}}})
	j := &store.Job{TenantID: impTenant, ID: "job", Input: raw, Params: map[string]any{}}
	if err := SealImportInput(p.Wrapper, j); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		opened, err := openImportInput(p.Wrapper, j)
		if err != nil || string(opened) != string(raw) {
			t.Fatal("retry decryption", err)
		}
	}
	for _, field := range []string{"tenant", "job"} {
		copy := *j
		if field == "tenant" {
			copy.TenantID = "foreign"
		} else {
			copy.ID = "foreign"
		}
		if _, err := openImportInput(p.Wrapper, &copy); err == nil {
			t.Fatal("wrong binding decrypted")
		}
	}
	j.Input[0] ^= 1
	if _, err := openImportInput(p.Wrapper, j); err == nil {
		t.Fatal("tampered sealed input accepted")
	}
	j.Input = []byte("plaintext")
	if _, err := openImportInput(p.Wrapper, j); err == nil {
		t.Fatal("flagged input fell back to plaintext")
	}
}

func TestImportMFAExportExcluded(t *testing.T) {
	for _, field := range []string{"mfa_factors", "authentication_methods", "authenticators"} {
		if _, ok := lookup(map[string]any{field: []any{map[string]any{"totp_secret": "secret"}}}, field); ok {
			t.Fatalf("export allowed %s", field)
		}
	}
}
func TestImportMFASealedTOTPReplay(t *testing.T) {
	e := newImpEnv(t, memory.New())
	p := e.importer()
	raw := fileOf(t, []any{map[string]any{"email": "sealed@example.test", "mfa_factors": []any{map[string]any{"totp": map[string]any{"secret": "JBSWY3DPEHPK3PXP"}}}}})
	j := &store.Job{TenantID: impTenant, ID: "job_sealed", Type: store.JobUsersImport, Status: store.JobPending, ConnectionID: e.conn.ID, Connection: e.conn.Name, Input: raw, Params: map[string]any{ParamSendCompletionEmail: false}, CreatedAt: e.now, UpdatedAt: e.now, ExpiresAt: e.now.Add(time.Hour)}
	if err := SealImportInput(p.Wrapper, j); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(j.Input), "JBSWY3DPEHPK3PXP") {
		t.Fatal("plaintext retained")
	}
	if err := e.st.Jobs().Create(context.Background(), j); err != nil {
		t.Fatal(err)
	}
	claimed, lease := e.claim("w1")
	first, errs := e.finish(p, e.st, claimed, lease)
	if first.Summary.Inserted != 1 || len(errs) != 0 {
		t.Fatal(first.Summary, errs)
	}
	u := e.user("sealed@example.test")
	methods, err := e.st.MFA().ListAuthenticators(context.Background(), impTenant, u.UserID)
	if err != nil || len(methods) != 1 || !methods[0].Confirmed || len(methods[0].SealedSecret) == 0 || strings.Contains(string(methods[0].SealedSecret), "JBSWY3DPEHPK3PXP") {
		t.Fatal(methods, err)
	}
	before := methods[0].ID
	retry := *claimed
	retry.Progress = first.Progress
	retry.Summary = first.Summary
	status, _, err := p.Run(context.Background(), e.st, &retry, nil)
	if err != nil || status != store.JobCompleted {
		t.Fatal(status, err)
	}
	methods, err = e.st.MFA().ListAuthenticators(context.Background(), impTenant, u.UserID)
	if err != nil || len(methods) != 1 || methods[0].ID != before {
		t.Fatal("checkpoint replay changed methods", methods, err)
	}
}
