package authz

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/rpid"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestEnrollmentPromptRejectsUnissuedAuthority(t *testing.T) {
	e := newEnv(t)
	e.h.Passkeys = passkey.NewService(e.st, rpid.Policy{}, fixedNow)
	ctx := context.Background()
	res := tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"}
	sess := &store.LoginSession{ID: "session", UserID: "user", TenantID: e.tenant.ID}
	for _, stage := range []string{"", StageMFA, "consent", StagePasskeyPrompt} {
		txn := &store.AuthTransaction{TenantID: e.tenant.ID, ID: "txn-" + stage, Origin: res.Origin(), Params: map[string]string{ParamStage: stage}, ExpiresAt: fixedNow().Add(TxnLifetime)}
		if err := e.st.AuthTransactions().Create(ctx, txn); err != nil {
			t.Fatal(err)
		}
		if kind, err := e.h.PasskeyPrompt(ctx, res, txn, sess); err == nil || kind != "" {
			t.Fatalf("unissued %q prompt: %q %v", stage, kind, err)
		}
	}
}
