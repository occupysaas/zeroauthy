package jobs

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestSocialUserImportIndexes(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	e := newImpEnv(t, st)
	if err := st.Connections().Create(ctx, &store.Connection{TenantID: impTenant, ID: "con_amz", Name: "amz", Strategy: "amazon"}); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"email": "import@x.test", "user_id": "import",
		"identities": []any{map[string]any{"provider": "amazon", "connection": "amz", "user_id": "amzn1.account.X"}}}
	done, errs := e.run(e.importer(), fileOf(t, []any{body}), nil)
	if done.Summary.Inserted != 1 || len(errs) != 0 {
		t.Fatalf("import %+v %v", done.Summary, errs)
	}
	if u, err := st.Users().FindByIdentity(ctx, impTenant, "con_amz", "amzn1.account.X"); err != nil || u.UserID != "auth0|import" {
		t.Fatalf("owner %+v %v", u, err)
	}

	// A store without social.v1 refuses descriptor identities.
	backing := memory.New()
	defer backing.Close()
	var hidden store.Store = noMicrosoftImportStore{backing}
	e = newImpEnv(t, hidden)
	if err := hidden.Connections().Create(ctx, &store.Connection{TenantID: impTenant, ID: "con_amz", Name: "amz", Strategy: "amazon"}); err != nil {
		t.Fatal(err)
	}
	done, errs = e.run(e.importer(), fileOf(t, []any{body}), nil)
	if done.Summary.Failed != 1 || len(errs) != 1 {
		t.Fatalf("unsupported store import %+v %v", done.Summary, errs)
	}
}
