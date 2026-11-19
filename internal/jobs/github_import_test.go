package jobs

import (
	"context"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestGitHubUserImportIndexes(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	e := newImpEnv(t, st)
	if err := st.Connections().Create(ctx, &store.Connection{TenantID: impTenant, ID: "con_gh", Name: "gh", Strategy: "github"}); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"email": "import@x.test", "user_id": "import",
		"identities": []any{map[string]any{"provider": "github", "connection": "gh", "user_id": "42"}}}
	done, errs := e.run(e.importer(), fileOf(t, []any{body}), nil)
	if done.Summary.Inserted != 1 || len(errs) != 0 {
		t.Fatalf("import %+v %v", done.Summary, errs)
	}
	u, err := st.Users().FindByIdentity(ctx, impTenant, "con_gh", "42")
	if err != nil || u.UserID != "auth0|import" {
		t.Fatalf("owner %+v %v", u, err)
	}

	// A non-canonical GitHub ID is rejected rather than indexed.
	body = map[string]any{"email": "other@x.test", "user_id": "other",
		"identities": []any{map[string]any{"provider": "github", "connection": "gh", "user_id": "042"}}}
	done, errs = e.run(e.importer(), fileOf(t, []any{body}), nil)
	if done.Summary.Failed != 1 || len(errs) != 1 {
		t.Fatalf("non-canonical import %+v %v", done.Summary, errs)
	}

	// A store without the GitHub capability refuses GitHub identities.
	backing := memory.New()
	defer backing.Close()
	var hidden store.Store = noMicrosoftImportStore{backing}
	e = newImpEnv(t, hidden)
	if err := hidden.Connections().Create(ctx, &store.Connection{TenantID: impTenant, ID: "con_gh", Name: "gh", Strategy: "github"}); err != nil {
		t.Fatal(err)
	}
	body = map[string]any{"email": "import@x.test", "user_id": "import",
		"identities": []any{map[string]any{"provider": "github", "connection": "gh", "user_id": "42"}}}
	done, errs = e.run(e.importer(), fileOf(t, []any{body}), nil)
	if done.Summary.Failed != 1 || len(errs) != 1 {
		t.Fatalf("unsupported store import %+v %v", done.Summary, errs)
	}
}
