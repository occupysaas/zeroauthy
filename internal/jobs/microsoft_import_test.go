package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type noMicrosoftImportStore struct{ store.Store }

func (s noMicrosoftImportStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(noMicrosoftImportStore{tx}) })
}

func TestMicrosoftImport(t *testing.T) {
	const oid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const tid = "11111111-2222-3333-4444-555555555555"
	for _, kind := range []string{"google", "oauth", "oidc", "personal", "single", "multi", "malformed", "unknown", "mode mismatch", "conflict", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			backing := memory.New()
			defer backing.Close()
			var st store.Store = backing
			if kind == "unsupported" {
				st = noMicrosoftImportStore{backing}
			}
			e := newImpEnv(t, st)
			c := &store.Connection{TenantID: impTenant, ID: "ms", Name: "personal", Strategy: "windowslive"}
			sub := "Case|Sensitive"
			id := sub
			if kind == "google" {
				c.Strategy = "google-oauth2"
			}
			if kind == "oauth" || kind == "oidc" {
				c.Strategy = "oauth2"
				if kind == "oidc" {
					c.Strategy = "oidc"
				}
				id = c.Name + "|" + sub
			}
			if kind == "single" || kind == "multi" || kind == "mode mismatch" || kind == "malformed" {
				c.Name = "work"
				c.Strategy = "waad"
				c.Extra = map[string]any{"tenant_domain": tid}
				sub = oid
				id = "work|" + oid
			}
			if kind == "multi" {
				c.Extra = map[string]any{"useCommonEndpoint": true}
				sub = tid + ":" + oid
				id = "work|" + sub
			}
			if kind == "mode mismatch" {
				id = "work|" + tid + ":" + oid
			}
			if kind == "malformed" {
				id = "work|not-a-guid"
			}
			if err := st.Connections().Create(ctx, c); err != nil {
				t.Fatal(err)
			}
			name := c.Name
			if kind == "unknown" {
				name = "missing"
			}
			ident := store.Identity{Connection: name, Provider: c.Strategy, UserID: id, ProfileData: map[string]any{}}
			if kind == "conflict" {
				e.mustCreate(&store.User{UserID: "auth0|owner", Identities: []store.Identity{{Connection: impConn, Provider: "auth0", UserID: "owner"}, ident}})
			}
			body := map[string]any{"email": "import@x.test", "user_id": "import", "identities": []any{map[string]any{"provider": ident.Provider, "connection": ident.Connection, "user_id": ident.UserID}}}
			done, errs := e.run(e.importer(), fileOf(t, []any{body}), nil)
			valid := kind == "google" || kind == "oauth" || kind == "oidc" || kind == "personal" || kind == "single" || kind == "multi"
			if valid {
				if done.Summary.Inserted != 1 || len(errs) != 0 {
					t.Fatalf("import %+v %v", done.Summary, errs)
				}
				u, err := st.Users().FindByIdentity(ctx, impTenant, c.ID, sub)
				if err != nil || u.UserID != "auth0|import" || len(u.Identities) != 2 || !u.Identities[1].Linked() {
					t.Fatalf("owner %+v %v", u, err)
				}
				// Identical upsert is allowed; a different ownership set is rejected.
				done, errs = e.run(e.importer(), fileOf(t, []any{body}), map[string]any{ParamUpsert: true})
				if done.Summary.Updated != 1 || len(errs) != 0 {
					t.Fatalf("same upsert %+v %v", done.Summary, errs)
				}
				body["identities"] = []any{}
				body["name"] = "must not change"
				done, errs = e.run(e.importer(), fileOf(t, []any{body}), map[string]any{ParamUpsert: true})
				if done.Summary.Failed != 1 {
					t.Fatalf("changed identity set %+v %v", done.Summary, errs)
				}
				u, err = st.Users().Get(ctx, impTenant, "auth0|import")
				if err != nil || u.Name == "must not change" || len(u.Identities) != 2 {
					t.Fatalf("mutated upsert %+v %v", u, err)
				}
			} else {
				if done.Summary.Failed != 1 || len(errs) != 1 {
					t.Fatalf("invalid import %+v %v", done.Summary, errs)
				}
				if _, err := st.Users().Get(ctx, impTenant, "auth0|import"); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("rejected import mutated: %v", err)
				}
			}
		})
	}
}
func TestMicrosoftImportRejectsFederatedDestination(t *testing.T) {
	for _, strategy := range []string{"windowslive", "waad"} {
		t.Run(strategy, func(t *testing.T) {
			st := memory.New()
			defer st.Close()
			e := newImpEnv(t, st)
			e.conn.Strategy = strategy
			if err := st.Connections().Update(context.Background(), e.conn); err != nil {
				t.Fatal(err)
			}
			done, errs := e.run(e.importer(), []byte(`[{"email":"a@x.test","user_id":"raw"}]`), nil)
			if done.Summary.Failed != 1 || len(errs) != 1 || errs[0].Errors[0].Code != "CONNECTION_NOT_FOUND" {
				t.Fatalf("job %+v %v", done.Summary, errs)
			}
			_, n, err := st.Users().List(context.Background(), impTenant, nil, store.UserSort{}, store.Page{})
			if err != nil || n != 0 {
				t.Fatalf("users %d %v", n, err)
			}
		})
	}
}
