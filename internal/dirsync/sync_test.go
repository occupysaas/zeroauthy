package dirsync

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSyncUsers(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, "", false)
	e.dir.users = []map[string]any{wsUser("Ann@corp.example.com", "Ann", false), wsUser("bob@corp.example.com", "Bob", true), wsUser("cat@corp.example.com", "Cat", false)}
	p := e.runNow(t)
	if p.LastSyncStatus != StatusSuccess || p.LastSyncError != "" || p.LastSyncAt == nil || p.LeaseUntil != nil {
		t.Fatalf("status %+v", p)
	}
	// Automatic synchronization: the next run is due in 40 minutes.
	if p.NextSyncAt == nil || !p.NextSyncAt.Equal(fixedNow.Add(AutomaticInterval)) || p.SyncID == "" {
		t.Fatalf("next %+v", p)
	}
	ann := e.user(t, "ann@corp.example.com")
	if ann.UserID != "google-apps|ann@corp.example.com" || ann.Email != "Ann@corp.example.com" || !ann.EmailVerified || ann.GivenName != "Ann" ||
		ann.Name != "Ann Example" || ann.Blocked || ann.Identities[0].Provider != "google-apps" || ann.Identities[0].Connection != "workspace" {
		t.Fatalf("ann %+v", ann)
	}
	// Suspended accounts are created blocked.
	if bob := e.user(t, "bob@corp.example.com"); !bob.Blocked {
		t.Fatalf("bob %+v", bob)
	}
	// A block set by an administrator is not lifted by synchronization.
	cat := e.user(t, "cat@corp.example.com")
	cat.Blocked = true
	if err := e.st.Users().Update(ctx, cat); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Sessions().Create(ctx, &store.LoginSession{TenantID: "ten_a", ID: "ses_ann", TokenHash: "h-ann", UserID: ann.UserID, Connection: "workspace", AuthenticatedAt: fixedNow, CreatedAt: fixedNow, UpdatedAt: fixedNow, ExpiresAt: fixedNow.Add(24 * time.Hour), IdleExpiresAt: fixedNow.Add(24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	// Next run: Ann removed from the directory, Bob reinstated, Cat renamed.
	e.now = fixedNow.Add(time.Hour)
	e.dir.users = []map[string]any{wsUser("bob@corp.example.com", "Bob", false), wsUser("cat@corp.example.com", "Catherine", false)}
	if p := e.runNow(t); p.LastSyncStatus != StatusSuccess {
		t.Fatalf("second run %+v", p)
	}
	ann = e.user(t, "ann@corp.example.com")
	if !ann.Blocked || ann.Identities[0].ProviderData[suspendedMarker] != true {
		t.Fatalf("removed user not blocked: %+v", ann)
	}
	if ss, _ := e.st.Sessions().ListByUser(ctx, "ten_a", ann.UserID); len(ss) != 0 {
		t.Fatalf("removed user's sessions survive: %+v", ss)
	}
	if bob := e.user(t, "bob@corp.example.com"); bob.Blocked {
		t.Fatalf("reinstated user still blocked: %+v", bob)
	}
	if cat := e.user(t, "cat@corp.example.com"); !cat.Blocked || cat.GivenName != "Catherine" {
		t.Fatalf("cat %+v", cat)
	}
	// Ann back: unblocked (the block was synchronization's).
	e.dir.users = append(e.dir.users, wsUser("ann@corp.example.com", "Ann", false))
	e.runNow(t)
	if ann := e.user(t, "ann@corp.example.com"); ann.Blocked {
		t.Fatalf("returning user still blocked: %+v", ann)
	}
	// Other tenants are untouched.
	if _, n, _ := e.st.Users().List(ctx, "ten_b", nil, store.UserSort{Field: "user_id"}, store.Page{}); n != 0 {
		t.Fatalf("ten_b has %d users", n)
	}
}

func TestSyncFailures(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		setup func(e *env)
		want  string
	}{
		"revoked grant":     {func(e *env) { e.dir.revoked = true }, ErrGrantRevoked.Error()},
		"not administrator": {func(e *env) { e.dir.forbidden = true }, "status 403"},
		"no grant": {func(e *env) {
			p, _ := e.st.DirectorySync().GetProvisioning(ctx, "ten_a", "con_ws")
			p.AdminGrant = nil
			_ = e.st.DirectorySync().UpdateProvisioning(ctx, p)
		}, "has not authorized directory access"},
		"groups disabled on the connection": {func(e *env) {
			p, _ := e.st.DirectorySync().GetProvisioning(ctx, "ten_a", "con_ws")
			p.Doc = json.RawMessage(`{"mapping":[{"auth0":"email","scim":"primaryEmail"}],"synchronize_groups":"all"}`)
			_ = e.st.DirectorySync().UpdateProvisioning(ctx, p)
		}, "api_enable_groups is false"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, "", false)
			e.dir.users = []map[string]any{wsUser("ann@corp.example.com", "Ann", false)}
			tc.setup(e)
			p := e.runNow(t)
			if p.LastSyncStatus != StatusFailed || !strings.Contains(p.LastSyncError, tc.want) {
				t.Fatalf("status %q error %q", p.LastSyncStatus, p.LastSyncError)
			}
			for _, secret := range []string{adminRefresh, adminAccess, provSecret} {
				if strings.Contains(p.LastSyncError, secret) {
					t.Fatalf("error exposes a secret: %q", p.LastSyncError)
				}
			}
		})
	}
	// Manual-only configurations are not rescheduled.
	e := newEnv(t, `{"mapping":[{"auth0":"email","scim":"primaryEmail"}],"synchronize_automatically":false}`, false)
	if p := e.runNow(t); p.NextSyncAt != nil || p.SyncID != "" || p.LastSyncStatus != StatusSuccess {
		t.Fatalf("manual %+v", p)
	}
	if n, _ := e.sync.RunDue(ctx); n != 0 {
		t.Fatal("manual configuration ran again")
	}
}

func TestSyncGroups(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"all", "selected"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t, `{"mapping":[{"auth0":"email","scim":"primaryEmail"}],"synchronize_groups":"`+mode+`"}`, true)
			e.dir.users = []map[string]any{wsUser("ann@corp.example.com", "Ann", false), wsUser("bob@corp.example.com", "Bob", false)}
			e.dir.groups = []Group{{ID: "g1", Name: "Engineering", Email: "eng@corp.example.com"}, {ID: "g2", Name: "Sales", Email: "sales@corp.example.com"}}
			e.dir.members = map[string][]Member{
				"g1": {{ID: "id-ann", Email: "ann@corp.example.com", Type: "USER", Status: "ACTIVE"}, {ID: "nested", Email: "x@corp.example.com", Type: "GROUP"}},
				"g2": {{ID: "id-bob", Email: "bob@corp.example.com", Type: "USER", Status: "ACTIVE"}},
			}
			if mode == "selected" {
				if err := e.st.DirectorySync().ReplaceGroups(ctx, "ten_a", "con_ws", []store.SynchronizedGroup{{GroupID: "g1", Doc: json.RawMessage(`{}`)}}); err != nil {
					t.Fatal(err)
				}
			}
			if p := e.runNow(t); p.LastSyncStatus != StatusSuccess {
				t.Fatalf("%+v", p)
			}
			groups, _, _ := e.st.Directory().ListGroups(ctx, "ten_a", store.GroupFilter{ConnectionID: "con_ws"}, store.Page{})
			want := 2
			if mode == "selected" {
				want = 1
			}
			if len(groups) != want {
				t.Fatalf("groups %+v", groups)
			}
			var eng *store.Group
			for _, g := range groups {
				if g.ExternalID == "g1" {
					eng = g
				}
			}
			if eng == nil || eng.Name != "Engineering" {
				t.Fatalf("engineering %+v", groups)
			}
			ms, _, _ := e.st.Directory().ListGroupMembers(ctx, "ten_a", eng.ID, store.Page{})
			if len(ms) != 1 || ms[0].UserID != "google-apps|ann@corp.example.com" {
				t.Fatalf("members %+v", ms)
			}
			// A group leaving the directory is deleted; membership follows the
			// directory.
			e.dir.groups = e.dir.groups[:1]
			e.dir.members["g1"] = []Member{{ID: "id-bob", Email: "bob@corp.example.com", Type: "USER", Status: "ACTIVE"}}
			e.runNow(t)
			groups, _, _ = e.st.Directory().ListGroups(ctx, "ten_a", store.GroupFilter{ConnectionID: "con_ws"}, store.Page{})
			if len(groups) != 1 || groups[0].ID != eng.ID {
				t.Fatalf("after removal %+v", groups)
			}
			ms, _, _ = e.st.Directory().ListGroupMembers(ctx, "ten_a", eng.ID, store.Page{})
			if len(ms) != 1 || ms[0].UserID != "google-apps|bob@corp.example.com" {
				t.Fatalf("members after change %+v", ms)
			}
		})
	}
}
