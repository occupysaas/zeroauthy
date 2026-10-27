package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testActions covers the Actions repository: names, copies, version numbering,
// bindings, single-use continue states, purges and tenant isolation. It runs
// unchanged against every driver.
func testActions(t *testing.T, factory Factory) {
	ctx := context.Background()
	s := open(t, factory)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tid := range []string{"act-a", "act-b", "act-list", "act-bind"} {
		must(s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
	}
	a := s.Actions()
	now := time.Now().UTC().Truncate(time.Second)
	draft := func(tid, id, name string) *store.Action {
		return &store.Action{
			TenantID: tid, ID: id, Name: name, Trigger: "post-login", Runtime: "node22",
			Code:         "exports.onExecutePostLogin = async () => {}",
			Dependencies: []store.Dependency{{Name: "lodash", Version: "4.17.21"}},
			Secrets:      []store.ActionSecret{{Name: "KEY", Sealed: []byte("sealed"), UpdatedAt: now}},
			CreatedAt:    now, UpdatedAt: now,
		}
	}
	built := func(tid, id string) {
		t.Helper()
		must(a.PutBuild(ctx, &store.Build{TenantID: tid, ID: id, Status: store.BuildBuilt,
			Requested: []store.Dependency{{Name: "lodash"}}, Resolved: []store.Dependency{{Name: "lodash", Version: "4.17.21"}}, BuiltAt: now}))
		must(a.PutArtifact(ctx, tid, id, []byte("artifact-"+id)))
	}
	mk := func(tid, id, name, build string) *store.Action {
		t.Helper()
		x := draft(tid, id, name)
		x.DraftBuildID = build
		must(a.CreateAction(ctx, x))
		return x
	}

	t.Run("CRUD and names", func(t *testing.T) {
		x := draft("act-a", "act_1", "Add Claims")
		must(a.CreateAction(ctx, x))
		x.Name, x.Dependencies[0].Name, x.Secrets[0].Sealed[0] = "mutated", "mutated", 'X'
		got, err := a.GetAction(ctx, "act-a", "act_1")
		must(err)
		if got.Name != "Add Claims" || got.Dependencies[0].Name != "lodash" || got.Secrets[0].Sealed[0] != 's' {
			t.Fatalf("input was not copied: %+v", got)
		}
		got.Dependencies[0].Name, got.Secrets[0].Sealed[0] = "mutated", 'X'
		again, _ := a.GetAction(ctx, "act-a", "act_1")
		if again.Dependencies[0].Name != "lodash" || again.Secrets[0].Sealed[0] != 's' {
			t.Fatal("output was not copied")
		}
		byName, err := a.GetActionByName(ctx, "act-a", "Add Claims")
		must(err)
		if byName.ID != "act_1" {
			t.Fatal(byName.ID)
		}
		if _, err := a.GetActionByName(ctx, "act-a", "add claims"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("names are case-sensitive: %v", err)
		}
		must(a.CreateAction(ctx, draft("act-a", "act_2", "add claims")))
		if err := a.CreateAction(ctx, draft("act-a", "act_3", "Add Claims")); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("duplicate name: %v", err)
		}
		if err := a.CreateAction(ctx, draft("act-a", "act_1", "Other")); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("duplicate id: %v", err)
		}
		must(a.CreateAction(ctx, draft("act-b", "act_1", "Add Claims")))
		if _, err := a.GetAction(ctx, "act-b", "missing"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		bad := draft("act-a", "act_bad", "x")
		bad.Dependencies = []store.Dependency{{Name: "lodash", Version: "^4"}}
		if err := a.CreateAction(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("range dependency: %v", err)
		}
		bad = draft("act-a", "act_bad", "x")
		bad.Secrets = []store.ActionSecret{{Name: "a-b"}}
		if err := a.CreateAction(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("secret name: %v", err)
		}
		up, _ := a.GetAction(ctx, "act-a", "act_1")
		up.Name, up.Code = "Renamed", "// v2"
		up.DeployedVersionID, up.Trigger = "forged", "credentials-exchange"
		if err := a.UpdateAction(ctx, up); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("trigger change: %v", err)
		}
		up.Trigger = "post-login"
		must(a.UpdateAction(ctx, up))
		got, _ = a.GetAction(ctx, "act-a", "act_1")
		if got.Name != "Renamed" || got.Code != "// v2" || got.DeployedVersionID != "" {
			t.Fatalf("update: %+v", got)
		}
		up.Name = "add claims"
		if err := a.UpdateAction(ctx, up); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("rename collision: %v", err)
		}
		up.ID = "ghost"
		up.Name = "ghost"
		if err := a.UpdateAction(ctx, up); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("update missing: %v", err)
		}
		must(a.UpdateAction(ctx, &store.Action{TenantID: "act-a", ID: "act_1", Name: "Add Claims", Trigger: "post-login", Runtime: "node22"}))
	})

	t.Run("list", func(t *testing.T) {
		for i := 0; i < 25; i++ {
			x := draft("act-list", fmt.Sprintf("l%02d", i), fmt.Sprintf("list %02d", i))
			x.CreatedAt = now.Add(time.Duration(i) * time.Second)
			must(a.CreateAction(ctx, x))
		}
		p, err := a.ListActions(ctx, "act-list", store.ActionFilter{})
		must(err)
		if p.Total != 25 || len(p.Items) != 20 {
			t.Fatalf("default page: total=%d len=%d", p.Total, len(p.Items))
		}
		p, err = a.ListActions(ctx, "act-list", store.ActionFilter{PageRequest: store.PageRequest{Page: 1, PerPage: 20}})
		must(err)
		if len(p.Items) != 5 {
			t.Fatalf("second page: %d", len(p.Items))
		}
		p, _ = a.ListActions(ctx, "act-list", store.ActionFilter{PageRequest: store.PageRequest{PerPage: 1000}})
		if len(p.Items) != 25 {
			t.Fatalf("clamped page: %d", len(p.Items))
		}
		p, _ = a.ListActions(ctx, "act-list", store.ActionFilter{Trigger: "credentials-exchange"})
		if p.Total != 0 || len(p.Items) != 0 {
			t.Fatal("trigger filter")
		}
		p, _ = a.ListActions(ctx, "act-list", store.ActionFilter{PageRequest: store.PageRequest{Page: 50}})
		if p.Total != 25 || len(p.Items) != 0 {
			t.Fatal("page past end")
		}
	})

	t.Run("deploy and rollback", func(t *testing.T) {
		mk("act-a", "dep", "Deployable", "")
		if _, err := a.Deploy(ctx, "act-a", "dep", ""); !errors.Is(err, store.ErrBuildNotReady) {
			t.Fatalf("no build: %v", err)
		}
		must(a.PutBuild(ctx, &store.Build{TenantID: "act-a", ID: "pend", Status: store.BuildPending}))
		d, _ := a.GetAction(ctx, "act-a", "dep")
		d.DraftBuildID = "pend"
		must(a.UpdateAction(ctx, d))
		if _, err := a.Deploy(ctx, "act-a", "dep", ""); !errors.Is(err, store.ErrBuildNotReady) {
			t.Fatalf("pending build: %v", err)
		}
		must(a.PutBuild(ctx, &store.Build{TenantID: "act-a", ID: "noart", Status: store.BuildBuilt}))
		d.DraftBuildID = "noart"
		must(a.UpdateAction(ctx, d))
		if _, err := a.Deploy(ctx, "act-a", "dep", ""); !errors.Is(err, store.ErrBuildNotReady) {
			t.Fatalf("built build without artifact: %v", err)
		}
		built("act-a", "b1")
		d.DraftBuildID = "b1"
		must(a.UpdateAction(ctx, d))
		v1, err := a.Deploy(ctx, "act-a", "dep", "")
		must(err)
		if v1.Number != 1 || v1.BuildID != "b1" || v1.ActionID != "dep" || v1.Runtime != "node22" || v1.Code != d.Code ||
			len(v1.Dependencies) != 1 || v1.Dependencies[0].Version != "4.17.21" || len(v1.Secrets) != 1 {
			t.Fatalf("v1: %+v", v1)
		}
		cur, _ := a.GetAction(ctx, "act-a", "dep")
		if cur.DeployedVersionID != v1.ID {
			t.Fatal("deployed version not recorded")
		}
		d, _ = a.GetAction(ctx, "act-a", "dep")
		d.Code = "// second"
		must(a.UpdateAction(ctx, d))
		v2, err := a.Deploy(ctx, "act-a", "dep", "")
		must(err)
		if v2.Number != 2 || v2.Code != "// second" {
			t.Fatalf("v2: %+v", v2)
		}
		v3, err := a.Deploy(ctx, "act-a", "dep", v1.ID)
		must(err)
		if v3.Number != 3 || v3.Code != v1.Code || v3.BuildID != "b1" {
			t.Fatalf("rollback: %+v", v3)
		}
		cur, _ = a.GetAction(ctx, "act-a", "dep")
		if cur.DeployedVersionID != v3.ID {
			t.Fatal("rollback not deployed")
		}
		if _, err := a.Deploy(ctx, "act-a", "dep", "nope"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("rollback to missing: %v", err)
		}
		if _, err := a.Deploy(ctx, "act-b", "dep", ""); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross tenant deploy: %v", err)
		}
		if _, err := a.GetVersion(ctx, "act-b", "dep", v1.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross tenant version: %v", err)
		}
		got, err := a.GetVersion(ctx, "act-a", "dep", v1.ID)
		must(err)
		got.Dependencies[0].Name = "mutated"
		got, _ = a.GetVersion(ctx, "act-a", "dep", v1.ID)
		if got.Dependencies[0].Name != "lodash" {
			t.Fatal("version not copied")
		}
		vs, err := a.ListVersions(ctx, "act-a", "dep", store.PageRequest{})
		must(err)
		if vs.Total != 3 || len(vs.Items) != 3 || vs.Items[0].Number != 3 || vs.Items[2].Number != 1 {
			t.Fatalf("versions: %+v", vs)
		}
	})

	t.Run("concurrent deploys", func(t *testing.T) {
		built("act-a", "cb")
		mk("act-a", "conc", "Concurrent", "cb")
		const n = 8
		var wg sync.WaitGroup
		nums := make(chan int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				v, err := a.Deploy(ctx, "act-a", "conc", "")
				if err != nil {
					t.Error(err)
					return
				}
				nums <- v.Number
			}()
		}
		wg.Wait()
		close(nums)
		seen := map[int]bool{}
		for v := range nums {
			if seen[v] {
				t.Fatalf("version %d allocated twice", v)
			}
			seen[v] = true
		}
		for i := 1; i <= n; i++ {
			if !seen[i] {
				t.Fatalf("version %d missing: %v", i, seen)
			}
		}
	})

	t.Run("builds and artifacts", func(t *testing.T) {
		if _, err := a.GetBuild(ctx, "act-a", "ghost"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		if err := a.PutBuild(ctx, &store.Build{TenantID: "act-a", ID: "x", Status: "weird"}); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("status: %v", err)
		}
		b := &store.Build{TenantID: "act-a", ID: "bx", Status: store.BuildFailed, Errors: []string{"boom"}, Requested: []store.Dependency{{Name: "a"}}}
		must(a.PutBuild(ctx, b))
		b.Errors[0] = "mutated"
		got, _ := a.GetBuild(ctx, "act-a", "bx")
		if got.Errors[0] != "boom" || got.Status != store.BuildFailed {
			t.Fatal("build not copied")
		}
		built("act-a", "bx")
		got, _ = a.GetBuild(ctx, "act-a", "bx")
		if got.Status != store.BuildBuilt {
			t.Fatal("build not replaced")
		}
		if _, err := a.GetBuild(ctx, "act-b", "bx"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("cross tenant build")
		}
		if err := a.PutArtifact(ctx, "act-a", "ghost", []byte("x")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("artifact without build: %v", err)
		}
		tar := []byte("tar-bytes")
		must(a.PutArtifact(ctx, "act-a", "bx", tar))
		tar[0] = 'X'
		art, err := a.GetArtifact(ctx, "act-a", "bx")
		must(err)
		if !bytes.Equal(art, []byte("tar-bytes")) {
			t.Fatal("artifact not copied")
		}
		if _, err := a.GetArtifact(ctx, "act-b", "bx"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("cross tenant artifact")
		}
		if _, err := a.GetArtifact(ctx, "act-a", "noart"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("missing artifact")
		}
		if err := a.PutArtifact(ctx, "act-a", "bx", make([]byte, 50_000_001)); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("oversize artifact: %v", err)
		}
	})

	t.Run("bindings", func(t *testing.T) {
		built("act-bind", "bb")
		for _, id := range []string{"b1", "b2", "b3"} {
			mk("act-bind", "bind_"+id, "bind "+id, "bb")
			_, err := a.Deploy(ctx, "act-bind", "bind_"+id, "")
			must(err)
		}
		mk("act-bind", "undeployed", "Undeployed", "bb")
		bs := func(ids ...string) []store.Binding {
			var out []store.Binding
			for i, id := range ids {
				out = append(out, store.Binding{TenantID: "act-bind", Trigger: "post-login", ID: fmt.Sprintf("bnd_%s_%d", id, i), ActionID: id, DisplayName: id})
			}
			return out
		}
		got, err := a.Bindings(ctx, "act-bind", "post-login")
		must(err)
		if len(got) != 0 {
			t.Fatal("expected no bindings")
		}
		out, err := a.ReplaceBindings(ctx, "act-bind", "post-login", bs("bind_b3", "bind_b1", "bind_b2"))
		must(err)
		order := func(v []store.BoundVersion) string {
			s := ""
			for _, b := range v {
				s += b.ActionID + ","
			}
			return s
		}
		if order(out) != "bind_b3,bind_b1,bind_b2," {
			t.Fatalf("order: %s", order(out))
		}
		got, _ = a.Bindings(ctx, "act-bind", "post-login")
		if order(got) != order(out) || got[0].Version.Number != 1 || got[0].Action.ID != "bind_b3" || got[0].Version.ID != got[0].Action.DeployedVersionID {
			t.Fatalf("snapshot: %+v", got[0])
		}
		if got[0].Trigger != "post-login" || got[0].TenantID != "act-bind" {
			t.Fatal("binding identity")
		}
		before, _ := a.Bindings(ctx, "act-bind", "post-login")
		for _, bad := range [][]store.Binding{bs("undeployed"), bs("ghost"), bs("bind_b1", "undeployed"), bs(""), append(bs("bind_b1"), store.Binding{ActionID: "bind_b2", Trigger: "credentials-exchange"})} {
			if _, err := a.ReplaceBindings(ctx, "act-bind", "post-login", bad); !errors.Is(err, store.ErrInvalid) {
				t.Fatalf("bad bindings %v: %v", bad, err)
			}
		}
		if _, err := a.ReplaceBindings(ctx, "act-bind", "post-login", func() []store.Binding {
			x := make([]store.Binding, 21)
			for i := range x {
				x[i] = store.Binding{ActionID: "bind_b1", ID: fmt.Sprint(i)}
			}
			return x
		}()); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("21 bindings: %v", err)
		}
		after, _ := a.Bindings(ctx, "act-bind", "post-login")
		if order(after) != order(before) {
			t.Fatal("refused replace changed bindings")
		}
		if _, err := a.ReplaceBindings(ctx, "act-bind", "credentials-exchange", bs("bind_b1")); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("trigger mismatch: %v", err)
		}
		// Replacement is atomic for concurrent readers: they see one list or the other.
		listA, listB := bs("bind_b1", "bind_b2"), bs("bind_b3")
		var stop atomic.Bool
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				l := listA
				if i%2 == 1 {
					l = listB
				}
				if _, err := a.ReplaceBindings(ctx, "act-bind", "post-login", l); err != nil {
					t.Error(err)
					break
				}
			}
			stop.Store(true)
		}()
		for !stop.Load() {
			snap, err := a.Bindings(ctx, "act-bind", "post-login")
			if err != nil {
				t.Fatal(err)
			}
			if o := order(snap); o != "bind_b1,bind_b2," && o != "bind_b3," && o != "bind_b3,bind_b1,bind_b2," {
				t.Fatalf("torn snapshot %q", o)
			}
		}
		wg.Wait()
		must(a.DeleteAction(ctx, "act-bind", "undeployed", false))
		must(a.DeleteAction(ctx, "act-bind", "bind_b3", true))
		left, err := a.Bindings(ctx, "act-bind", "post-login")
		if err != nil || len(left) != 0 {
			t.Fatalf("forced delete left bindings: %v %s", err, order(left))
		}
		if err := a.DeleteAction(ctx, "act-bind", "bind_b3", false); !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := a.GetVersion(ctx, "act-bind", "bind_b3", "x"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("versions survive delete")
		}
	})

	t.Run("delete bound without force", func(t *testing.T) {
		built("act-a", "db")
		mk("act-a", "del", "Delete me", "db")
		_, err := a.Deploy(ctx, "act-a", "del", "")
		must(err)
		_, err = a.ReplaceBindings(ctx, "act-a", "post-login", []store.Binding{{ActionID: "del", ID: "bnd_del"}})
		must(err)
		if err := a.DeleteAction(ctx, "act-a", "del", false); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("bound delete: %v", err)
		}
		if _, err := a.GetAction(ctx, "act-a", "del"); err != nil {
			t.Fatal("refused delete removed the action")
		}
		must(a.DeleteAction(ctx, "act-a", "del", true))
		if _, err := a.GetAction(ctx, "act-a", "del"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		if got, err := a.Bindings(ctx, "act-a", "post-login"); err != nil || len(got) != 0 {
			t.Fatalf("bindings survive: %v %v", err, got)
		}
	})

	t.Run("executions and continue", func(t *testing.T) {
		old := now.Add(-11 * 24 * time.Hour)
		must(a.CreateExecution(ctx, &store.Execution{TenantID: "act-a", ID: "ex_old", Trigger: "post-login", Status: "final", CreatedAt: old, UpdatedAt: old,
			Results: []store.ExecutionResult{{ActionName: "x", ErrorID: "e", StartedAt: old, EndedAt: old}}}))
		must(a.CreateExecution(ctx, &store.Execution{TenantID: "act-b", ID: "ex_new", Trigger: "post-login", Status: "pending", CreatedAt: now, UpdatedAt: now}))
		if err := a.CreateExecution(ctx, &store.Execution{TenantID: "act-b", ID: "ex_new"}); !errors.Is(err, store.ErrConflict) {
			t.Fatal(err)
		}
		if err := a.CreateExecution(ctx, &store.Execution{TenantID: "act-missing", ID: "ex_x", Trigger: "post-login", Status: "final"}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("execution for a missing tenant: %v", err)
		}
		if err := a.CreateContinue(ctx, &store.ContinueState{TenantID: "act-missing", StateHash: "h", SessionID: "s", Sealed: []byte("x"), ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("continue state for a missing tenant: %v", err)
		}
		e, err := a.GetExecution(ctx, "act-a", "ex_old")
		must(err)
		e.Results[0].ActionName = "mutated"
		e, _ = a.GetExecution(ctx, "act-a", "ex_old")
		if e.Results[0].ActionName != "x" {
			t.Fatal("execution not copied")
		}
		if _, err := a.GetExecution(ctx, "act-b", "ex_old"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("cross tenant execution")
		}
		n, err := a.PurgeExecutions(ctx, now.Add(-10*24*time.Hour))
		must(err)
		if n != 1 {
			t.Fatalf("purged %d", n)
		}
		if _, err := a.GetExecution(ctx, "act-a", "ex_old"); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("old execution survived")
		}
		if _, err := a.GetExecution(ctx, "act-b", "ex_new"); err != nil {
			t.Fatal(err)
		}

		cs := func(tid, h string, exp time.Time) *store.ContinueState {
			return &store.ContinueState{TenantID: tid, StateHash: h, SessionID: "sess", Sealed: []byte("seal"), ExpiresAt: exp, CreatedAt: now}
		}
		must(a.CreateContinue(ctx, cs("act-a", "h1", now.Add(15*time.Minute))))
		if err := a.CreateContinue(ctx, cs("act-a", "h1", now.Add(time.Hour))); !errors.Is(err, store.ErrConflict) {
			t.Fatal(err)
		}
		if _, err := a.ConsumeContinue(ctx, "act-b", "h1", now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("cross tenant consume: %v", err)
		}
		got, err := a.ConsumeContinue(ctx, "act-a", "h1", now)
		must(err)
		if got.SessionID != "sess" || string(got.Sealed) != "seal" {
			t.Fatalf("%+v", got)
		}
		if _, err := a.ConsumeContinue(ctx, "act-a", "h1", now); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("reuse: %v", err)
		}
		must(a.CreateContinue(ctx, cs("act-a", "exp", now.Add(time.Minute))))
		if _, err := a.ConsumeContinue(ctx, "act-a", "exp", now.Add(2*time.Minute)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired: %v", err)
		}
		must(a.CreateContinue(ctx, cs("act-a", "race", now.Add(time.Hour))))
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := a.ConsumeContinue(ctx, "act-a", "race", now); err == nil {
					wins.Add(1)
				} else if !errors.Is(err, store.ErrNotFound) {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d consumers won", wins.Load())
		}
		must(a.CreateContinue(ctx, cs("act-a", "p1", now.Add(-time.Hour))))
		must(a.CreateContinue(ctx, cs("act-b", "p2", now.Add(time.Hour))))
		n, err = a.PurgeContinue(ctx, now)
		must(err)
		if n != 1 {
			t.Fatalf("purged %d", n)
		}
		if _, err := a.ConsumeContinue(ctx, "act-b", "p2", now); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("deploy and bindings roll back", func(t *testing.T) {
		built("act-a", "rb")
		mk("act-a", "rbk", "Rollback me", "rb")
		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if _, err := tx.Actions().Deploy(ctx, "act-a", "rbk", ""); err != nil {
				return err
			}
			if _, err := tx.Actions().ReplaceBindings(ctx, "act-a", "post-login", []store.Binding{{ActionID: "rbk", ID: "rbk_b"}}); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatal(err)
		}
		got, err := a.GetAction(ctx, "act-a", "rbk")
		must(err)
		if got.DeployedVersionID != "" {
			t.Fatalf("deploy not rolled back: %q", got.DeployedVersionID)
		}
		if vs, _ := a.ListVersions(ctx, "act-a", "rbk", store.PageRequest{}); vs.Total != 0 {
			t.Fatal("version survived rollback")
		}
		for _, b := range mustBound(t, a, "act-a") {
			if b.ActionID == "rbk" {
				t.Fatal("binding survived rollback")
			}
		}
	})

	t.Run("transaction rollback", func(t *testing.T) {
		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Actions().CreateAction(ctx, draft("act-a", "tx_1", "In tx")); err != nil {
				return err
			}
			if _, err := tx.Actions().GetAction(ctx, "act-a", "tx_1"); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatal(err)
		}
		if _, err := a.GetAction(ctx, "act-a", "tx_1"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("rolled back action visible: %v", err)
		}
		must(s.WithTx(ctx, func(tx store.Store) error { return tx.Actions().CreateAction(ctx, draft("act-a", "tx_2", "Committed")) }))
		if _, err := a.GetAction(ctx, "act-a", "tx_2"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("tenant delete cleanup", func(t *testing.T) {
		must(s.Tenants().Create(ctx, &store.Tenant{ID: "act-gone", Name: "act-gone"}))
		built("act-gone", "gb")
		mk("act-gone", "g1", "Same Name", "gb")
		mk("act-b", "g1x", "Same Name Gone", "")
		gv, err := a.Deploy(ctx, "act-gone", "g1", "")
		must(err)
		deployedID := gv.ID
		_, err = a.ReplaceBindings(ctx, "act-gone", "post-login", []store.Binding{{ActionID: "g1", ID: "bnd"}})
		must(err)
		must(a.CreateExecution(ctx, &store.Execution{TenantID: "act-gone", ID: "ge", CreatedAt: now, UpdatedAt: now}))
		must(a.CreateContinue(ctx, &store.ContinueState{TenantID: "act-gone", StateHash: "gh", ExpiresAt: now.Add(time.Hour), CreatedAt: now}))
		must(s.Tenants().Delete(ctx, "act-gone"))
		checks := map[string]error{}
		_, checks["action"] = a.GetAction(ctx, "act-gone", "g1")
		_, checks["build"] = a.GetBuild(ctx, "act-gone", "gb")
		_, checks["artifact"] = a.GetArtifact(ctx, "act-gone", "gb")
		_, checks["execution"] = a.GetExecution(ctx, "act-gone", "ge")
		_, checks["continue"] = a.ConsumeContinue(ctx, "act-gone", "gh", now)
		for name, err := range checks {
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%s survived tenant delete: %v", name, err)
			}
		}
		if bs, err := a.Bindings(ctx, "act-gone", "post-login"); err != nil || len(bs) != 0 {
			t.Errorf("bindings survived tenant delete: %v %v", err, bs)
		}
		if vs, err := a.ListVersions(ctx, "act-gone", "g1", store.PageRequest{}); err != nil || vs.Total != 0 {
			t.Errorf("versions survived tenant delete: %v %+v", err, vs)
		}
		if _, err := a.GetVersion(ctx, "act-gone", "g1", deployedID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("version survived tenant delete: %v", err)
		}
		if _, err := a.GetAction(ctx, "act-b", "g1x"); err != nil {
			t.Fatalf("other tenant affected: %v", err)
		}
		// Recreating the tenant must not resurrect anything or collide on names.
		must(s.Tenants().Create(ctx, &store.Tenant{ID: "act-gone", Name: "act-gone"}))
		must(a.CreateAction(ctx, draft("act-gone", "g1", "Same Name")))
	})
}

func mustBound(t *testing.T, a store.Actions, tid string) []store.BoundVersion {
	t.Helper()
	b, err := a.Bindings(context.Background(), tid, "post-login")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
