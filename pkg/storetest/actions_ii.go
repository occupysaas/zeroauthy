package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testActionsII catches lost immutable pins, unsafe deletes, non-atomic leases,
// queue caps, transaction leaks and aliasing of caller-owned data.
func testActionsII(t *testing.T, factory Factory) {
	ctx := context.Background()
	setup := func(t *testing.T) (store.Store, store.Actions) {
		t.Helper()
		s := open(t, factory)
		if err := s.Tenants().Create(ctx, &store.Tenant{ID: "ii", Name: "ii"}); err != nil {
			t.Fatal(err)
		}
		return s, s.Actions()
	}
	must := func(t *testing.T, e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	build := func(t *testing.T, a store.Actions) {
		t.Helper()
		must(t, a.PutBuild(ctx, &store.Build{TenantID: "ii", ID: "built", Status: store.BuildBuilt}))
		must(t, a.PutArtifact(ctx, "ii", "built", []byte("tar")))
	}
	module := func(id string) *store.ActionModule {
		return &store.ActionModule{TenantID: "ii", ID: id, Name: id, Code: "exports.x=1", DraftBuildID: "built", Secrets: []store.ActionSecret{{Name: "KEY", Sealed: []byte("sealed")}}}
	}
	t.Run("Modules", func(t *testing.T) {
		_, a := setup(t)
		build(t, a)
		m := module("m")
		must(t, a.CreateModule(ctx, m))
		m.Secrets[0].Sealed[0] = 'X'
		g, e := a.GetModuleByName(ctx, "ii", "m")
		must(t, e)
		if string(g.Secrets[0].Sealed) != "sealed" {
			t.Fatal("input alias")
		}
		g.Secrets[0].Sealed[0] = 'Y'
		g, e = a.GetModule(ctx, "ii", "m")
		must(t, e)
		if string(g.Secrets[0].Sealed) != "sealed" {
			t.Fatal("output alias")
		}
		dup := module("other")
		dup.Name = "m"
		if e = a.CreateModule(ctx, dup); !errors.Is(e, store.ErrConflict) {
			t.Fatal(e)
		}
		g.Name = "rename"
		if e = a.UpdateModule(ctx, g); !errors.Is(e, store.ErrInvalid) {
			t.Fatal("immutable name", e)
		}
		g.Name = "m"
		v, e := a.PublishModule(ctx, "ii", "m")
		must(t, e)
		if v.Number != 1 {
			t.Fatal(v)
		}
		if _, e = a.PublishModule(ctx, "ii", "m"); !errors.Is(e, store.ErrConflict) {
			t.Fatal(e)
		}
		g.Code = "exports.x=2"
		must(t, a.UpdateModule(ctx, g))
		v2, e := a.PublishModule(ctx, "ii", "m")
		must(t, e)
		g, e = a.RollbackModule(ctx, "ii", "m", v.ID)
		must(t, e)
		if g.Code != "exports.x=1" || g.LatestVersionNumber != 2 || g.AllChangesPublished {
			t.Fatal(g)
		}
		got, e := a.GetModuleVersion(ctx, "ii", "m", v2.ID)
		must(t, e)
		if got.Code != "exports.x=2" {
			t.Fatal(got)
		}
		if _, e = a.GetModule(ctx, "other", "m"); !errors.Is(e, store.ErrNotFound) {
			t.Fatal(e)
		}
		p, e := a.ListModuleVersions(ctx, "ii", "m", store.PageRequest{PerPage: 1})
		must(t, e)
		if p.Total != 2 || len(p.Items) != 1 || p.Items[0].Number != 2 {
			t.Fatal(p)
		}
		unbuilt := module("unbuilt")
		unbuilt.DraftBuildID = ""
		must(t, a.CreateModule(ctx, unbuilt))
		if _, e = a.PublishModule(ctx, "ii", "unbuilt"); !errors.Is(e, store.ErrBuildNotReady) {
			t.Fatal(e)
		}
	})

	t.Run("RevertedDraftIsUnchanged", func(t *testing.T) {
		_, a := setup(t)
		build(t, a)
		must(t, a.CreateModule(ctx, module("m")))
		_, e := a.PublishModule(ctx, "ii", "m")
		must(t, e)
		m, e := a.GetModule(ctx, "ii", "m")
		must(t, e)
		m.Code = "changed"
		must(t, a.UpdateModule(ctx, m))
		m.Code = "exports.x=1"
		must(t, a.UpdateModule(ctx, m))
		m, e = a.GetModule(ctx, "ii", "m")
		must(t, e)
		if !m.AllChangesPublished {
			t.Fatal("reverted draft must match latest snapshot")
		}
		if _, e = a.PublishModule(ctx, "ii", "m"); !errors.Is(e, store.ErrConflict) {
			t.Fatal(e)
		}
	})
	t.Run("PublishConcurrentAndLimit", func(t *testing.T) {
		_, a := setup(t)
		build(t, a)
		must(t, a.CreateModule(ctx, module("m")))
		var n atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, e := a.PublishModule(ctx, "ii", "m")
				if e == nil {
					n.Add(1)
				} else if !errors.Is(e, store.ErrConflict) {
					t.Error(e)
				}
			}()
		}
		wg.Wait()
		if n.Load() != 1 {
			t.Fatal(n.Load())
		}
		for i := 2; i <= 100; i++ {
			m, e := a.GetModule(ctx, "ii", "m")
			must(t, e)
			m.Code = fmt.Sprint(i)
			must(t, a.UpdateModule(ctx, m))
			v, e := a.PublishModule(ctx, "ii", "m")
			must(t, e)
			if v.Number != i {
				t.Fatal(v.Number)
			}
		}
		m, e := a.GetModule(ctx, "ii", "m")
		must(t, e)
		m.Code = "101"
		must(t, a.UpdateModule(ctx, m))
		if _, e = a.PublishModule(ctx, "ii", "m"); !errors.Is(e, store.ErrPrecondition) {
			t.Fatal(e)
		}
	})
	t.Run("ReferencesAndTombstones", func(t *testing.T) {
		_, a := setup(t)
		build(t, a)
		must(t, a.CreateModule(ctx, module("m")))
		v, e := a.PublishModule(ctx, "ii", "m")
		must(t, e)
		x := &store.Action{TenantID: "ii", ID: "x", Name: "x", Trigger: "post-login", DraftBuildID: "built", Modules: []store.ModuleRef{{ModuleName: "m", VersionNumber: 1}}}
		must(t, a.CreateAction(ctx, x))
		x.Modules[0].ModuleName = "mutated"
		x, e = a.GetAction(ctx, "ii", "x")
		must(t, e)
		if x.Modules[0].ModuleID != "m" || x.Modules[0].VersionID != v.ID {
			t.Fatal(x.Modules)
		}
		if e = a.DeleteModule(ctx, "ii", "m"); !errors.Is(e, store.ErrPrecondition) {
			t.Fatal(e)
		}
		old, e := a.Deploy(ctx, "ii", "x", "")
		must(t, e)
		x.Modules = nil
		must(t, a.UpdateAction(ctx, x))
		if e = a.DeleteModule(ctx, "ii", "m"); !errors.Is(e, store.ErrPrecondition) {
			t.Fatal(e)
		}
		p, e := a.ModuleUsers(ctx, "ii", "m", store.PageRequest{PerPage: 1})
		must(t, e)
		if p.Total != 1 || len(p.Items) != 1 {
			t.Fatal(p)
		}
		_, e = a.Deploy(ctx, "ii", "x", "")
		must(t, e)
		must(t, a.DeleteModule(ctx, "ii", "m"))
		if _, e = a.GetModule(ctx, "ii", "m"); !errors.Is(e, store.ErrNotFound) {
			t.Fatal(e)
		}
		_, e = a.GetModuleVersion(ctx, "ii", "m", v.ID)
		must(t, e)
		_, e = a.Deploy(ctx, "ii", "x", old.ID)
		must(t, e)
		must(t, a.DeleteAction(ctx, "ii", "x", true))
		_, e = a.PurgeJobs(ctx, time.Now())
		must(t, e)
		if _, e = a.GetModuleVersion(ctx, "ii", "m", v.ID); !errors.Is(e, store.ErrNotFound) {
			t.Fatal("unpinned tombstone", e)
		}
	})

	t.Run("ModulePagingLimitsAndResolution", func(t *testing.T) {
		_, a := setup(t)
		build(t, a)
		for i := 0; i < 100; i++ {
			must(t, a.CreateModule(ctx, module(fmt.Sprintf("m%03d", i))))
		}
		if e := a.CreateModule(ctx, module("overflow")); !errors.Is(e, store.ErrPrecondition) {
			t.Fatal(e)
		}
		p, e := a.ListModules(ctx, "ii", store.PageRequest{Page: 1, PerPage: 3})
		must(t, e)
		if p.Total != 100 || len(p.Items) != 3 || p.Items[0].ID != "m003" {
			t.Fatal(p)
		}
		v, e := a.PublishModule(ctx, "ii", "m000")
		must(t, e)
		for _, refs := range [][]store.ModuleRef{{{ModuleID: "missing", VersionID: v.ID}}, {{ModuleID: "m001", VersionID: v.ID}}, {{ModuleID: "m000", VersionID: v.ID, ModuleName: "m001", VersionNumber: 1}}, {{ModuleName: "m000", VersionNumber: 2}}, {{ModuleName: "m000", VersionNumber: 1}, {ModuleID: "m000", VersionID: v.ID}}} {
			x := &store.Action{TenantID: "ii", ID: "bad", Name: "bad", Trigger: "post-login", Modules: refs}
			if e := a.CreateAction(ctx, x); !errors.Is(e, store.ErrInvalid) {
				t.Fatalf("accepted mismatched refs %+v: %v", refs, e)
			}
		}
		for i := 0; i < 3; i++ {
			must(t, a.CreateAction(ctx, &store.Action{TenantID: "ii", ID: fmt.Sprint(i), Name: fmt.Sprint(i), Trigger: "post-login", Modules: []store.ModuleRef{{ModuleID: "m000", VersionID: v.ID}}}))
		}
		users, e := a.ModuleUsers(ctx, "ii", "m000", store.PageRequest{Page: 1, PerPage: 1})
		must(t, e)
		if users.Total != 3 || len(users.Items) != 1 || users.Items[0].ID != "1" || !users.Items[0].InDraft || users.Items[0].InDeployed {
			t.Fatal(users)
		}
	})
	t.Run("JobPinsKeepTombstonesAndNamesCanBeReused", func(t *testing.T) {
		_, a := setup(t)
		build(t, a)
		must(t, a.CreateModule(ctx, module("m")))
		v, e := a.PublishModule(ctx, "ii", "m")
		must(t, e)
		now := time.Now().UTC()
		must(t, a.CreateExecution(ctx, &store.Execution{TenantID: "ii", ID: "run", Trigger: "post-change-password"}))
		must(t, a.EnqueueJob(ctx, &store.ActionJob{TenantID: "ii", ID: "j", Trigger: "post-change-password", ModuleVersionIDs: []string{v.ID}, NextAt: now}))
		must(t, a.DeleteModule(ctx, "ii", "m"))
		_, e = a.GetModuleVersion(ctx, "ii", "m", v.ID)
		must(t, e)
		replacement := module("replacement")
		replacement.Name = "m"
		must(t, a.CreateModule(ctx, replacement))
		if e = a.CreateModule(ctx, module("m")); !errors.Is(e, store.ErrConflict) {
			t.Fatal(e)
		}
		jobs, e := a.ClaimJobs(ctx, now, time.Minute, 1)
		must(t, e)
		if len(jobs) != 1 {
			t.Fatal(jobs)
		}
		jobs[0].Status = "failed"
		jobs[0].ExecutionIDs = []string{"run"}
		must(t, a.FinishJob(ctx, &jobs[0], jobs[0].LeaseUntil))
		_, e = a.PurgeJobs(ctx, now.Add(time.Hour))
		must(t, e)
		if _, e = a.GetModuleVersion(ctx, "ii", "m", v.ID); !errors.Is(e, store.ErrNotFound) {
			t.Fatal(e)
		}
		if _, e = a.GetExecution(ctx, "ii", "run"); !errors.Is(e, store.ErrNotFound) {
			t.Fatal(e)
		}
	})
	t.Run("Jobs", func(t *testing.T) {
		_, a := setup(t)
		now := time.Now().UTC().Truncate(time.Second)
		for i := 0; i < 3; i++ {
			j := &store.ActionJob{TenantID: "ii", ID: fmt.Sprint(i), Trigger: "post-user-registration", Sealed: []byte("sealed"), NextAt: now.Add(time.Duration(2-i) * time.Second)}
			must(t, a.EnqueueJob(ctx, j))
			j.Sealed[0] = 'X'
		}
		jobs, e := a.ClaimJobs(ctx, now.Add(3*time.Second), time.Minute, 1)
		must(t, e)
		if len(jobs) != 1 || jobs[0].ID != "2" || string(jobs[0].Sealed) != "sealed" {
			t.Fatal(jobs)
		}
		lease := jobs[0].LeaseUntil
		old := jobs[0]
		old.Status = "done"
		if e = a.FinishJob(ctx, &old, lease.Add(time.Second)); !errors.Is(e, store.ErrConflict) {
			t.Fatal(e)
		}
		others, e := a.ClaimJobs(ctx, now.Add(3*time.Second), time.Minute, 3)
		must(t, e)
		if len(others) != 2 || others[0].ID != "1" || others[1].ID != "0" {
			t.Fatal(others)
		}
		retry, e := a.ClaimJobs(ctx, lease, time.Minute, 1)
		must(t, e)
		if len(retry) != 1 || retry[0].ID != "2" {
			t.Fatal(retry)
		}
		if e = a.FinishJob(ctx, &old, lease); !errors.Is(e, store.ErrConflict) {
			t.Fatal(e)
		}
		retry[0].Status = "done"
		must(t, a.FinishJob(ctx, &retry[0], retry[0].LeaseUntil))
		n, e := a.PurgeJobs(ctx, now.Add(time.Hour))
		must(t, e)
		if n != 1 {
			t.Fatal(n)
		}
	})
	t.Run("QueueCap", func(t *testing.T) {
		_, a := setup(t)
		for i := 0; i < 10000; i++ {
			must(t, a.EnqueueJob(ctx, &store.ActionJob{TenantID: "ii", ID: fmt.Sprint(i), Trigger: "post-change-password"}))
		}
		if e := a.EnqueueJob(ctx, &store.ActionJob{TenantID: "ii", ID: "overflow", Trigger: "post-change-password"}); !errors.Is(e, store.ErrPrecondition) {
			t.Fatal(e)
		}
	})
	t.Run("TransactionAndTenantCleanup", func(t *testing.T) {
		s, a := setup(t)
		boom := errors.New("rollback")
		e := s.WithTx(ctx, func(tx store.Store) error {
			must(t, tx.Actions().CreateModule(ctx, module("m")))
			must(t, tx.Actions().EnqueueJob(ctx, &store.ActionJob{TenantID: "ii", ID: "j", Trigger: "post-user-registration"}))
			return boom
		})
		if !errors.Is(e, boom) {
			t.Fatal(e)
		}
		if _, e = a.GetModule(ctx, "ii", "m"); !errors.Is(e, store.ErrNotFound) {
			t.Fatal(e)
		}
		jobs, e := a.ClaimJobs(ctx, time.Now(), time.Minute, 5)
		must(t, e)
		if len(jobs) != 0 {
			t.Fatal(jobs)
		}
		must(t, a.CreateModule(ctx, module("m")))
		must(t, a.EnqueueJob(ctx, &store.ActionJob{TenantID: "ii", ID: "j", Trigger: "post-user-registration"}))
		must(t, s.Tenants().Delete(ctx, "ii"))
		p, e := a.ListModules(ctx, "ii", store.PageRequest{})
		must(t, e)
		if p.Total != 0 {
			t.Fatal(p)
		}
		jobs, e = a.ClaimJobs(ctx, time.Now(), time.Minute, 5)
		must(t, e)
		if len(jobs) != 0 {
			t.Fatal(jobs)
		}
	})
	t.Run("ChallengeAndPasswordTime", func(t *testing.T) {
		s, _ := setup(t)
		now := time.Now().UTC().Truncate(time.Second)
		must(t, s.Users().Create(ctx, &store.User{TenantID: "ii", UserID: "auth0|ii", LastPasswordReset: &now}))
		u, e := s.Users().Get(ctx, "ii", "auth0|ii")
		must(t, e)
		if u.LastPasswordReset == nil || !u.LastPasswordReset.Equal(now) {
			t.Fatal(u)
		}
		*u.LastPasswordReset = now.Add(time.Hour)
		u, e = s.Users().Get(ctx, "ii", "auth0|ii")
		must(t, e)
		if !u.LastPasswordReset.Equal(now) {
			t.Fatal("password timestamp alias")
		}
		must(t, s.PasswordResetTickets().Create(ctx, &store.PasswordResetTicket{TenantID: "ii", ID: "t", TokenHash: "hash", ExpiresAt: now.Add(time.Hour)}))
		must(t, s.PasswordResetTickets().MarkChallengePassed(ctx, "ii", "hash", now, "https://example.test"))
		ticket, e := s.PasswordResetTickets().GetByTokenHash(ctx, "ii", "hash")
		must(t, e)
		if ticket.ChallengePassedAt == nil || !ticket.ChallengePassedAt.Equal(now) || ticket.ChallengeResultURL != "https://example.test" || ticket.UsedAt != nil {
			t.Fatal(ticket)
		}
		if e = s.PasswordResetTickets().MarkChallengePassed(ctx, "other", "hash", now, ""); !errors.Is(e, store.ErrNotFound) {
			t.Fatal(e)
		}
		_, e = s.PasswordResetTickets().Consume(ctx, "ii", "hash", now)
		must(t, e)
		if e = s.PasswordResetTickets().MarkChallengePassed(ctx, "ii", "hash", now, ""); !errors.Is(e, store.ErrAlreadyUsed) {
			t.Fatal(e)
		}
	})
}
