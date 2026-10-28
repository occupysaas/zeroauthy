package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Catches a migration that drops existing Actions, or leaves upgraded databases
// with different columns from fresh installations.
func TestActionsIIMigration(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			old := openAtVersion(t, mk(t), 23)
			insertLegacyUser(t, old, &store.User{TenantID: "legacy", UserID: "auth0|u", Email: "legacy@example.test"})
			mustExec(t, old, `INSERT INTO tenants (id,name,friendly_name,default_audience,allowed_logout_urls,enabled_locales,custom_text,session_lifetime,idle_session_lifetime,logo_url,primary_color,default_directory,created_at) VALUES ('legacy','legacy','','','[]','[]','{}',0,0,'','','',1)`)
			mustExec(t, old, `INSERT INTO actions (tenant_id,id,name,trigger_id,runtime,code,dependencies,secrets,draft_build_id,deployed_version_id,created_at,updated_at) VALUES ('legacy','a','a','post-login','node22','old code','[]','[]','','v',1,2)`)
			mustExec(t, old, `INSERT INTO action_versions (tenant_id,id,action_id,number,code,runtime,build_id,dependencies,secrets,created_at) VALUES ('legacy','v','a',1,'published code','node22','b','[]','[]',1)`)
			mustExec(t, old, `INSERT INTO password_reset_tickets (tenant_id,id,token_hash,user_id,connection,client_id,lang,expires_at,used_at,created_at,result_url,include_email_in_redirect,mark_email_verified,origin) VALUES ('legacy','ticket','hash','u','','','',9999999999999999,NULL,1,'',false,false,'')`)
			if err := old.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			if old.LatestVersion() < 24 {
				t.Fatal("Actions II migration missing")
			}
			a, err := old.Actions().GetAction(ctx, "legacy", "a")
			if err != nil || a.Code != "old code" || len(a.Modules) != 0 {
				t.Fatalf("legacy Action: %+v %v", a, err)
			}
			v, err := old.Actions().GetVersion(ctx, "legacy", "a", "v")
			if err != nil || v.Code != "published code" || len(v.Modules) != 0 {
				t.Fatalf("legacy version: %+v %v", v, err)
			}
			ticket, err := old.PasswordResetTickets().GetByTokenHash(ctx, "legacy", "hash")
			if err != nil || ticket.ChallengePassedAt != nil || ticket.ChallengeResultURL != "" {
				t.Fatalf("legacy ticket: %+v %v", ticket, err)
			}
			user, err := old.Users().Get(ctx, "legacy", "auth0|u")
			if err != nil || user.Email != "legacy@example.test" || user.LastPasswordReset != nil {
				t.Fatalf("legacy user: %+v %v", user, err)
			}
			fresh := mustOpen(t, mk(t))
			for _, table := range []string{"actions", "action_versions", "action_modules", "action_module_versions", "action_jobs", "users", "password_reset_tickets"} {
				got, want := tableShape(t, old, table), tableShape(t, fresh, table)
				if len(want) == 0 || !slices.Equal(got, want) {
					t.Errorf("%s: upgraded %v != fresh %v", table, got, want)
				}
				if got, want := actionsIISchemaDefinition(t, old, table), actionsIISchemaDefinition(t, fresh, table); !slices.Equal(got, want) {
					t.Errorf("%s: upgraded definitions %v != fresh %v", table, got, want)
				}
			}
		})
	}
}

// Catches unlocked publish counters, duplicate worker claims, and deleted pins
// being resurrected or lost by deployment racing with module deletion.
func TestActionsIIConcurrency(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mk(t)
			a := s.Actions()
			must := func(t *testing.T, err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(t, s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			must(t, a.PutBuild(ctx, &store.Build{TenantID: "t", ID: "b", Status: store.BuildBuilt}))
			must(t, a.PutArtifact(ctx, "t", "b", []byte("tar")))
			module := func(id string) *store.ActionModule {
				return &store.ActionModule{TenantID: "t", ID: id, Name: id, Code: "initial", DraftBuildID: "b"}
			}
			t.Run("publish numbering", func(t *testing.T) {
				must(t, a.CreateModule(ctx, module("numbers")))
				const n = 12
				var wg sync.WaitGroup
				nums := make(chan int, n)
				for i := range n {
					wg.Go(func() {
						// An edit+publish is one caller transaction, so every successful
						// publication has distinct draft content.
						err := s.WithTx(ctx, func(tx store.Store) error {
							m, err := tx.Actions().GetModule(ctx, "t", "numbers")
							if err != nil {
								return err
							}
							m.Code = fmt.Sprint(i)
							if err = tx.Actions().UpdateModule(ctx, m); err != nil {
								return err
							}
							v, err := tx.Actions().PublishModule(ctx, "t", "numbers")
							if err == nil {
								nums <- v.Number
							}
							return err
						})
						if err != nil {
							t.Error(err)
						}
					})
				}
				wg.Wait()
				close(nums)
				var got []int
				for n := range nums {
					got = append(got, n)
				}
				slices.Sort(got)
				if len(got) != n {
					t.Fatalf("numbers %v", got)
				}
				for i, v := range got {
					if v != i+1 {
						t.Fatalf("numbers %v", got)
					}
				}
			})
			t.Run("disjoint worker claims", func(t *testing.T) {
				now := time.Now().UTC().Truncate(time.Second)
				for i := range 20 {
					must(t, a.EnqueueJob(ctx, &store.ActionJob{TenantID: "t", ID: fmt.Sprint(i), Trigger: "post-user-registration", NextAt: now}))
				}

				var wg sync.WaitGroup
				results := make(chan []store.ActionJob, 2)
				start := make(chan struct{})
				if s.d.name == "sqlite" {
					for range 2 {
						wg.Go(func() {
							<-start
							js, err := a.ClaimJobs(ctx, now, time.Minute, 10)
							if err != nil {
								t.Error(err)
							}
							results <- js
						})
					}
					close(start)
				} else {
					// Hold the first claim's transaction open. The second worker
					// must skip its ten locked rows and claim the other ten before
					// the first transaction commits, without waiting on its lease.
					ready, release := make(chan struct{}), make(chan struct{})
					wg.Go(func() {
						err := s.WithTx(ctx, func(tx store.Store) error {
							js, err := tx.Actions().ClaimJobs(ctx, now, time.Minute, 10)
							results <- js
							close(ready)
							<-release
							return err
						})
						if err != nil {
							t.Error(err)
						}
					})
					<-ready
					claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					js, err := a.ClaimJobs(claimCtx, now, time.Minute, 10)
					cancel()
					close(release)
					if err != nil {
						t.Error(err)
					}
					results <- js
				}
				wg.Wait()
				close(results)
				seen := map[string]bool{}
				for js := range results {
					if len(js) != 10 {
						t.Errorf("claimed %d, want 10", len(js))
					}
					for _, j := range js {
						if seen[j.ID] {
							t.Errorf("duplicate claim %s", j.ID)
						}
						seen[j.ID] = true
						if j.Attempts != 1 {
							t.Errorf("attempts %d", j.Attempts)
						}
					}
				}
				if len(seen) != 20 {
					t.Fatalf("claimed %d unique jobs", len(seen))
				}
			})
			t.Run("delete versus old version deploy", func(t *testing.T) {
				for i := range 12 {
					id := fmt.Sprintf("race%d", i)
					must(t, a.CreateModule(ctx, module(id)))
					mv, err := a.PublishModule(ctx, "t", id)
					must(t, err)
					x := &store.Action{TenantID: "t", ID: id, Name: id, Trigger: "post-login", DraftBuildID: "b", Modules: []store.ModuleRef{{ModuleID: id, VersionID: mv.ID}}}
					must(t, a.CreateAction(ctx, x))
					old, err := a.Deploy(ctx, "t", id, "")
					must(t, err)
					x.Modules = nil
					must(t, a.UpdateAction(ctx, x))
					_, err = a.Deploy(ctx, "t", id, "")
					must(t, err)
					var wg sync.WaitGroup
					var deployErr, delErr error
					wg.Go(func() { _, deployErr = a.Deploy(ctx, "t", id, old.ID) })
					wg.Go(func() { delErr = a.DeleteModule(ctx, "t", id) })
					wg.Wait()
					if deployErr != nil || delErr != nil && !errors.Is(delErr, store.ErrPrecondition) {
						t.Fatalf("deploy=%v delete=%v", deployErr, delErr)
					}
					got, err := a.GetModuleVersion(ctx, "t", id, mv.ID)
					must(t, err)
					if got.Code != "initial" {
						t.Fatalf("pin changed: %+v", got)
					}
					x, err = a.GetAction(ctx, "t", id)
					must(t, err)
					v, err := a.GetVersion(ctx, "t", id, x.DeployedVersionID)
					must(t, err)
					if len(v.Modules) != 1 || v.Modules[0].VersionID != mv.ID {
						t.Fatalf("lost deployment pin: %+v", v)
					}
					must(t, a.DeleteAction(ctx, "t", id, true))
				}
			})
		})
	}
}

// Catches byte-sized MySQL names rejecting the documented 255 Unicode chars.
func TestActionsIIUnicodeNames(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mk(t)
			if err := s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			moduleName := ""
			for range 255 {
				moduleName += "界"
			}
			if err := s.Actions().CreateModule(ctx, &store.ActionModule{TenantID: "t", ID: "unicode", Name: moduleName}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Actions().GetModuleByName(ctx, "t", moduleName)
			if err != nil || got.Name != moduleName {
				t.Fatalf("Unicode name: %+v %v", got, err)
			}
		})
	}
}

// Catches a cap check outside the enqueue transaction, mutable sealed payloads
// on finish, missing tenant predicates, and challenge writes that revive expiry.
func TestActionsIIQueueAndTicketEdges(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := mk(t)
			a := s.Actions()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, tid := range []string{"t", "other"} {
				must(s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
			}
			// Build a near-cap fixture efficiently; only the two racing enqueue calls
			// exercise the boundary, through the real repository transaction.
			for batch := 0; batch < 20; batch++ {
				values := []string{}
				args := []any{}
				for i := batch * 500; i < min((batch+1)*500, 9999); i++ {
					values = append(values, "(?,?,?,?,?,?,?,?,?,?,?,?)")
					args = append(args, "t", fmt.Sprint(i), "post-change-password", "pending", []byte("sealed"), 0, int64(1), int64(0), "[]", "[]", int64(1), int64(1))
				}
				mustExec(t, s, `INSERT INTO action_jobs (tenant_id,id,trigger_id,status,sealed,attempts,next_at,lease_until,execution_ids,module_version_ids,created_at,updated_at) VALUES `+strings.Join(values, ","), args...)
			}
			var wg sync.WaitGroup
			errs := make(chan error, 2)
			start := make(chan struct{})
			for _, id := range []string{"last", "overflow"} {
				wg.Go(func() {
					<-start
					errs <- a.EnqueueJob(ctx, &store.ActionJob{TenantID: "t", ID: id, Trigger: "post-change-password"})
				})
			}
			close(start)
			wg.Wait()
			close(errs)
			success, full := 0, 0
			for err := range errs {
				if err == nil {
					success++
				} else if errors.Is(err, store.ErrPrecondition) {
					full++
				} else {
					t.Fatal(err)
				}
			}
			if success != 1 || full != 1 {
				t.Fatalf("enqueue race: success=%d full=%d", success, full)
			}
			must(a.EnqueueJob(ctx, &store.ActionJob{TenantID: "other", ID: "0", Trigger: "post-user-registration", Sealed: []byte("other event"), NextAt: time.Unix(0, 0)}))
			now := time.Now().UTC()
			jobs, err := a.ClaimJobs(ctx, now, time.Minute, 1)
			must(err)
			if len(jobs) != 1 || jobs[0].TenantID != "other" {
				t.Fatalf("claim order: %+v", jobs)
			}
			job := jobs[0]
			job.Status = "pending"
			job.Sealed = []byte("tampered")
			job.Trigger = "custom-email-provider"
			job.Attempts = 100
			job.ModuleVersionIDs = []string{"missing"}
			job.NextAt = time.Unix(0, 0)
			must(a.FinishJob(ctx, &job, job.LeaseUntil))
			jobs, err = a.ClaimJobs(ctx, now, time.Minute, 1)
			must(err)
			if len(jobs) != 1 || jobs[0].TenantID != "other" || string(jobs[0].Sealed) != "other event" || jobs[0].Trigger != "post-user-registration" || jobs[0].Attempts != 2 || len(jobs[0].ModuleVersionIDs) != 0 {
				t.Fatalf("worker changed immutable event: %+v", jobs)
			}
			job = jobs[0]
			job.Status = "done"
			job.ExecutionIDs = []string{"shared-run"}
			for _, tid := range []string{"t", "other"} {
				must(a.CreateExecution(ctx, &store.Execution{TenantID: tid, ID: "shared-run", Trigger: "post-change-password"}))
			}
			must(a.FinishJob(ctx, &job, job.LeaseUntil))
			if err = a.FinishJob(ctx, &job, job.LeaseUntil); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("finished lease reused: %v", err)
			}
			if err = a.FinishJob(ctx, &store.ActionJob{TenantID: "missing", ID: "0", Status: "done"}, job.LeaseUntil); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("cross tenant finish: %v", err)
			}
			purged, err := a.PurgeJobs(ctx, now.Add(time.Hour))
			must(err)
			if purged != 1 {
				t.Fatalf("purged %d terminal jobs, want 1", purged)
			}
			if _, err = a.GetExecution(ctx, "other", "shared-run"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("purged execution retained: %v", err)
			}
			if _, err = a.GetExecution(ctx, "t", "shared-run"); err != nil {
				t.Fatalf("other tenant execution purged: %v", err)
			}
			remaining, err := a.ClaimJobs(ctx, now, time.Minute, 1)
			must(err)
			if len(remaining) != 1 || remaining[0].TenantID != "t" {
				t.Fatalf("pending jobs purged: %+v", remaining)
			}
			must(s.PasswordResetTickets().Create(ctx, &store.PasswordResetTicket{TenantID: "t", ID: "expired", TokenHash: "expired", ExpiresAt: now}))
			if err = s.PasswordResetTickets().MarkChallengePassed(ctx, "t", "expired", now, "https://example.test"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("expired challenge passed: %v", err)
			}
			ticket, err := s.PasswordResetTickets().GetByTokenHash(ctx, "t", "expired")
			must(err)
			if ticket.ChallengePassedAt != nil || ticket.UsedAt != nil {
				t.Fatalf("expired ticket changed: %+v", ticket)
			}
			past := now.Add(-time.Hour).Truncate(time.Microsecond)
			must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "u"}))
			u, err := s.Users().Get(ctx, "t", "u")
			must(err)
			u.LastPasswordReset = &past
			must(s.Users().Update(ctx, u))
			u, err = s.Users().Get(ctx, "t", "u")
			must(err)
			if u.LastPasswordReset == nil || !u.LastPasswordReset.Equal(past) {
				t.Fatalf("password reset update: %+v", u)
			}
		})
	}
}

// Compare defaults, indexes, keys and references as well as column shapes.
func actionsIISchemaDefinition(t *testing.T, s *Store, table string) []string {
	t.Helper()
	ctx := context.Background()
	if s.d.name == "mysql" {
		var name, definition string
		if err := s.queryRow(ctx, `SHOW CREATE TABLE `+table).Scan(&name, &definition); err != nil {
			t.Fatal(err)
		}
		return []string{definition}
	}
	q := `SELECT type || ' ' || sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL`
	args := []any{table}
	if s.d.name == "postgres" {
		q = `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND tablename=? UNION ALL SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=current_schema() AND t.relname=?`
		args = append(args, table)
	}
	rows, err := s.query(ctx, q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var definition string
		if err = rows.Scan(&definition); err != nil {
			t.Fatal(err)
		}
		out = append(out, definition)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}
