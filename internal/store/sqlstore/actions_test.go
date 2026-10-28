package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

var actionTables = []string{"actions", "action_versions", "action_builds", "action_artifacts", "action_bindings", "action_binding_sets", "action_executions", "action_continues"}

// tableShape lists "column type nullability" for a table, per dialect.
func tableShape(t *testing.T, s *Store, table string) []string {
	t.Helper()
	ctx := context.Background()
	var q string
	switch s.d.name {
	case "sqlite":
		q = `SELECT name, UPPER(type), CASE WHEN "notnull" THEN 'NOT NULL' ELSE 'NULL' END FROM pragma_table_info(?)`
	case "postgres":
		q = `SELECT column_name, UPPER(data_type), is_nullable FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=?`
	default:
		q = `SELECT column_name, UPPER(column_type), is_nullable FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=?`
	}
	rows, err := s.query(ctx, q, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n, ty, null string
		if err := rows.Scan(&n, &ty, &null); err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.ToLower(n)+" "+ty+" "+strings.TrimPrefix(null, "NO"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

func TestActionsMigration(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			old := openAtVersion(t, mk(t), 22)
			for _, table := range actionTables {
				if _, err := old.query(ctx, `SELECT 1 FROM `+table+` WHERE 1=0`); err == nil {
					t.Fatalf("%s exists before 0023", table)
				}
			}
			if err := old.Tenants().Create(ctx, &store.Tenant{ID: "legacy", Name: "legacy"}); err != nil {
				t.Fatal(err)
			}
			if err := old.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			if old.LatestVersion() < 23 {
				t.Fatal("Actions migration missing")
			}
			if _, err := old.Tenants().Get(ctx, "legacy"); err != nil {
				t.Fatalf("legacy tenant lost: %v", err)
			}
			a := &store.Action{TenantID: "legacy", ID: "a1", Name: "Upgraded", Trigger: "post-login", Runtime: "node22", Code: "// x"}
			if err := old.Actions().CreateAction(ctx, a); err != nil {
				t.Fatal(err)
			}
			fresh := mustOpen(t, mk(t))
			// 0023 also adds the sealed post-login effects to codes.
			for _, table := range []string{"auth_codes", "device_codes"} {
				shape := tableShape(t, fresh, table)
				want := map[string]string{"sqlite": "action_effects BLOB NULL", "postgres": "action_effects BYTEA YES",
					"mysql": "action_effects LONGBLOB YES"}[fresh.d.name]
				if !slices.Contains(shape, want) {
					t.Errorf("%s: no %q column in %v", table, want, shape)
				}
				if got := tableShape(t, old, table); !slices.Equal(got, shape) {
					t.Errorf("%s: upgraded %v != fresh %v", table, got, shape)
				}
			}
			for _, table := range actionTables {
				if got, want := tableShape(t, old, table), tableShape(t, fresh, table); len(want) == 0 || !slices.Equal(got, want) {
					t.Errorf("%s: upgraded %v != fresh %v", table, got, want)
				}
			}
			var typ string
			for _, c := range tableShape(t, fresh, "action_artifacts") {
				if strings.HasPrefix(c, "data ") {
					typ = c
				}
			}
			want := map[string]string{"sqlite": "BLOB", "postgres": "BYTEA", "mysql": "LONGBLOB"}[fresh.d.name]
			if !strings.Contains(typ, want) {
				t.Errorf("artifact column %q, want %s", typ, want)
			}
			// Artifacts round-trip bytes exactly, including NUL and invalid UTF-8.
			if err := fresh.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
				t.Fatal(err)
			}
			if err := fresh.Actions().PutBuild(ctx, &store.Build{TenantID: "t", ID: "b", Status: store.BuildBuilt}); err != nil {
				t.Fatal(err)
			}
			blob := []byte{0, 0xff, 0xfe, 'a', 0, 0x80}
			if err := fresh.Actions().PutArtifact(ctx, "t", "b", blob); err != nil {
				t.Fatal(err)
			}
			got, err := fresh.Actions().GetArtifact(ctx, "t", "b")
			if err != nil || string(got) != string(blob) {
				t.Fatalf("artifact bytes: %v %v", got, err)
			}
		})
	}
}

func TestActionsConcurrency(t *testing.T) {
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
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
			must(a.PutBuild(ctx, &store.Build{TenantID: "t", ID: "b", Status: store.BuildBuilt, Resolved: []store.Dependency{}}))
			must(a.PutArtifact(ctx, "t", "b", []byte("tar")))
			mk := func(id string) {
				must(a.CreateAction(ctx, &store.Action{TenantID: "t", ID: id, Name: id, Trigger: "post-login", Runtime: "node22", DraftBuildID: "b"}))
			}

			t.Run("deploy numbering", func(t *testing.T) {
				mk("dep")
				const n = 12
				nums := make(chan int, n)
				var wg sync.WaitGroup
				for range n {
					wg.Go(func() {
						v, err := a.Deploy(ctx, "t", "dep", "")
						if err != nil {
							t.Error(err)
							return
						}
						nums <- v.Number
					})
				}
				wg.Wait()
				close(nums)
				var got []int
				for v := range nums {
					got = append(got, v)
				}
				slices.Sort(got)
				for i, v := range got {
					if v != i+1 {
						t.Fatalf("numbers %v", got)
					}
				}
				if len(got) != n {
					t.Fatalf("numbers %v", got)
				}
			})

			t.Run("bind versus delete", func(t *testing.T) {
				for i := range 15 {
					id := fmt.Sprintf("bd%d", i)
					mk(id)
					_, err := a.Deploy(ctx, "t", id, "")
					must(err)
					var wg sync.WaitGroup
					var bindErr, delErr error
					wg.Go(func() {
						_, bindErr = a.ReplaceBindings(ctx, "t", "post-login", []store.Binding{{ID: "bnd" + id, ActionID: id}})
					})
					wg.Go(func() { delErr = a.DeleteAction(ctx, "t", id, false) })
					wg.Wait()
					switch {
					case bindErr == nil && errors.Is(delErr, store.ErrConflict):
					case errors.Is(bindErr, store.ErrInvalid) && delErr == nil:
					case bindErr == nil && delErr == nil:
						t.Fatalf("iteration %d: both won: the Action was deleted while bound", i)
					default:
						t.Fatalf("iteration %d: bind=%v delete=%v", i, bindErr, delErr)
					}
					var orphans int
					must(s.queryRow(ctx, `SELECT COUNT(*) FROM action_bindings b WHERE NOT EXISTS (SELECT 1 FROM actions x WHERE x.tenant_id=b.tenant_id AND x.id=b.action_id)`).Scan(&orphans))
					if orphans != 0 {
						t.Fatalf("iteration %d: %d orphan bindings", i, orphans)
					}
					if _, err := a.Bindings(ctx, "t", "post-login"); err != nil {
						t.Fatalf("iteration %d: snapshot: %v", i, err)
					}
					_, err = a.ReplaceBindings(ctx, "t", "post-login", nil)
					must(err)
				}
			})

			t.Run("consume continue", func(t *testing.T) {
				now := time.Now().UTC().Truncate(time.Second)
				for i := range 10 {
					h := fmt.Sprintf("h%d", i)
					must(a.CreateContinue(ctx, &store.ContinueState{TenantID: "t", StateHash: h, SessionID: "s", Sealed: []byte("x"), ExpiresAt: now.Add(time.Hour), CreatedAt: now}))
					var wins atomic.Int32
					var wg sync.WaitGroup
					for range 8 {
						wg.Go(func() {
							if _, err := a.ConsumeContinue(ctx, "t", h, now); err == nil {
								wins.Add(1)
							} else if !errors.Is(err, store.ErrNotFound) {
								t.Error(err)
							}
						})
					}
					wg.Wait()
					if wins.Load() != 1 {
						t.Fatalf("%s: %d winners", h, wins.Load())
					}
				}
			})
		})
	}
}

func TestActionsSeedBindings(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.ActionsSeedBindings(t, func(t *testing.T) store.Store { return mustOpen(t, mk(t)) })
		})
	}
}

func TestActionsSeedBindingsRestartAndLegacy(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dsn := mk(t)
			s := mustOpen(t, dsn)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Tenants().Create(ctx, &store.Tenant{ID: "restart", Name: "restart"}))
			must(s.Actions().PutBuild(ctx, &store.Build{TenantID: "restart", ID: "built", Status: store.BuildBuilt}))
			must(s.Actions().PutArtifact(ctx, "restart", "built", []byte("artifact")))
			must(s.Actions().CreateAction(ctx, &store.Action{TenantID: "restart", ID: "a", Name: "a", Trigger: "post-login", Runtime: "node22", DraftBuildID: "built"}))
			_, err := s.Actions().Deploy(ctx, "restart", "a", "")
			must(err)
			seed := []store.Binding{{ActionID: "a", DisplayName: "seed"}}
			_, err = s.Actions().InitializeBindings(ctx, "restart", "post-login", seed)
			must(err)
			// Simulate legacy nonempty binding rows with no durable marker.
			_, err = s.exec(ctx, `DELETE FROM action_binding_sets WHERE tenant_id=?`, "restart")
			must(err)
			got, err := s.Actions().InitializeBindings(ctx, "restart", "post-login", []store.Binding{})
			must(err)
			if len(got) != 1 || got[0].DisplayName != "seed" {
				t.Fatal("legacy nonempty binding overwritten")
			}
			var count int
			must(s.queryRow(ctx, `SELECT COUNT(*) FROM action_binding_sets WHERE tenant_id=?`, "restart").Scan(&count))
			if count != 1 {
				t.Fatal("legacy marker not backfilled")
			}
			_, err = s.Actions().ReplaceBindings(ctx, "restart", "post-login", nil)
			must(err)
			must(s.Close())
			reopened := mustOpen(t, dsn)
			initialized, err := reopened.Actions().BindingsInitialized(ctx, "restart", "post-login")
			must(err)
			if !initialized {
				t.Fatal("explicit empty initialization did not survive database reopen")
			}
			got, err = reopened.Actions().InitializeBindings(ctx, "restart", "post-login", seed)
			must(err)
			if len(got) != 0 {
				t.Fatal("database restart reenabled disabled flow")
			}
		})
	}
}

// Public caller transactions may read before the repository acquires its
// Actions lock. MySQL must not retain that earlier consistent-read snapshot.
func TestActionsSeedBindingsCallerTransactionFresh(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		if name == "sqlite" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			s := mustOpen(t, mk(t))
			if err := s.Tenants().Create(ctx, &store.Tenant{ID: "caller", Name: "caller"}); err != nil {
				t.Fatal(err)
			}
			err := s.WithTx(ctx, func(tx store.Store) error {
				initialized, err := tx.Actions().BindingsInitialized(ctx, "caller", "post-login")
				if err != nil {
					return err
				}
				if initialized {
					return errors.New("unexpected initial marker")
				}
				// A different connection commits a management clear after the caller's
				// first read and before InitializeBindings takes the tenant writer lock.
				if _, err := s.Actions().ReplaceBindings(ctx, "caller", "post-login", nil); err != nil {
					return err
				}
				bs, err := tx.Actions().InitializeBindings(ctx, "caller", "post-login", []store.Binding{{ActionID: "obsolete-seed-ref"}})
				if err != nil {
					return err
				}
				if len(bs) != 0 {
					return errors.New("caller snapshot resurrected bindings")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
