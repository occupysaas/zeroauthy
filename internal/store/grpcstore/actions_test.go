package grpcstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestActionsPluginRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	if err := c.CheckActionsSupport(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	a := c.Actions()
	now := time.Now().UTC().Truncate(time.Second)
	act := &store.Action{
		TenantID: "t", ID: "act_1", Name: "Every Field", Trigger: "post-login", Runtime: "node22",
		Code:         "exports.onExecutePostLogin = async () => {}",
		Dependencies: []store.Dependency{{Name: "lodash", Version: "4.17.21"}, {Name: "left-pad"}},
		Secrets: []store.ActionSecret{{Name: "KEY", Sealed: []byte{0, 1, 2, 255}, UpdatedAt: now},
			{Name: "OTHER", Sealed: []byte("sealed"), UpdatedAt: now.Add(time.Second)}},
		DraftBuildID: "b1", CreatedAt: now, UpdatedAt: now,
	}
	if err := a.CreateAction(ctx, act); err != nil {
		t.Fatal(err)
	}
	got, err := a.GetAction(ctx, "t", "act_1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, act) {
		t.Fatalf("action\n got %+v\nwant %+v", got, act)
	}
	if by, err := a.GetActionByName(ctx, "t", "Every Field"); err != nil || by.ID != "act_1" {
		t.Fatalf("by name: %+v %v", by, err)
	}

	build := &store.Build{TenantID: "t", ID: "b1", Status: store.BuildBuilt,
		Requested: []store.Dependency{{Name: "lodash"}}, Resolved: []store.Dependency{{Name: "lodash", Version: "4.17.21"}},
		Errors: []string{"warn one", "warn two"}, ArtifactSHA256: "abc123", BuiltAt: now}
	if err := a.PutBuild(ctx, build); err != nil {
		t.Fatal(err)
	}
	gb, err := a.GetBuild(ctx, "t", "b1")
	if err != nil || !reflect.DeepEqual(gb, build) {
		t.Fatalf("build %+v %v", gb, err)
	}

	// Artifacts above gRPC's 4 MB default message size travel in chunks.
	tar := make([]byte, 5<<20+17)
	for i := range tar {
		tar[i] = byte(i * 31)
	}
	if err := a.PutArtifact(ctx, "t", "b1", tar); err != nil {
		t.Fatal(err)
	}
	back, err := a.GetArtifact(ctx, "t", "b1")
	if err != nil || !bytes.Equal(back, tar) {
		t.Fatalf("artifact round trip: len %d err %v", len(back), err)
	}
	if _, err := a.GetArtifact(ctx, "t", "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing artifact: %v", err)
	}
	if err := a.PutArtifact(ctx, "t", "missing", []byte("x")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("artifact without build: %v", err)
	}
	if err := a.PutArtifact(ctx, "t", "b1", make([]byte, 51<<20)); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("oversize artifact: %v", err)
	}

	v1, err := a.Deploy(ctx, "t", "act_1", "")
	if err != nil || v1.Number != 1 || v1.BuildID != "b1" || len(v1.Secrets) != 2 || v1.Secrets[0].Sealed[3] != 255 {
		t.Fatalf("deploy %+v %v", v1, err)
	}
	gv, err := a.GetVersion(ctx, "t", "act_1", v1.ID)
	if err != nil || !reflect.DeepEqual(gv, v1) {
		t.Fatalf("version %+v %v", gv, err)
	}
	if vs, err := a.ListVersions(ctx, "t", "act_1", store.PageRequest{}); err != nil || vs.Total != 1 || !reflect.DeepEqual(vs.Items[0], *v1) {
		t.Fatalf("versions %+v %v", vs, err)
	}
	if l, err := a.ListActions(ctx, "t", store.ActionFilter{Trigger: "post-login"}); err != nil || l.Total != 1 || l.Items[0].DeployedVersionID != v1.ID {
		t.Fatalf("list %+v %v", l, err)
	}

	bound, err := a.ReplaceBindings(ctx, "t", "post-login", []store.Binding{{ActionID: "act_1", ID: "bind_1", DisplayName: "Shown"}})
	if err != nil || len(bound) != 1 || bound[0].Version.ID != v1.ID || bound[0].DisplayName != "Shown" || bound[0].Action.Name != "Every Field" {
		t.Fatalf("bindings %+v %v", bound, err)
	}
	snap, err := a.Bindings(ctx, "t", "post-login")
	if err != nil || !reflect.DeepEqual(snap, bound) {
		t.Fatalf("snapshot %+v %v", snap, err)
	}
	if err := a.DeleteAction(ctx, "t", "act_1", false); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("bound delete: %v", err)
	}

	ex := &store.Execution{TenantID: "t", ID: "ex_1", Trigger: "post-login", Status: "failed", CreatedAt: now, UpdatedAt: now,
		Results: []store.ExecutionResult{{JobID: "ajob_every_field", JobAttempt: 4, ActionName: "Every Field", ErrorID: "e1", ErrorMsg: "boom", StartedAt: now, EndedAt: now.Add(time.Second)}}}
	if err := a.CreateExecution(ctx, ex); err != nil {
		t.Fatal(err)
	}
	if g, err := a.GetExecution(ctx, "t", "ex_1"); err != nil || !reflect.DeepEqual(g, ex) {
		t.Fatalf("execution %+v %v", g, err)
	}
	if n, err := a.PurgeExecutions(ctx, now.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("purge executions %d %v", n, err)
	}

	cs := &store.ContinueState{TenantID: "t", StateHash: "h", SessionID: "s", Sealed: []byte{9, 8, 7}, ExpiresAt: now.Add(time.Minute), CreatedAt: now}
	if err := a.CreateContinue(ctx, cs); err != nil {
		t.Fatal(err)
	}
	if g, err := a.ConsumeContinue(ctx, "t", "h", "s", now); err != nil || !reflect.DeepEqual(g, cs) {
		t.Fatalf("continue %+v %v", g, err)
	}
	if _, err := a.ConsumeContinue(ctx, "t", "h", "s", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("single use: %v", err)
	}
	if n, err := a.PurgeContinue(ctx, now); err != nil || n != 0 {
		t.Fatalf("purge continue %d %v", n, err)
	}

	if err := a.DeleteAction(ctx, "t", "act_1", true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetAction(ctx, "t", "act_1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := a.Deploy(ctx, "t", "gone", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deploy missing: %v", err)
	}
	// ErrBuildNotReady survives the wire.
	if err := a.CreateAction(ctx, &store.Action{TenantID: "t", ID: "act_2", Name: "No Build", Trigger: "post-login", Runtime: "node22", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Deploy(ctx, "t", "act_2", ""); !errors.Is(err, store.ErrBuildNotReady) {
		t.Fatalf("unbuilt deploy: %v", err)
	}
}

func TestActionsConformanceOverPlugin(t *testing.T) {
	storetest.RunSuites(t, func(t *testing.T) store.Store { return inProcess(t) }, "Actions", "ActionsII")
}

// badArtifact serves artifact streams that disagree with their header.
type badArtifact struct {
	*Server
	msgs []*storev1.ActionsArtifactChunk
}

func (b badArtifact) ActionsGetArtifact(_ *storev1.ActionsRequest, st grpc.ServerStreamingServer[storev1.ActionsArtifactChunk]) error {
	for _, m := range b.msgs {
		if err := st.Send(m); err != nil {
			return err
		}
	}
	return nil
}

func TestActionsGetArtifactIntegrity(t *testing.T) {
	sum := func(s string) []byte { x := sha256.Sum256([]byte(s)); return x[:] }
	cases := []struct {
		name string
		msgs []*storev1.ActionsArtifactChunk
		want string
	}{
		{"wrong sha", []*storev1.ActionsArtifactChunk{{TotalSize: 8, Sha256: sum("expected"), Data: []byte("tampered")}}, "SHA-256 verification"},
		{"truncated", []*storev1.ActionsArtifactChunk{{TotalSize: 8, Sha256: sum("12345678"), Data: []byte("1234")}}, "SHA-256 verification"},
		{"empty stream", nil, "SHA-256 verification"},
		{"oversize mid-stream", []*storev1.ActionsArtifactChunk{{TotalSize: 6, Sha256: sum("123456"), Data: []byte("1234")}, {Data: []byte("5678")}}, "exceeds declared size"},
		{"bad header sha", []*storev1.ActionsArtifactChunk{{TotalSize: 1, Sha256: []byte("short"), Data: []byte("x")}}, "malformed artifact header"},
		{"size over limit", []*storev1.ActionsArtifactChunk{{TotalSize: maxArtifact() + 1, Sha256: sum("x")}}, "malformed artifact header"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := serveWith(t, badArtifact{Server: NewServer(memory.New()), msgs: tc.msgs})
			defer c.Close()
			got, err := c.Actions().GetArtifact(context.Background(), "t", "b")
			if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Fatalf("got %d bytes, err %v; want error containing %q", len(got), err, tc.want)
			}
		})
	}
}

// The server handler guards stored data: every rejected upload must leave
// the previous artifact untouched.
func TestActionsPutArtifactIntegrity(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	a := c.Actions()
	if err := a.PutBuild(ctx, &store.Build{TenantID: "t", ID: "b1", Status: store.BuildBuilt}); err != nil {
		t.Fatal(err)
	}
	if err := a.PutArtifact(ctx, "t", "b1", []byte("original")); err != nil {
		t.Fatal(err)
	}
	sum := func(s string) []byte { x := sha256.Sum256([]byte(s)); return x[:] }
	hdr := func(size int64, sha []byte, data string) *storev1.ActionsArtifactChunk {
		return &storev1.ActionsArtifactChunk{TenantId: "t", BuildId: "b1", TotalSize: size, Sha256: sha, Data: []byte(data)}
	}
	cases := []struct {
		name string
		msgs []*storev1.ActionsArtifactChunk
	}{
		{"wrong sha", []*storev1.ActionsArtifactChunk{hdr(8, sum("expected"), "tampered")}},
		{"wrong size (truncated)", []*storev1.ActionsArtifactChunk{hdr(8, sum("1234"), "1234")}},
		{"oversize mid-stream", []*storev1.ActionsArtifactChunk{hdr(6, sum("12345678"), "1234"), {Data: []byte("5678")}}},
		{"declared over limit", []*storev1.ActionsArtifactChunk{hdr(maxArtifact()+1, sum("x"), "x")}},
		{"negative size", []*storev1.ActionsArtifactChunk{hdr(-1, sum("x"), "x")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := c.rpc.ActionsPutArtifact(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range tc.msgs {
				if err := st.Send(m); err != nil {
					break // the server may answer before reading everything
				}
			}
			res, err := st.CloseAndRecv()
			if err != nil {
				t.Fatal(err)
			}
			if e := errFromPB(res.GetError()); !errors.Is(e, store.ErrInvalid) {
				t.Fatalf("outcome %v; want store.ErrInvalid", e)
			}
			got, err := a.GetArtifact(ctx, "t", "b1")
			if err != nil || string(got) != "original" {
				t.Fatalf("stored artifact changed: %q %v", got, err)
			}
		})
	}
	// The client refuses to send an artifact above the limit.
	if err := a.PutArtifact(ctx, "t", "b1", make([]byte, maxArtifact()+1)); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("client oversize: %v", err)
	}
}

// A plugin transaction scopes Actions writes: rollback discards them.
func TestActionsPluginTransactionRollback(t *testing.T) {
	ctx := context.Background()
	c := inProcessSQLite(t)
	defer c.Close()
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	boom := errors.New("rollback")
	err := c.WithTx(ctx, func(tx store.Store) error {
		a := tx.Actions()
		if err := a.PutBuild(ctx, &store.Build{TenantID: "t", ID: "b1", Status: store.BuildBuilt, BuiltAt: now}); err != nil {
			return err
		}
		if err := a.PutArtifact(ctx, "t", "b1", []byte("tar")); err != nil {
			return err
		}
		if err := a.CreateAction(ctx, &store.Action{TenantID: "t", ID: "a1", Name: "A", Trigger: "post-login", Runtime: "node22", DraftBuildID: "b1", CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if _, err := a.Deploy(ctx, "t", "a1", ""); err != nil {
			return err
		}
		if _, err := a.GetAction(ctx, "t", "a1"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("WithTx: %v", err)
	}
	if _, err := c.Actions().GetBuild(ctx, "t", "b1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("build survived rollback: %v", err)
	}
	if _, err := c.Actions().GetAction(ctx, "t", "a1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("action survived rollback: %v", err)
	}
}

type oldActionsPlugin struct{ *Server }

func (oldActionsPlugin) ActionsCapabilities(context.Context, *storev1.PingRequest) (*storev1.ActionsCapabilitiesResult, error) {
	return nil, status.Error(codes.Unimplemented, "pre-Actions plugin")
}

func TestActionsOldPlugin(t *testing.T) {
	ctx := context.Background()
	c := serveWith(t, oldActionsPlugin{NewServer(memory.New())})
	defer c.Close()
	err := c.CheckActionsSupport(ctx)
	if !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("capability: %v", err)
	}
	// Missing RPCs never read as an empty registry.
	old := serveWith(t, struct{ storev1.StoreServiceServer }{storev1.UnimplementedStoreServiceServer{}})
	defer old.Close()
	if _, err := old.Actions().ListActions(ctx, "t", store.ActionFilter{}); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("list on old plugin: %v", err)
	}
	if _, err := old.Actions().Bindings(ctx, "t", "post-login"); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("bindings on old plugin: %v", err)
	}
	if _, err := old.Actions().BindingsInitialized(ctx, "t", "post-login"); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("marker read on old plugin: %v", err)
	}
	if _, err := old.Actions().InitializeBindings(ctx, "t", "post-login", nil); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("initialization on old plugin: %v", err)
	}
	if _, err := old.Actions().GetArtifact(ctx, "t", "b"); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("artifact on old plugin: %v", err)
	}
	if err := old.Actions().PutArtifact(ctx, "t", "b", []byte("x")); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("put artifact on old plugin: %v", err)
	}

	// Missing Actions II RPCs must fail closed, including the ticket operation.
	for name, call := range map[string]func() error{
		"module":  func() error { _, e := old.Actions().GetModule(ctx, "t", "m"); return e },
		"publish": func() error { _, e := old.Actions().PublishModule(ctx, "t", "m"); return e },
		"usage":   func() error { _, e := old.Actions().ModuleUsers(ctx, "t", "m", store.PageRequest{}); return e },
		"enqueue": func() error { return old.Actions().EnqueueJob(ctx, &store.ActionJob{TenantID: "t", ID: "j"}) },
		"claim":   func() error { _, e := old.Actions().ClaimJobs(ctx, time.Now(), time.Minute, 1); return e },
		"finish": func() error {
			return old.Actions().FinishJob(ctx, &store.ActionJob{TenantID: "t", ID: "j"}, time.Now())
		},
		"purge":     func() error { _, e := old.Actions().PurgeJobs(ctx, time.Now()); return e },
		"challenge": func() error { return old.PasswordResetTickets().MarkChallengePassed(ctx, "t", "h", time.Now(), "") },
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, store.ErrActionsUnavailable) {
				t.Fatalf("old plugin: %v", err)
			}
		})
	}
}

type versionOneActionsPlugin struct{ *Server }

func (versionOneActionsPlugin) ActionsCapabilities(context.Context, *storev1.PingRequest) (*storev1.ActionsCapabilitiesResult, error) {
	return &storev1.ActionsCapabilitiesResult{Version: 1}, nil
}
func TestActionsVersionOnePluginRefused(t *testing.T) {
	c := serveWith(t, versionOneActionsPlugin{NewServer(memory.New())})
	defer c.Close()
	if err := c.CheckActionsSupport(context.Background()); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("v1 plugin without durable binding ownership accepted: %v", err)
	}
}

// Losing any field in the new wire messages corrupts published snapshots or worker state.
func TestActionsIIPluginRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 28, 12, 13, 14, 123456789, time.UTC)
	must(c.Tenants().Create(ctx, &store.Tenant{ID: "ii", Name: "ii"}))
	a := c.Actions()
	must(a.PutBuild(ctx, &store.Build{TenantID: "ii", ID: "b", Status: store.BuildBuilt, Resolved: []store.Dependency{{Name: "dep", Version: "1.2.3"}}, BuiltAt: now}))
	must(a.PutArtifact(ctx, "ii", "b", []byte("tar")))
	m := &store.ActionModule{TenantID: "ii", ID: "m", Name: "module", Code: "exports.x=1", Dependencies: []store.Dependency{{Name: "dep", Version: "1.2.3"}}, Secrets: []store.ActionSecret{{Name: "KEY", Sealed: []byte{0, 1, 255}, UpdatedAt: now}}, DraftBuildID: "b", CreatedAt: now, UpdatedAt: now}
	must(a.CreateModule(ctx, m))
	got, err := a.GetModule(ctx, "ii", "m")
	must(err)
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("module got %#v want %#v", got, m)
	}
	v, err := a.PublishModule(ctx, "ii", "m")
	must(err)
	if v.ModuleID != "m" || v.Number != 1 || v.BuildID != "b" || v.Code != "exports.x=1" || !reflect.DeepEqual(v.Dependencies, m.Dependencies) || !reflect.DeepEqual(v.Secrets, m.Secrets) || v.CreatedAt.IsZero() {
		t.Fatalf("version fields: %#v", v)
	}
	back, err := a.GetModuleVersion(ctx, "ii", "m", v.ID)
	must(err)
	if !reflect.DeepEqual(back, v) {
		t.Fatalf("version got %#v want %#v", back, v)
	}
	got, err = a.GetModule(ctx, "ii", "m")
	must(err)
	if !got.AllChangesPublished || got.LatestVersionNumber != 1 {
		t.Fatalf("published flags: %#v", got)
	}
	pins := []store.ModuleRef{{ModuleID: "m", ModuleName: "module", VersionID: v.ID, VersionNumber: 1}}
	act := &store.Action{TenantID: "ii", ID: "act", Name: "action", Trigger: "post-login", Runtime: "node22", Code: "exports.onExecutePostLogin=()=>{}", DraftBuildID: "b", Modules: pins, CreatedAt: now, UpdatedAt: now}
	must(a.CreateAction(ctx, act))
	act.Code += ";"
	must(a.UpdateAction(ctx, act))
	deployed, err := a.Deploy(ctx, "ii", "act", "")
	must(err)
	if !reflect.DeepEqual(deployed.Modules, pins) {
		t.Fatalf("deployment pins: %#v", deployed.Modules)
	}
	users, err := a.ModuleUsers(ctx, "ii", "m", store.PageRequest{})
	must(err)
	if users.Total != 1 || !users.Items[0].InDraft || !users.Items[0].InDeployed || users.Items[0].ID != "act" || !reflect.DeepEqual(users.Items[0].Modules, pins) {
		t.Fatalf("module users: %#v", users)
	}
	if err = a.DeleteModule(ctx, "ii", "m"); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("delete used module: %v", err)
	}
	j := &store.ActionJob{TenantID: "ii", ID: "j", Trigger: "post-user-registration", Status: "pending", Sealed: []byte{0, 2, 255}, NextAt: now, CreatedAt: now, UpdatedAt: now, ExecutionIDs: []string{"e1", "e2"}, ModuleVersionIDs: []string{v.ID}}
	must(a.EnqueueJob(ctx, j))
	jobs, err := a.ClaimJobs(ctx, now, time.Minute+123*time.Nanosecond, 1)
	must(err)
	if len(jobs) != 1 {
		t.Fatalf("jobs: %#v", jobs)
	}
	claim := jobs[0]
	if claim.TenantID != "ii" || claim.ID != "j" || claim.Trigger != j.Trigger || claim.Status != "pending" || claim.Attempts != 1 || !claim.LeaseUntil.Equal(now.Add(time.Minute+123*time.Nanosecond)) || !claim.NextAt.Equal(now) || !claim.CreatedAt.Equal(now) || !reflect.DeepEqual(claim.Sealed, j.Sealed) || !reflect.DeepEqual(claim.ExecutionIDs, j.ExecutionIDs) || !reflect.DeepEqual(claim.ModuleVersionIDs, j.ModuleVersionIDs) {
		t.Fatalf("claim fields: %#v", claim)
	}
	claim.Status = "done"
	must(a.FinishJob(ctx, &claim, claim.LeaseUntil))
	must(c.Users().Create(ctx, &store.User{TenantID: "ii", UserID: "u", LastPasswordReset: &now}))
	u, err := c.Users().Get(ctx, "ii", "u")
	must(err)
	if u.LastPasswordReset == nil || !u.LastPasswordReset.Equal(now) {
		t.Fatalf("password reset time: %#v", u)
	}
	later := now.Add(time.Second)
	u.LastPasswordReset = &later
	must(c.Users().Update(ctx, u))
	u, err = c.Users().Get(ctx, "ii", "u")
	must(err)
	if u.LastPasswordReset == nil || !u.LastPasswordReset.Equal(later) {
		t.Fatalf("updated password reset time: %#v", u)
	}
	ticket := &store.PasswordResetTicket{TenantID: "ii", ID: "t", TokenHash: "h", ExpiresAt: now.Add(time.Hour), ChallengePassedAt: &now, ChallengeResultURL: "https://example.test/first"}
	must(c.PasswordResetTickets().Create(ctx, ticket))
	rt, err := c.PasswordResetTickets().GetByTokenHash(ctx, "ii", "h")
	must(err)
	if rt.ChallengePassedAt == nil || !rt.ChallengePassedAt.Equal(now) || rt.ChallengeResultURL != "https://example.test/first" {
		t.Fatalf("initial challenge: %#v", rt)
	}
	must(c.PasswordResetTickets().MarkChallengePassed(ctx, "ii", "h", later, "https://example.test/after"))
	rt, err = c.PasswordResetTickets().Consume(ctx, "ii", "h", later)
	must(err)
	if rt.ChallengePassedAt == nil || !rt.ChallengePassedAt.Equal(later) || rt.ChallengeResultURL != "https://example.test/after" {
		t.Fatalf("marked challenge: %#v", rt)
	}
}

type versionTwoActionsPlugin struct{ *Server }

func (versionTwoActionsPlugin) ActionsCapabilities(context.Context, *storev1.PingRequest) (*storev1.ActionsCapabilitiesResult, error) {
	return &storev1.ActionsCapabilitiesResult{Version: 2}, nil
}
func TestActionsOldPluginVersionTwo(t *testing.T) {
	c := serveWith(t, versionTwoActionsPlugin{NewServer(memory.New())})
	defer c.Close()
	err := c.CheckActionsSupport(context.Background())
	if !errors.Is(err, store.ErrActionsUnavailable) || !strings.Contains(err.Error(), "capability 3") || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("v2 plugin accepted or unclear upgrade diagnostic: %v", err)
	}
}

// A dropped tx_id would persist challenge approval despite a failed password transaction.
func TestActionsIIChallengeTransactionRollback(t *testing.T) {
	ctx := context.Background()
	c := inProcessSQLite(t)
	defer c.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	must(c.Tenants().Create(ctx, &store.Tenant{ID: "ii", Name: "ii"}))
	must(c.Users().Create(ctx, &store.User{TenantID: "ii", UserID: "u"}))
	must(c.PasswordResetTickets().Create(ctx, &store.PasswordResetTicket{TenantID: "ii", ID: "t", TokenHash: "h", ExpiresAt: now.Add(time.Hour)}))
	boom := errors.New("rollback")
	err := c.WithTx(ctx, func(tx store.Store) error {
		if err := tx.PasswordResetTickets().MarkChallengePassed(ctx, "ii", "h", now, "https://example.test/done"); err != nil {
			return err
		}
		ticket, err := tx.PasswordResetTickets().GetByTokenHash(ctx, "ii", "h")
		if err != nil {
			return err
		}
		if ticket.ChallengePassedAt == nil || !ticket.ChallengePassedAt.Equal(now) || ticket.ChallengeResultURL != "https://example.test/done" {
			t.Fatalf("transaction challenge: %#v", ticket)
		}
		u, err := tx.Users().Get(ctx, "ii", "u")
		if err != nil {
			return err
		}
		u.LastPasswordReset = &now
		if err = tx.Users().Update(ctx, u); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("transaction: %v", err)
	}
	ticket, err := c.PasswordResetTickets().GetByTokenHash(ctx, "ii", "h")
	must(err)
	if ticket.ChallengePassedAt != nil || ticket.ChallengeResultURL != "" {
		t.Fatalf("challenge survived rollback: %#v", ticket)
	}
	u, err := c.Users().Get(ctx, "ii", "u")
	must(err)
	if u.LastPasswordReset != nil {
		t.Fatalf("password timestamp survived rollback: %#v", u)
	}
}
