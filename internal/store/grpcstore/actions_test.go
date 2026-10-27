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
		Results: []store.ExecutionResult{{ActionName: "Every Field", ErrorID: "e1", ErrorMsg: "boom", StartedAt: now, EndedAt: now.Add(time.Second)}}}
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
	if g, err := a.ConsumeContinue(ctx, "t", "h", now); err != nil || !reflect.DeepEqual(g, cs) {
		t.Fatalf("continue %+v %v", g, err)
	}
	if _, err := a.ConsumeContinue(ctx, "t", "h", now); !errors.Is(err, store.ErrNotFound) {
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
	storetest.RunSuites(t, func(t *testing.T) store.Store { return inProcess(t) }, "Actions")
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
	if _, err := old.Actions().GetArtifact(ctx, "t", "b"); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("artifact on old plugin: %v", err)
	}
	if err := old.Actions().PutArtifact(ctx, "t", "b", []byte("x")); !errors.Is(err, store.ErrActionsUnavailable) {
		t.Fatalf("put artifact on old plugin: %v", err)
	}
}
