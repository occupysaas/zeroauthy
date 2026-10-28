package actions_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// moduleFixture stores sealed snapshots just as management will, using a
// distinct domain even when an Action and Module have the same identifier.
func moduleFixture(t *testing.T, h *harness, tid, name, code string, vals map[string]string) (*store.ActionModule, *store.ActionModuleVersion) {
	t.Helper()
	m := &store.ActionModule{TenantID: tid, ID: "mod_" + name, Name: name, Code: code, DraftBuildID: h.built(tid)}
	for k, v := range vals {
		sealed, err := keys.SealModuleSecret(h.w, tid, m.ID, k, v)
		if err != nil {
			t.Fatal(err)
		}
		m.Secrets = append(m.Secrets, store.ActionSecret{Name: k, Sealed: sealed})
	}
	if err := h.st.Actions().CreateModule(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	v, err := h.st.Actions().PublishModule(context.Background(), tid, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	return m, v
}

func pinModule(t *testing.T, h *harness, a *store.Action, m *store.ActionModule, v *store.ActionModuleVersion) *store.ActionVersion {
	t.Helper()
	ctx := context.Background()
	cur, err := h.st.Actions().GetAction(ctx, a.TenantID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	cur.Modules = append(cur.Modules, store.ModuleRef{ModuleID: m.ID, VersionID: v.ID})
	if err = h.st.Actions().UpdateAction(ctx, cur); err != nil {
		t.Fatal(err)
	}
	av, err := h.st.Actions().Deploy(ctx, a.TenantID, a.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	return av
}

// installedFixture supplies a local, immutable dependency artifact through the
// production store/Ensure path, avoiding any public registry dependency.
func installedFixture(t *testing.T, h *harness, tid, name, code string) string {
	t.Helper()
	deps := []store.Dependency{{Name: name, Version: "1.0.0"}}
	id := build.ID(actionsrules.Runtime, deps)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for file, text := range map[string]string{"package.json": fmt.Sprintf(`{"name":%q,"version":"1.0.0","main":"index.js"}`, name), "index.js": code} {
		if err := tw.WriteHeader(&tar.Header{Name: "node_modules/" + name + "/" + file, Mode: 0600, Size: int64(len(text)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	art := buf.Bytes()
	sum := sha256.Sum256(art)
	ctx := context.Background()
	if err := h.st.Actions().PutBuild(ctx, &store.Build{TenantID: tid, ID: id, Status: store.BuildBuilt, Requested: deps, Resolved: deps, ArtifactSHA256: hex.EncodeToString(sum[:])}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.Actions().PutArtifact(ctx, tid, id, art); err != nil {
		t.Fatal(err)
	}
	return id
}

// Missing actions: resolution, allowing module-to-module imports or resolving
// through the caller's npm tree must each break these observable assertions.
func TestModulesRequire(t *testing.T) {
	for _, tc := range []struct {
		name, module, action string
		want                 string
	}{
		{"greet", `exports.greet=()=>"hello"`, `require('actions:util').greet()`, "hello"},
		{"own-context", `exports.greet=()=>typeof callerOnly`, `require('actions:util').greet()`, "undefined"},
		{"once", `let n=0; exports.greet=()=>++n`, `[require('actions:util').greet(),require('actions:util').greet()].join(',')`, "1,2"},
		{"own-npm", `exports.greet=()=>require('module-dep')`, `require('actions:util').greet()`, "module dependency"},
		{"module-import-refused", `exports.greet=()=>require('actions:other')`, `(()=>{try{require('actions:util').greet();return 'escaped'}catch{return 'blocked'}})()`, "blocked"},
		{"caller-npm-refused", `exports.greet=()=>require('caller-dep')`, `(()=>{try{require('actions:util').greet();return 'escaped'}catch{return 'blocked'}})()`, "blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			m, _ := moduleFixture(t, h, "t1", "util", tc.module, nil)
			m.DraftBuildID = installedFixture(t, h, "t1", "module-dep", `module.exports='module dependency'`)
			m.Dependencies = []store.Dependency{{Name: "module-dep", Version: "1.0.0"}}
			if err := h.st.Actions().UpdateModule(context.Background(), m); err != nil {
				t.Fatal(err)
			}
			mv, err := h.st.Actions().PublishModule(context.Background(), "t1", m.ID)
			if err != nil {
				t.Fatal(err)
			}
			a := h.action("t1", trigLogin, "caller", `globalThis.callerOnly='private'; exports.onExecutePostLogin=(e,a)=>a.idToken.setCustomClaim('answer',`+tc.action+`);`, nil, true)
			a.DraftBuildID = installedFixture(t, h, "t1", "caller-dep", `module.exports='caller dependency'`)
			a.Dependencies = []store.Dependency{{Name: "caller-dep", Version: "1.0.0"}}
			if err = h.st.Actions().UpdateAction(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			pinModule(t, h, a, m, mv)
			other, otherVersion := moduleFixture(t, h, "t1", "other", `exports.greet=()=>"other"`, nil)
			pinModule(t, h, a, other, otherVersion)
			// Both imports exist for the caller; the module's require must
			// still refuse the caller's tree and the pinned sibling module.
			cur, err := h.st.Actions().GetAction(context.Background(), "t1", a.ID)
			if err != nil {
				t.Fatal(err)
			}
			cur.Code = `if(require('caller-dep')!=='caller dependency'||require('actions:other').greet()!=='other') throw Error('caller fixtures unavailable');` + cur.Code
			if err = h.st.Actions().UpdateAction(context.Background(), cur); err != nil {
				t.Fatal(err)
			}
			if _, err = h.st.Actions().Deploy(context.Background(), "t1", a.ID, ""); err != nil {
				t.Fatal(err)
			}
			h.bind("t1", trigLogin, a)
			if got := h.mustPostLogin("t1").Effects.IDClaims["answer"]; got != tc.want {
				t.Fatalf("answer=%v want %s", got, tc.want)
			}
		})
	}
}

type moduleFaultStore struct {
	store.Store
	repo store.Actions
}

func (s moduleFaultStore) Actions() store.Actions { return s.repo }

type moduleFaultActions struct {
	store.Actions
	change func(*store.ActionModuleVersion) (*store.ActionModuleVersion, error)
}

func (r moduleFaultActions) GetModuleVersion(ctx context.Context, tid, mid, vid string) (*store.ActionModuleVersion, error) {
	v, err := r.Actions.GetModuleVersion(ctx, tid, mid, vid)
	if err != nil {
		return nil, err
	}
	return r.change(v)
}

// Losing an immutable version or its artifact must fail before any Action
// effects run, including when its source never calls require on that module.
func TestModulesFailClosed(t *testing.T) {
	for _, fault := range []string{"missing-version", "missing-build", "corrupt-artifact", "wrong-tenant", "wrong-module", "wrong-version", "wrong-number", "wrong-secret-domain"} {
		t.Run(fault, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			m, _ := moduleFixture(t, h, "t1", "util", `exports.greet=()=>"hello"`, nil)
			m.DraftBuildID = installedFixture(t, h, "t1", "module-dep", `module.exports='module dependency'`)
			m.Dependencies = []store.Dependency{{Name: "module-dep", Version: "1.0.0"}}
			if err := h.st.Actions().UpdateModule(ctx, m); err != nil {
				t.Fatal(err)
			}
			v, err := h.st.Actions().PublishModule(ctx, "t1", m.ID)
			if err != nil {
				t.Fatal(err)
			}
			a := h.action("t1", trigLogin, "caller", `exports.onExecutePostLogin=(e,a)=>a.user.setAppMetadata('escaped',true)`, nil, true)
			pinModule(t, h, a, m, v)
			h.bind("t1", trigLogin, a)
			h.eng.Store = moduleFaultStore{Store: h.st, repo: moduleFaultActions{Actions: h.st.Actions(), change: func(v *store.ActionModuleVersion) (*store.ActionModuleVersion, error) {
				switch fault {
				case "missing-version":
					return nil, store.ErrNotFound
				case "missing-build":
					v.BuildID = strings.Repeat("f", 64)
				case "corrupt-artifact":
					if err := h.st.Actions().PutArtifact(ctx, "t1", v.BuildID, []byte("corrupt")); err != nil {
						t.Fatal(err)
					}
				case "wrong-tenant":
					v.TenantID = "t2"
				case "wrong-module":
					v.ModuleID = "other"
				case "wrong-version":
					v.ID = "other"
				case "wrong-number":
					v.Number++
				case "wrong-secret-domain":
					sealed, err := keys.SealActionSecret(h.w, "t1", v.ModuleID, "KEY", "cross-domain-secret")
					if err != nil {
						t.Fatal(err)
					}
					v.Secrets = []store.ActionSecret{{Name: "KEY", Sealed: sealed}}
				}
				return v, nil
			}}}
			if _, err := h.postLogin("t1"); err == nil {
				t.Fatal("broken module pin did not fail closed")
			}
			if h.user("t1").AppMetadata["escaped"] != nil {
				t.Fatal("Action ran despite unusable pin")
			}
		})
	}
}

func TestModulesObjectsNotSharedBetweenActions(t *testing.T) {
	h := newHarness(t)
	m, v := moduleFixture(t, h, "t1", "util", `let n=0; module.exports={next:()=>++n};`, nil)
	for _, name := range []string{"one", "two"} {
		a := h.action("t1", trigLogin, name, `const m=require('actions:util'); exports.onExecutePostLogin=(e,a)=>a.idToken.setCustomClaim('`+name+`',m.next());`, nil, true)
		pinModule(t, h, a, m, v)
	}
	a, _ := h.st.Actions().GetAction(context.Background(), "t1", "act_one")
	b, _ := h.st.Actions().GetAction(context.Background(), "t1", "act_two")
	h.bind("t1", trigLogin, a, b)
	for _, want := range []float64{1, 2} {
		r := h.mustPostLogin("t1")
		if r.Effects.IDClaims["one"] != want || r.Effects.IDClaims["two"] != want {
			t.Fatalf("module state shared or reevaluated: %#v", r.Effects.IDClaims)
		}
	}
}

func TestModulesSecretsIsolation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	m, v := moduleFixture(t, h, "t1", "util", `exports.read=()=>{console.log(actions.secrets.KEY);return {own:actions.secrets.KEY, action:actions.secrets.ACTION, other:actions.secrets.OTHER, event:typeof event}}; exports.fail=()=>{setTimeout(()=>{throw Error(actions.secrets.KEY)},5);throw Error(actions.secrets.KEY)};`, map[string]string{"KEY": "module-secret-123"})
	o, ov := moduleFixture(t, h, "t1", "other", `exports.read=()=>actions.secrets.OTHER`, map[string]string{"OTHER": "other-secret-456"})
	a := h.action("t1", trigLogin, "caller", `exports.onExecutePostLogin=(e,a)=>{const m=require('actions:util');const r=m.read(); if(r.own!=='module-secret-123'||r.action!==undefined||r.other!==undefined||r.event!=='undefined'||e.secrets.KEY!==undefined||e.secrets.OTHER!==undefined) throw Error('secret isolation failed');console.log(e.secrets.ACTION,require('actions:other').read()); if(e.fail)m.fail();a.idToken.setCustomClaim('isolated',true)};`, map[string]string{"ACTION": "action-secret-789"}, true)
	pinModule(t, h, a, m, v)
	pinModule(t, h, a, o, ov)
	h.bind("t1", trigLogin, a)
	if h.mustPostLogin("t1").Effects.IDClaims["isolated"] != true {
		t.Fatal("secret isolation not exercised")
	}
	for _, fail := range []bool{false, true} {
		raw, err := h.eng.Test(ctx, "t1", a.ID, json.RawMessage(fmt.Sprintf(`{"fail":%t}`, fail)))
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Logs  []string
			Error *struct{ Message string }
		}
		if err = json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Logs) != 2 || (out.Error != nil) != fail {
			t.Fatalf("test output: %s", raw)
		}
		for _, secret := range []string{"module-secret-123", "other-secret-456", "action-secret-789"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("secret in test output: %s", raw)
			}
		}
	}
	// The same throw through a bound flow must be masked in Go's log and
	// persisted execution errors, including delayed runner stderr.
	h.redeploy(a, `exports.onExecutePostLogin=(e,a)=>{console.log(e.secrets.ACTION);require('actions:util').fail()}`)
	_, err := h.postLogin("t1")
	if !errors.Is(err, actions.ErrActionError) {
		t.Fatalf("throw: %v", err)
	}
	var ef *actions.ErrFlow
	if !errors.As(err, &ef) {
		t.Fatal(err)
	}
	record := mustJSON(t, h.execution("t1", ef.ExecutionID))
	time.Sleep(100 * time.Millisecond)
	for _, secret := range []string{"module-secret-123", "other-secret-456", "action-secret-789"} {
		if strings.Contains(fmt.Sprint(err)+record+h.logs.String(), secret) {
			t.Fatalf("secret escaped masking: %s %s %s", err, record, h.logs.String())
		}
	}
	if !strings.Contains(h.logs.String(), "uncaught:") {
		t.Fatal("delayed module error was not logged")
	}
}

func TestModulesPinned(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	m, v1 := moduleFixture(t, h, "t1", "util", `exports.greet=()=>"v1"`, nil)
	a := h.action("t1", trigLogin, "caller", `exports.onExecutePostLogin=(e,a)=>a.idToken.setCustomClaim('answer',require('actions:util').greet())`, nil, true)
	pinModule(t, h, a, m, v1)
	h.bind("t1", trigLogin, a)
	m.Code = `exports.greet=()=>"v2"`
	if err := h.st.Actions().UpdateModule(ctx, m); err != nil {
		t.Fatal(err)
	}
	v2, err := h.st.Actions().PublishModule(ctx, "t1", m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.mustPostLogin("t1").Effects.IDClaims["answer"]; got != "v1" {
		t.Fatalf("publish changed pin: %v", got)
	}
	if _, err = h.st.Actions().RollbackModule(ctx, "t1", m.ID, v1.ID); err != nil {
		t.Fatal(err)
	}
	if got := h.mustPostLogin("t1").Effects.IDClaims["answer"]; got != "v1" {
		t.Fatalf("rollback changed pin: %v", got)
	}
	cur, _ := h.st.Actions().GetAction(ctx, "t1", a.ID)
	cur.Modules = nil
	if err = h.st.Actions().UpdateAction(ctx, cur); err != nil {
		t.Fatal(err)
	}
	pinModule(t, h, a, m, v2)
	if got := h.mustPostLogin("t1").Effects.IDClaims["answer"]; got != "v2" {
		t.Fatalf("redeploy did not pick reference: %v", got)
	}
}

func TestModulesTombstone(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	m, v := moduleFixture(t, h, "t1", "util", `exports.greet=()=>"retained"`, nil)
	a := h.action("t1", trigLogin, "caller", `exports.onExecutePostLogin=(e,a)=>a.idToken.setCustomClaim('answer',require('actions:util').greet());exports.onContinuePostLogin=exports.onExecutePostLogin`, nil, true)
	old := pinModule(t, h, a, m, v)
	h.bind("t1", trigLogin, a)
	// A suspended flow is also a lower-level pinned snapshot execution. The
	// real durable queued-job regression belongs to Task 7.
	redirect := h.action("t1", trigLogin, "redirect", `exports.onExecutePostLogin=(e,a)=>a.redirect.sendUserTo('https://step.test/');exports.onContinuePostLogin=()=>{}`, nil, false)
	h.bind("t1", trigLogin, redirect, a)
	in := redirectInput(h)
	r, err := h.eng.PostLogin(ctx, in)
	state := redirectState(t, r, err)
	cur, _ := h.st.Actions().GetAction(ctx, "t1", a.ID)
	cur.Modules = nil
	cur.Code = `exports.onExecutePostLogin=()=>{}`
	if err = h.st.Actions().UpdateAction(ctx, cur); err != nil {
		t.Fatal(err)
	}
	if _, err = h.st.Actions().Deploy(ctx, "t1", a.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err = h.st.Actions().DeleteModule(ctx, "t1", m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = h.st.Actions().GetModule(ctx, "t1", m.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("module visible after deletion: %v", err)
	}
	r, err = resume(t, h, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test"})
	if err != nil || r.Effects.IDClaims["answer"] != "retained" {
		t.Fatalf("pinned continuation after delete: %#v %v", r, err)
	}
	if _, err = h.st.Actions().Deploy(ctx, "t1", a.ID, old.ID); err != nil {
		t.Fatal(err)
	}
	h.bind("t1", trigLogin, a)
	if got := h.mustPostLogin("t1").Effects.IDClaims["answer"]; got != "retained" {
		t.Fatalf("old-version redeploy: %v", got)
	}
}

func TestModulesTenantIsolation(t *testing.T) {
	h := newHarness(t)
	m, v := moduleFixture(t, h, "t1", "util", `exports.greet=()=>require('tenant-private')`, nil)
	// Tenant A's installed package exists inside A's permitted root. B must
	// neither resolve A's module name nor acquire that dependency tree.
	m.DraftBuildID = installedFixture(t, h, "t1", "tenant-private", `module.exports='tenant A'`)
	m.Dependencies = []store.Dependency{{Name: "tenant-private", Version: "1.0.0"}}
	ctx := context.Background()
	if err := h.st.Actions().UpdateModule(ctx, m); err != nil {
		t.Fatal(err)
	}
	v, err := h.st.Actions().PublishModule(ctx, "t1", m.ID)
	if err != nil {
		t.Fatal(err)
	}
	code := `exports.onExecutePostLogin=(e,a)=>a.idToken.setCustomClaim('answer',require('actions:util').greet())`
	a := h.action("t1", trigLogin, "caller", code, nil, true)
	pinModule(t, h, a, m, v)
	h.bind("t1", trigLogin, a)
	if h.mustPostLogin("t1").Effects.IDClaims["answer"] != "tenant A" {
		t.Fatal("tenant A fixture not exercised")
	}
	b := h.action("t2", trigLogin, "caller", code, nil, false)
	h.bind("t2", trigLogin, b)
	if _, err = h.postLogin("t2"); !errors.Is(err, actions.ErrActionError) {
		t.Fatalf("B imported A: %v", err)
	}
	mb, vb := moduleFixture(t, h, "t2", "util", `exports.greet=()=>{try{return require('tenant-private')}catch{return 'isolated'}}`, nil)
	pinModule(t, h, b, mb, vb)
	if got := h.mustPostLogin("t2").Effects.IDClaims["answer"]; got != "isolated" {
		t.Fatalf("B reached A deps: %v", got)
	}
}
