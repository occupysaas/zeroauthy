package seed

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestActionsModulesSeed(t *testing.T) {
	f, err := Parse([]byte(`tenants:
- name: acme
  domains: [acme.test]
  modules:
  - name: shared
    code: module.exports={n:1};
    secrets: [{name: KEY, value: hidden}]
    publish: true
  actions:
  - name: login
    supported_triggers: [{id: post-login}]
    modules: [{module_name: shared, module_version_number: 1}]
    deploy: true
`))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	ae := actionstest.NewOffline(t, st, w)
	if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	m, err := st.Actions().GetModuleByName(ctx, tn.ID, "shared")
	if err != nil {
		t.Fatal(err)
	}
	a, err := st.Actions().GetActionByName(ctx, tn.ID, "login")
	if err != nil || len(a.Modules) != 1 || a.Modules[0].ModuleID != m.ID || m.LatestVersionNumber != 1 {
		t.Fatalf("a=%+v m=%+v err=%v", a, m, err)
	}
	m.Code = "management edit"
	if err := st.Actions().UpdateModule(ctx, m); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []Mode{ModeCreateOnly, ModeApply} {
		f.Mode = mode
		if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
			t.Fatal(err)
		}
		got, _ := st.Actions().GetModule(ctx, tn.ID, m.ID)
		if got.Code != "management edit" || got.LatestVersionNumber != 1 {
			t.Fatal(got)
		}
	}
}

func TestActionsModulesSeedFailureRetryAndValidation(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	ae := actionstest.NewOffline(t, st, w)
	source := `tenants:
- name: acme
  domains: [acme.test]
  modules:
  - name: shared
    code: module.exports={};
    dependencies: [{name: missing-offline-fixture, version: 1.0.0}]
    publish: true
`
	f, err := Parse([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, nil, w); err == nil {
		t.Fatal("legacy seed accepted modules without build manager")
	}
	if err := ApplyWithActions(ctx, st, f, nil, w, nil); err == nil {
		t.Fatal("modules accepted without engine")
	}
	if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err == nil {
		t.Fatal("failed dependency build accepted")
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if _, err := st.Actions().GetModuleByName(ctx, tn.ID, "shared"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("failed module persisted", err)
	}
	f.Tenants[0].Modules[0].Dependencies = nil
	if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
		t.Fatal(err)
	}
	m, err := st.Actions().GetModuleByName(ctx, tn.ID, "shared")
	if err != nil || m.LatestVersionNumber != 1 {
		t.Fatalf("module=%+v err=%v", m, err)
	}
	if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
		t.Fatal(err)
	}
	again, _ := st.Actions().GetModuleByName(ctx, tn.ID, "shared")
	if again.ID != m.ID || again.LatestVersionNumber != 1 {
		t.Fatal("restart republished module", again)
	}
	for _, edit := range []func(*File){func(f *File) { f.Tenants[0].Modules = append(f.Tenants[0].Modules, f.Tenants[0].Modules[0]) }, func(f *File) { f.Tenants[0].Modules[0].Name = "" }, func(f *File) { f.Tenants[0].Modules[0].APIVersion = strings.Repeat("v", 21) }, func(f *File) {
		f.Tenants[0].Modules[0].Secrets = []ActionSecret{{Name: "KEY", Value: strings.Repeat("x", 4097)}}
	}} {
		f, _ := Parse([]byte(source))
		edit(f)
		if err := f.validate(); err == nil {
			t.Fatal("invalid module seed accepted")
		}
	}
}
