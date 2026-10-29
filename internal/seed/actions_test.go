package seed

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

const actionsSeed = `tenants:
- name: acme
  domains: [acme.test]
  actions:
  - name: login
    supported_triggers: [{id: post-login, version: v3}]
    code: exports.onExecutePostLogin = async () => {};
    dependencies: []
    secrets: [{name: KEY, value: secret}]
    deploy: true
  - name: draft
    dependencies: [{name: task10-fixture, version: 1.0.0}]
    supported_triggers: [{id: credentials-exchange, version: v2}]
    code: exports.onExecuteCredentialsExchange = async () => {};
    deploy: false
  triggers:
    post-login:
      bindings: [{ref: {type: action_name, value: login}, display_name: Login}]
`

func TestActionsSeed(t *testing.T) {
	f, err := Parse([]byte(actionsSeed))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	ae := actionstest.NewOffline(t, st, w)
	if err := Apply(ctx, st, f, nil, w); err == nil || !strings.Contains(err.Error(), "ApplyWithActions") {
		t.Fatalf("legacy Apply=%v", err)
	}
	if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	a, err := st.Actions().GetActionByName(ctx, tn.ID, "login")
	if err != nil {
		t.Fatal(err)
	}
	if a.Code != "exports.onExecutePostLogin = async () => {};" || a.DeployedVersionID == "" || len(a.Secrets) != 1 {
		t.Fatalf("seeded=%+v", a)
	}
	value, err := keys.OpenActionSecret(w, tn.ID, a.ID, "KEY", a.Secrets[0].Sealed)
	if err != nil || value != "secret" {
		t.Fatalf("secret=%q %v", value, err)
	}
	bs, err := st.Actions().Bindings(ctx, tn.ID, "post-login")
	if err != nil || len(bs) != 1 || bs[0].Action.ID != a.ID {
		t.Fatalf("bindings=%v %v", bs, err)
	}
	draft, _ := st.Actions().GetActionByName(ctx, tn.ID, "draft")
	if draft.DeployedVersionID != "" || draft.DraftBuildID == "" || len(draft.Dependencies) != 1 || draft.Dependencies[0].Name != "task10-fixture" || draft.Dependencies[0].Version != "1.0.0" {
		t.Fatal(draft)
	}
	// Both seed modes preserve Actions and nonempty trigger bindings owned by
	// management, including code, secrets, deployed versions, order and names.
	a.Code = "management edit"
	a.UpdatedAt = time.Now()
	if err := st.Actions().UpdateAction(ctx, a); err != nil {
		t.Fatal(err)
	}
	bs[0].DisplayName = "management binding"
	if _, err := st.Actions().ReplaceBindings(ctx, tn.ID, "post-login", []store.Binding{bs[0].Binding}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []Mode{ModeApply, ModeCreateOnly} {
		f.Mode = mode
		if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
			t.Fatal(err)
		}
		got, _ := st.Actions().GetAction(ctx, tn.ID, a.ID)
		if got.Code != "management edit" || got.DeployedVersionID != a.DeployedVersionID {
			t.Fatal(got)
		}
		bindings, _ := st.Actions().Bindings(ctx, tn.ID, "post-login")
		if bindings[0].DisplayName != "management binding" || bindings[0].ID != bs[0].ID {
			t.Fatal(bindings)
		}
	}
	for _, doc := range []string{strings.Replace(actionsSeed, "post-login, version", "unsupported, version", 1), strings.Replace(actionsSeed, "dependencies: []", "dependencies: [{name: pkg, version: ^1.0.0}]", 1), strings.Replace(actionsSeed, "value: secret", "value: "+strings.Repeat("x", 4097), 1), strings.Replace(actionsSeed, "dependencies: []", "dependencies: [{name: pkg, version: 1.0.0, registry_url: https://bad.invalid}]", 1), strings.Replace(actionsSeed, "display_name: Login", "display_name: Login, secrets: []", 1)} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Fatalf("accepted invalid seed: %.200s", doc)
		}
	}
}
func TestActionsSeedFailureRetry(t *testing.T) {
	f, err := Parse([]byte(actionsSeed))
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	w := testWrapper(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ae := actionstest.NewOffline(t, st, w)
	if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err == nil {
		t.Fatal("canceled build succeeded")
	}
	// No partially owned Action can prevent a deploy on the next startup.
	if err := ApplyWithActions(context.Background(), st, f, nil, w, ae.Engine); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(context.Background(), "acme")
	a, err := st.Actions().GetActionByName(context.Background(), tn.ID, "login")
	if err != nil || a.DeployedVersionID == "" {
		t.Fatalf("retry=%+v %v", a, err)
	}
}

func TestActionsSeedRespectsAPITenant(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	ae := actionstest.NewOffline(t, st, w)
	f, err := Parse([]byte(actionsSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "api-tenant", Name: "acme", Domains: []string{"acme.test"}, Origin: store.OriginAPI}); err != nil {
		t.Fatal(err)
	}
	if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
		t.Fatal(err)
	}
	list, err := st.Actions().ListActions(ctx, "api-tenant", store.ActionFilter{})
	if err != nil || len(list.Items) != 0 {
		t.Fatalf("API tenant changed: %v %v", list, err)
	}
}

func TestActionsSeedBuildFailureLeavesNoOwnedDraft(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w := testWrapper(t)
	ae := actionstest.NewOffline(t, st, w)
	doc := strings.Replace(actionsSeed, "dependencies: []", "dependencies: [{name: task10-missing, version: 1.0.0}]", 1)
	f, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err == nil || !strings.Contains(err.Error(), "dependency build failed") {
		t.Fatalf("failed seed=%v", err)
	}
	tn, err := st.Tenants().GetByName(ctx, "acme")
	if err != nil {
		t.Fatalf("ordinary seed not applied: %v", err)
	}
	if _, err := st.Actions().GetActionByName(ctx, tn.ID, "login"); err != store.ErrNotFound {
		t.Fatalf("failed build left draft: %v", err)
	}
	f, err = Parse([]byte(actionsSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
		t.Fatal(err)
	}
	a, err := st.Actions().GetActionByName(ctx, tn.ID, "login")
	if err != nil || a.DeployedVersionID == "" {
		t.Fatalf("retry did not deploy: %+v %v", a, err)
	}
}

func TestActionsSeedPreservesExplicitlyEmptyBindings(t *testing.T) {
	for _, initiallyEmpty := range []bool{false, true} {
		t.Run(fmt.Sprint(initiallyEmpty), func(t *testing.T) {
			ctx := context.Background()
			st := memory.New()
			w := testWrapper(t)
			ae := actionstest.NewOffline(t, st, w)
			f, err := Parse([]byte(actionsSeed))
			if err != nil {
				t.Fatal(err)
			}
			if initiallyEmpty {
				plain, err := Parse([]byte("tenants:\n- name: acme\n  domains: [acme.test]\n"))
				if err != nil {
					t.Fatal(err)
				}
				if err := Apply(ctx, st, plain, nil, w); err != nil {
					t.Fatal(err)
				}
			} else if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
				t.Fatal(err)
			}
			tn, err := st.Tenants().GetByName(ctx, "acme")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Actions().ReplaceBindings(ctx, tn.ID, "post-login", nil); err != nil {
				t.Fatal(err)
			}
			for _, mode := range []Mode{ModeApply, ModeCreateOnly} {
				f.Mode = mode
				if err := ApplyWithActions(ctx, st, f, nil, w, ae.Engine); err != nil {
					t.Fatal(err)
				}
				bs, err := st.Actions().Bindings(ctx, tn.ID, "post-login")
				if err != nil || len(bs) != 0 {
					t.Fatalf("restart reenabled disabled flow: %v %v", bs, err)
				}
			}
		})
	}
}

// The seed refuses a second custom-email-provider binding, as the API does.
func TestActionsSeedSingleCustomEmailBinding(t *testing.T) {
	src := `tenants:
- name: acme
  domains: [acme.test]
  actions:
  - {name: a, supported_triggers: [{id: custom-email-provider, version: v1}], code: "", deploy: true}
  - {name: b, supported_triggers: [{id: custom-email-provider, version: v1}], code: "", deploy: true}
  triggers:
    custom-email-provider:
      bindings: [{ref: {type: action_name, value: a}}, {ref: {type: action_name, value: b}}]
`
	f, err := Parse([]byte(src))
	if err == nil {
		st := memory.New()
		w := testWrapper(t)
		err = ApplyWithActions(context.Background(), st, f, nil, w, actionstest.NewOffline(t, st, w).Engine)
	}
	if err == nil || !strings.Contains(err.Error(), "custom-email-provider") {
		t.Fatalf("two custom-email-provider bindings: %v", err)
	}
}
