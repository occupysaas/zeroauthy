package actionsrules

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func validAction() *store.Action {
	return &store.Action{Name: "Add claims", Trigger: "post-login", Code: "exports.onExecutePostLogin = async () => {}"}
}

func TestActionsNormalizeAction(t *testing.T) {
	a := validAction()
	if errs := NormalizeAction(a); len(errs) != 0 || a.Runtime != "node22" {
		t.Fatalf("errs=%v runtime=%q", errs, a.Runtime)
	}
	for name, mod := range map[string]func(*store.Action){
		"empty name":  func(a *store.Action) { a.Name = "" },
		"long name":   func(a *store.Action) { a.Name = strings.Repeat("é", 129) },
		"bad trigger": func(a *store.Action) { a.Trigger = "nope" },
		"bad runtime": func(a *store.Action) { a.Runtime = "node18" },
		"big code":    func(a *store.Action) { a.Code = strings.Repeat("x", 100001) },
		"bad dep":     func(a *store.Action) { a.Dependencies = []store.Dependency{{Name: "x", Version: "^1.0.0"}} },
		"bad secret":  func(a *store.Action) { a.Secrets = []store.ActionSecret{{Name: "a-b"}} },
	} {
		a := validAction()
		mod(a)
		if len(NormalizeAction(a)) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	a = validAction()
	a.Name = strings.Repeat("é", 128)
	a.Code = strings.Repeat("x", 100000)
	if errs := NormalizeAction(a); len(errs) != 0 {
		t.Fatalf("boundaries: %v", errs)
	}
}

func TestActionsValidateDependencies(t *testing.T) {
	for _, v := range []string{"", "latest", "1.2.3", "1.2.3-beta.1", "0.0.0+build.5"} {
		if errs := ValidateDependencies([]store.Dependency{{Name: "lodash", Version: v}}); len(errs) != 0 {
			t.Errorf("%q refused: %v", v, errs)
		}
	}
	for _, v := range []string{"^1.2.3", "~1.2.3", "1.x", "1", ">=1.0.0", "*", "next", "git+https://x/y.git", "github:a/b", "file:../x", "https://x/y.tgz", "npm:foo@1.0.0", "1.2.3 - 2.0.0", "01.2.3"} {
		if len(ValidateDependencies([]store.Dependency{{Name: "lodash", Version: v}})) == 0 {
			t.Errorf("%q accepted", v)
		}
	}
	for _, n := range []string{"", "Lodash", "../x", "a b", "git+https://x", "http://x/y.tgz", ".hidden", "_x", "@scope/", "@s/n/m"} {
		if len(ValidateDependencies([]store.Dependency{{Name: n}})) == 0 {
			t.Errorf("name %q accepted", n)
		}
	}
	if len(ValidateDependencies([]store.Dependency{{Name: "@scope/pkg", Version: "1.0.0"}})) != 0 {
		t.Error("scoped refused")
	}
	if len(ValidateDependencies([]store.Dependency{{Name: "a"}, {Name: "a"}})) == 0 {
		t.Error("duplicate accepted")
	}
	many := make([]store.Dependency, 51)
	for i := range many {
		many[i].Name = "p" + strings.Repeat("a", i)
	}
	if len(ValidateDependencies(many)) == 0 || len(ValidateDependencies(many[:50])) != 0 {
		t.Error("dependency count limit")
	}
}

func TestActionsValidateSecrets(t *testing.T) {
	ok := []store.ActionSecret{{Name: "API_KEY1"}, {Name: strings.Repeat("a", 128)}}
	if errs := ValidateSecrets(ok); len(errs) != 0 {
		t.Fatal(errs)
	}
	for _, s := range [][]store.ActionSecret{{{Name: ""}}, {{Name: strings.Repeat("a", 129)}}, {{Name: "a.b"}}, {{Name: "a"}, {Name: "a"}}} {
		if len(ValidateSecrets(s)) == 0 {
			t.Errorf("%v accepted", s)
		}
	}
	many := make([]store.ActionSecret, 65)
	for i := range many {
		many[i].Name = "s" + strings.Repeat("a", i)
	}
	if len(ValidateSecrets(many)) == 0 || len(ValidateSecrets(many[:64])) != 0 {
		t.Error("secret count limit")
	}
}

func TestActionsValidateBindings(t *testing.T) {
	b := func(n int) []store.Binding {
		out := make([]store.Binding, n)
		for i := range out {
			out[i] = store.Binding{ActionID: "a"}
		}
		return out
	}
	if len(ValidateBindings("post-login", b(20))) != 0 || len(ValidateBindings("post-login", b(21))) == 0 {
		t.Error("binding limit")
	}
	if len(ValidateBindings("nope", b(1))) == 0 || len(ValidateBindings("post-login", []store.Binding{{}})) == 0 {
		t.Error("trigger/action")
	}
	if len(ValidateBindings("post-login", []store.Binding{{ActionID: "a", Trigger: "credentials-exchange"}})) == 0 {
		t.Error("mismatched trigger")
	}
}

// Rejecting malformed reference pairs prevents silently pinning a different module.
func TestModuleRules(t *testing.T) {
	for _, refs := range [][]store.ModuleRef{
		{{ModuleID: "m"}}, {{VersionID: "v"}}, {{ModuleName: "m"}}, {{VersionNumber: 1}},
		{{ModuleID: "m", VersionID: "v", ModuleName: "n"}},
		{{ModuleName: "m", VersionNumber: 1}, {ModuleName: "m", VersionNumber: 2}},
	} {
		if len(ValidateModuleRefs(refs)) == 0 {
			t.Fatalf("accepted malformed refs: %+v", refs)
		}
	}
	for _, refs := range [][]store.ModuleRef{{{ModuleID: "m", VersionID: "v"}}, {{ModuleName: "m", VersionNumber: 1}}, {{ModuleID: "m", VersionID: "v", ModuleName: "n", VersionNumber: 1}}} {
		if errs := ValidateModuleRefs(refs); len(errs) != 0 {
			t.Fatal(errs)
		}
	}
	for _, name := range []string{"", "a\x00b", strings.Repeat("x", 256)} {
		if len(NormalizeModule(&store.ActionModule{Name: name})) == 0 {
			t.Fatalf("accepted name %q", name)
		}
	}
	if errs := NormalizeModule(&store.ActionModule{Name: "Any Module", Code: strings.Repeat("é", 65536)}); len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(NormalizeModule(&store.ActionModule{Name: "m", Code: strings.Repeat("é", 65537)})) == 0 {
		t.Fatal("oversized module")
	}
}
