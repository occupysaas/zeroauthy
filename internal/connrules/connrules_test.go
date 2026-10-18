package connrules

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func decode(t *testing.T, body string) *Spec {
	t.Helper()
	var s Spec
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	return &s
}

func mustAPI(t *testing.T, body string) *Spec {
	t.Helper()
	s := decode(t, body)
	CreateDefaults(s)
	if errs := NormalizeAPI(s); len(errs) > 0 {
		t.Fatalf("%s: %v", body, errs)
	}
	return s
}

func wantErr(t *testing.T, name string, s *Spec, api bool, want string) {
	t.Helper()
	var errs []error
	if api {
		errs = NormalizeAPI(s)
	} else {
		errs = Normalize(s)
	}
	for _, e := range errs {
		if strings.Contains(e.Error(), want) {
			return
		}
	}
	t.Errorf("%s: errors %v, want one containing %q", name, errs, want)
}

// A connection that names only a name and strategy gets Auth0's create
// defaults (D-0042).
func TestAPICreateDefaults(t *testing.T) {
	s := mustAPI(t, `{"name":"My-DB","strategy":"auth0"}`)
	c := s.Options.PasswordOptions.Complexity
	if deref(c.MinLength) != 15 || len(c.CharacterTypes) != 0 || c.CharacterTypeRule != "all" ||
		c.IdenticalCharacters != "allow" || c.SequentialCharacters != "allow" || c.MaxLengthExceeded != "error" {
		t.Errorf("complexity = %+v", c)
	}
	po := s.Options.PasswordOptions
	if po.History.Active || deref(po.History.Size) != 3 || po.Dictionary.Active || po.Dictionary.Default != "en_100k" ||
		len(po.Dictionary.Custom) != 0 || po.ProfileData.Active || !slices.Equal(po.ProfileData.BlockedFields, DefaultBlockedFields) {
		t.Errorf("password options = %+v %+v %+v", po.History, po.Dictionary, po.ProfileData)
	}
	if !*s.Options.BruteForceProtection || !slices.Equal(s.Realms, []string{"My-DB"}) || s.IsDomainConnection {
		t.Errorf("spec = %+v", s)
	}
	if !slices.Equal(po.ProfileData.BlockedFields[5:], []string{"user_metadata.name", "user_metadata.first", "user_metadata.last"}) {
		t.Errorf("blocked fields = %v", po.ProfileData.BlockedFields)
	}
	e := s.Options.Extra
	if e["strategy_version"] != float64(2) || s.Authentication["active"] != true || s.ConnectedAccounts["active"] != false {
		t.Errorf("create defaults = %v %v %v", e, s.Authentication, s.ConnectedAccounts)
	}
	am := e["authentication_methods"].(map[string]any)
	if am["passkey"].(map[string]any)["enabled"] != false || am["password"].(map[string]any)["enabled"] != true {
		t.Errorf("authentication_methods = %v", am)
	}
}

// The seed keeps its own defaults: no password options unless named, an
// unset minimum length stays zero (the store reads it as 8).
func TestSeedDefaultsStay(t *testing.T) {
	s := &Spec{Name: "legacy_name with spaces"}
	if errs := Normalize(s); len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.Strategy != "auth0" || s.Options.PasswordOptions != nil || s.Options.BruteForceProtection != nil ||
		s.Realms != nil || s.Options.Extra != nil {
		t.Errorf("seed spec = %+v", s)
	}
	s = &Spec{Name: "db", Options: Options{PasswordOptions: &PasswordOptions{Complexity: &Complexity{}}}}
	if errs := Normalize(s); len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.Options.PasswordOptions.Complexity.MinLength != nil || s.Options.PasswordOptions.History != nil {
		t.Errorf("seed password options = %+v", s.Options.PasswordOptions)
	}
	// The seed's minimum length range is wider than Auth0's.
	s = &Spec{Name: "db", Options: Options{PasswordOptions: &PasswordOptions{Complexity: &Complexity{MinLength: intp(200)}}}}
	if errs := Normalize(s); len(errs) > 0 {
		t.Errorf("seed min length 200: %v", errs)
	}
	wantErr(t, "api min length 200", &Spec{Name: "db", Strategy: "auth0",
		Options: Options{PasswordOptions: &PasswordOptions{Complexity: &Complexity{MinLength: intp(200)}}}}, true, "min_length")
}

func TestNameAndStrategy(t *testing.T) {
	for _, n := range []string{"a", "My-DB", "a-b-c", "A1", "x" + strings.Repeat("y", 127)} {
		if errs := NormalizeAPI(&Spec{Name: n, Strategy: "auth0"}); len(errs) > 0 {
			t.Errorf("name %q: %v", n, errs)
		}
	}
	for _, n := range []string{"", "-a", "a-", "a--b", "a_b", "a.b", "a b", strings.Repeat("a", 129)} {
		wantErr(t, "name "+n, &Spec{Name: n, Strategy: "auth0"}, true, "name")
	}
	wantErr(t, "strategy", &Spec{Name: "a", Strategy: "google-oauth2"}, true, "strategy")
	wantErr(t, "no strategy", &Spec{Name: "a"}, true, "strategy")
	wantErr(t, "seed strategy", &Spec{Name: "a", Strategy: "samlp"}, false, "not supported")
	wantErr(t, "seed no name", &Spec{}, false, "name is required")
}

func TestPasswordLimits(t *testing.T) {
	cx := func(c Complexity) *Spec {
		return &Spec{Name: "a", Strategy: "auth0", Options: Options{PasswordOptions: &PasswordOptions{Complexity: &c}}}
	}
	wantErr(t, "min 73", cx(Complexity{MinLength: intp(73)}), true, "min_length")
	wantErr(t, "min -1", cx(Complexity{MinLength: intp(-1)}), true, "min_length")
	wantErr(t, "bad type", cx(Complexity{MinLength: intp(8), CharacterTypes: []string{"emoji"}}), true, "character_types")
	wantErr(t, "dup type", cx(Complexity{MinLength: intp(8), CharacterTypes: []string{"number", "number"}}), true, "twice")
	wantErr(t, "three_of_four partial", cx(Complexity{MinLength: intp(8), CharacterTypeRule: "three_of_four", CharacterTypes: []string{"number"}}), true, "all four")
	wantErr(t, "bad rule", cx(Complexity{MinLength: intp(8), CharacterTypeRule: "any"}), true, "character_type_rule")
	wantErr(t, "bad identical", cx(Complexity{MinLength: intp(8), IdenticalCharacters: "maybe"}), true, "identical_characters")
	wantErr(t, "bad sequential", cx(Complexity{MinLength: intp(8), SequentialCharacters: "maybe"}), true, "sequential_characters")
	wantErr(t, "bad max", cx(Complexity{MinLength: intp(8), MaxLengthExceeded: "cut"}), true, "max_length_exceeded")
	wantErr(t, "classes 3", cx(Complexity{MinLength: intp(8), MinCharacterClasses: 3}), true, "character classes")
	ok := cx(Complexity{MinLength: intp(72), CharacterTypeRule: "three_of_four", CharacterTypes: store.CharacterTypes, MaxLengthExceeded: "truncate"})
	if errs := NormalizeAPI(ok); len(errs) > 0 {
		t.Errorf("valid complexity: %v", errs)
	}

	hs := func(h History) *Spec {
		return &Spec{Name: "a", Strategy: "auth0", Options: Options{PasswordOptions: &PasswordOptions{History: &h}}}
	}
	wantErr(t, "history 25", hs(History{Active: true, Size: intp(25)}), true, "history.size")
	wantErr(t, "history -1", hs(History{Size: intp(-1)}), true, "history.size")
	for _, n := range []int{1, 24} {
		if errs := NormalizeAPI(hs(History{Active: true, Size: intp(n)})); len(errs) > 0 {
			t.Errorf("history %d: %v", n, errs)
		}
	}
	wantErr(t, "dictionary", &Spec{Name: "a", Strategy: "auth0", Options: Options{PasswordOptions: &PasswordOptions{
		Dictionary: &Dictionary{Default: "en_1m"}}}}, true, "dictionary.default")
	s := mustAPI(t, `{"name":"a","strategy":"auth0","options":{"password_options":{"dictionary":{"active":true,"default":"en_10k","custom":["acme"]}}}}`)
	if d := s.Options.PasswordOptions.Dictionary; !d.Active || d.Default != "en_10k" || !slices.Equal(d.Custom, []string{"acme"}) {
		t.Errorf("dictionary = %+v", d)
	}
	// Parts not sent take their defaults, even when others are.
	if deref(s.Options.PasswordOptions.Complexity.MinLength) != 15 || deref(s.Options.PasswordOptions.History.Size) != 3 {
		t.Errorf("unsent parts = %+v", s.Options.PasswordOptions)
	}
}

func TestLegacyPasswordFields(t *testing.T) {
	cases := []struct {
		level       string
		min         int
		types       []string
		rule, ident string
	}{
		{"none", 1, nil, "all", "allow"},
		{"low", 6, nil, "all", "allow"},
		{"fair", 8, []string{"lowercase", "uppercase", "number"}, "all", "allow"},
		{"good", 8, store.CharacterTypes, "three_of_four", "allow"},
		{"excellent", 10, store.CharacterTypes, "all", "block"},
	}
	for _, tc := range cases {
		s := mustAPI(t, `{"name":"a","strategy":"auth0","options":{"passwordPolicy":"`+tc.level+`"}}`)
		c := s.Options.PasswordOptions.Complexity
		if deref(c.MinLength) != tc.min || !slices.Equal(c.CharacterTypes, append([]string{}, tc.types...)) && !(len(tc.types) == 0 && len(c.CharacterTypes) == 0) ||
			c.CharacterTypeRule != tc.rule || c.IdenticalCharacters != tc.ident {
			t.Errorf("%s: complexity = %+v", tc.level, c)
		}
		if s.Options.PasswordPolicy != "" {
			t.Errorf("%s: legacy field not cleared", tc.level)
		}
	}
	// An explicit minimum length overrides the level's.
	s := mustAPI(t, `{"name":"a","strategy":"auth0","options":{"passwordPolicy":"fair","password_complexity_options":{"min_length":12}}}`)
	if deref(s.Options.PasswordOptions.Complexity.MinLength) != 12 || len(s.Options.PasswordOptions.Complexity.CharacterTypes) != 3 {
		t.Errorf("override = %+v", s.Options.PasswordOptions.Complexity)
	}
	// Legacy history, dictionary and personal data map onto the new parts.
	s = mustAPI(t, `{"name":"a","strategy":"auth0","options":{
		"password_history":{"enable":true,"size":5},
		"password_dictionary":{"enable":true,"dictionary":["acme","widgets"]},
		"password_no_personal_info":{"enable":true}}}`)
	po := s.Options.PasswordOptions
	if !po.History.Active || deref(po.History.Size) != 5 || !po.Dictionary.Active || !slices.Equal(po.Dictionary.Custom, []string{"acme", "widgets"}) ||
		po.Dictionary.Default != "en_100k" || !po.ProfileData.Active || len(po.ProfileData.BlockedFields) != 8 || deref(po.Complexity.MinLength) != 15 {
		t.Errorf("legacy mapping = %+v %+v %+v %+v", po.Complexity, po.History, po.Dictionary, po.ProfileData)
	}
	if s.Options.PasswordHistory != nil || s.Options.PasswordDictionary != nil || s.Options.PasswordNoPersonalInfo != nil {
		t.Error("legacy fields not cleared")
	}
	// Limits.
	for name, body := range map[string]string{
		"policy":       `{"passwordPolicy":"strong"}`,
		"min 0":        `{"password_complexity_options":{"min_length":0}}`,
		"min 129":      `{"password_complexity_options":{"min_length":129}}`,
		"min 100":      `{"password_complexity_options":{"min_length":100}}`,
		"history 25":   `{"password_history":{"enable":true,"size":25}}`,
		"both models":  `{"passwordPolicy":"low","password_options":{}}`,
		"both models2": `{"password_history":{"enable":false},"password_options":{"history":{"active":false,"size":3}}}`,
	} {
		wantErr(t, name, decode(t, `{"name":"a","strategy":"auth0","options":`+body+`}`), true, "")
		if errs := NormalizeAPI(decode(t, `{"name":"a","strategy":"auth0","options":`+body+`}`)); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	wantErr(t, "both", decode(t, `{"name":"a","strategy":"auth0","options":{"passwordPolicy":"low","password_options":{}}}`), true, "cannot be combined")
}

func TestOtherLimits(t *testing.T) {
	spec := func(opts string) *Spec { return decode(t, `{"name":"a","strategy":"auth0","options":`+opts+`}`) }
	wantErr(t, "username min 0", spec(`{"validation":{"username":{"min":0,"max":10}}}`), true, "validation.username.min")
	wantErr(t, "username max 129", spec(`{"validation":{"username":{"min":1,"max":129}}}`), true, "validation.username.max")
	wantErr(t, "username min=max", spec(`{"validation":{"username":{"min":5,"max":5}}}`), true, "less than max")
	if errs := NormalizeAPI(spec(`{"validation":{"username":{"min":1,"max":128}}}`)); len(errs) > 0 {
		t.Errorf("valid username limits: %v", errs)
	}
	wantErr(t, "precedence short", spec(`{"precedence":["email","username"]}`), true, "precedence")
	wantErr(t, "precedence bad", spec(`{"precedence":["email","username","fax"]}`), true, "precedence")
	wantErr(t, "precedence dup", spec(`{"precedence":["email","email","username"]}`), true, "precedence")
	if errs := NormalizeAPI(spec(`{"precedence":["phone_number","email","username"]}`)); len(errs) > 0 {
		t.Errorf("valid precedence: %v", errs)
	}
	wantErr(t, "import without custom db", spec(`{"import_mode":true}`), true, "enabledDatabaseCustomization")
	wantErr(t, "scripts without custom db", spec(`{"customScripts":{"login":"x"}}`), true, "enabledDatabaseCustomization")
	wantErr(t, "unknown script", spec(`{"enabledDatabaseCustomization":true,"customScripts":{"login":"x","bogus":"y"}}`), true, `unknown customScripts key "bogus"`)
	wantErr(t, "no login", spec(`{"enabledDatabaseCustomization":true,"customScripts":{"get_user":"x"}}`), true, "login script")
	wantErr(t, "big script", spec(`{"enabledDatabaseCustomization":true,"customScripts":{"login":"`+strings.Repeat("a", 102401)+`"}}`), true, "larger than 102400")
	wantErr(t, "bad config key", spec(`{"enabledDatabaseCustomization":true,"customScripts":{"login":"x"},"configuration":{"bad-key":"v"}}`), true, `configuration key "bad-key"`)
	wantErr(t, "big config", spec(`{"enabledDatabaseCustomization":true,"customScripts":{"login":"x"},"configuration":{"A":"`+strings.Repeat("v", 4097)+`"}}`), true, "larger than 4096")
	ok := spec(`{"enabledDatabaseCustomization":true,"customScripts":{"login":"x"},"configuration":{"A":"b","B":null}}`)
	if errs := NormalizeAPI(ok); len(errs) > 0 {
		t.Errorf("null configuration value: %v", errs)
	}

	// set_user_root_attributes: API needs the external store.
	root := func(extra string) *Spec {
		return spec(`{"enabledDatabaseCustomization":true,"customScripts":{"login":"x"},"set_user_root_attributes":"on_first_login"` + extra + `}`)
	}
	if errs := NormalizeAPI(root(``)); len(errs) > 0 {
		t.Errorf("external store: %v", errs)
	}
	wantErr(t, "root with import", root(`,"import_mode":true`), true, "set_user_root_attributes")
	wantErr(t, "root without custom db", spec(`{"set_user_root_attributes":"on_each_login"}`), true, "set_user_root_attributes")
	wantErr(t, "root bad", spec(`{"enabledDatabaseCustomization":true,"customScripts":{"login":"x"},"set_user_root_attributes":"sometimes"}`), true, "set_user_root_attributes")
	for _, v := range []string{"on_each_login", "on_first_login", "never_on_login"} {
		if errs := NormalizeAPI(spec(`{"enabledDatabaseCustomization":true,"customScripts":{"login":"x"},"set_user_root_attributes":"` + v + `"}`)); len(errs) > 0 {
			t.Errorf("%s: %v", v, errs)
		}
	}
	// The seed allows it with import mode (as it always did).
	seed := &Spec{Name: "a", Options: Options{EnabledDatabaseCustomization: true, ImportMode: true,
		CustomScripts: map[string]string{"login": "x"}, SetUserRootAttributes: "on_first_login"}}
	if errs := Normalize(seed); len(errs) > 0 {
		t.Errorf("seed import mode with root attributes: %v", errs)
	}
}

func TestExtraKeys(t *testing.T) {
	s := decode(t, `{"name":"a","strategy":"auth0","options":{
		"mfa":{"active":true},"strategy_version":2,"disable_self_service_change_password":true,
		"non_persistent_attrs":["a"],"attributes":{"email":{}},"my_custom":{"deep":[1,2,{"x":null}]},"brute_force_protection":false}}`)
	if _, ok := s.Options.Extra["brute_force_protection"]; ok {
		t.Error("typed key landed in Extra")
	}
	if _, ok := s.Options.Extra["configuration"]; ok {
		t.Error("configuration landed in Extra")
	}
	if s.Options.Extra["my_custom"] == nil || len(s.Options.Extra) != 6 {
		t.Errorf("extra = %v", s.Options.Extra)
	}
	if errs := NormalizeAPI(s); len(errs) > 0 {
		t.Fatal(errs)
	}
	if *s.Options.BruteForceProtection {
		t.Error("explicit brute_force_protection:false overridden")
	}
	for name, body := range map[string]string{
		"mfa string":     `{"mfa":"yes"}`,
		"flag number":    `{"disable_self_service_change_password":1}`,
		"version str":    `{"strategy_version":"2"}`,
		"attrs array":    `{"attributes":[]}`,
		"non_persistent": `{"non_persistent_attrs":[1]}`,
		"reserved":       `{"zeroauthy:connection":{}}`,
	} {
		wantErr(t, name, decode(t, `{"name":"a","strategy":"auth0","options":`+body+`}`), true, "")
		if errs := NormalizeAPI(decode(t, `{"name":"a","strategy":"auth0","options":`+body+`}`)); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	for k, typ := range ExtraSchema {
		if !slices.Contains([]string{"object", "array", "boolean", "number", "string"}, typ) {
			t.Errorf("ExtraSchema[%s] = %q", k, typ)
		}
	}
}

func TestTopLevelProperties(t *testing.T) {
	s := mustAPI(t, `{"name":"a","strategy":"auth0","display_name":"Staff","show_as_button":false,
		"metadata":{"k":"v"},"realms":["a","b"],"is_domain_connection":true,"enabled_clients":["c1"]}`)
	if s.DisplayName != "Staff" || !s.IsDomainConnection {
		t.Errorf("spec = %+v", s)
	}
	wantErr(t, "metadata value", &Spec{Name: "a", Strategy: "auth0", Metadata: map[string]string{"k": strings.Repeat("v", 256)}}, true, "metadata")
	big := map[string]string{}
	for i := range 11 {
		big[string(rune('a'+i))] = "v"
	}
	wantErr(t, "metadata count", &Spec{Name: "a", Strategy: "auth0", Metadata: big}, true, "metadata")
	wantErr(t, "empty realm", &Spec{Name: "a", Strategy: "auth0", Realms: []string{""}}, true, "realms")
}

// Apply and FromConnection are inverses, so an update that changes nothing
// leaves a connection as it was.
func TestFromConnectionApplyRoundTrip(t *testing.T) {
	for _, c := range []*store.Connection{
		{Name: "plain", Strategy: "auth0", BruteForceProtection: true,
			PasswordOptions: store.PasswordOptions{
				Complexity:  store.PasswordComplexity{MinLength: 9, CharacterTypeRule: "all", IdenticalCharacters: "allow", SequentialCharacters: "allow", MaxLengthExceeded: "error"},
				History:     store.PasswordHistory{Size: 3},
				Dictionary:  store.PasswordDictionary{Default: "en_100k"},
				ProfileData: store.PasswordProfileData{BlockedFields: slices.Clone(DefaultBlockedFields)},
			}},
		{Name: "rich", Strategy: "auth0", EnabledClients: []string{"c1", "c2"}, DisableSignup: true, RequiresUsername: true,
			IsDomainConnection: true, UsernameMin: 3, UsernameMax: 20,
			PasswordOptions: store.PasswordOptions{
				Complexity: store.PasswordComplexity{MinLength: 12, CharacterTypes: slices.Clone(store.CharacterTypes),
					CharacterTypeRule: "three_of_four", IdenticalCharacters: "block", SequentialCharacters: "block", MaxLengthExceeded: "truncate"},
				History:     store.PasswordHistory{Active: true, Size: 5},
				Dictionary:  store.PasswordDictionary{Active: true, Default: "en_10k", Custom: []string{"acme"}},
				ProfileData: store.PasswordProfileData{Active: true, BlockedFields: []string{"email"}},
			},
			Extra: map[string]any{
				"mfa": map[string]any{"active": true}, "list": []any{"a", 1.5, nil},
				topKey: map[string]any{"display_name": "Rich", "show_as_button": true, "metadata": map[string]any{"k": "v"},
					"realms": []any{"rich", "other"}, "authentication": map[string]any{"active": false}, "connected_accounts": map[string]any{"active": true}},
			}},
		{Name: "classes", Strategy: "auth0", PasswordOptions: store.PasswordOptions{
			Complexity:  store.PasswordComplexity{MinLength: 8, CharacterTypeRule: "all", IdenticalCharacters: "allow", SequentialCharacters: "allow", MaxLengthExceeded: "error", MinCharacterClasses: 2},
			History:     store.PasswordHistory{Size: 3},
			Dictionary:  store.PasswordDictionary{Default: "en_100k"},
			ProfileData: store.PasswordProfileData{BlockedFields: slices.Clone(DefaultBlockedFields)}}},
		{Name: "custom", Strategy: "auth0", EnabledDatabaseCustomization: true, ImportMode: true, SetUserRootAttributes: "on_first_login",
			CustomScripts: map[string]string{"login": "function login(){}"},
			PasswordOptions: store.PasswordOptions{
				Complexity:  store.PasswordComplexity{MinLength: 8, CharacterTypeRule: "all", IdenticalCharacters: "allow", SequentialCharacters: "allow", MaxLengthExceeded: "error"},
				History:     store.PasswordHistory{Size: 3},
				Dictionary:  store.PasswordDictionary{Default: "en_100k"},
				ProfileData: store.PasswordProfileData{BlockedFields: slices.Clone(DefaultBlockedFields)}}},
	} {
		s := FromConnection(c)
		got := &store.Connection{}
		Apply(s, got)
		if !reflect.DeepEqual(got, c) {
			t.Errorf("%s: round trip\n got %+v\nwant %+v", c.Name, got, c)
		}
	}
}

// FromConnection renders defaults the store leaves as zero values, and a
// connection's MinCharacterClasses stays off the wire.
func TestFromConnectionRendering(t *testing.T) {
	c := &store.Connection{Name: "seeded", Strategy: "auth0",
		PasswordOptions: store.PasswordOptions{Complexity: store.LegacyComplexity(0, 2)}}
	s := FromConnection(c)
	cx := s.Options.PasswordOptions.Complexity
	if deref(cx.MinLength) != 8 || cx.MinCharacterClasses != 2 || cx.CharacterTypeRule != "all" || cx.CharacterTypes == nil || len(cx.CharacterTypes) != 0 {
		t.Errorf("complexity = %+v", cx)
	}
	if !slices.Equal(s.Realms, []string{"seeded"}) || s.EnabledClients == nil || s.Options.Extra == nil {
		t.Errorf("spec = %+v", s)
	}
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "lasses") || strings.Contains(string(out), topKey) || strings.Contains(string(out), "configuration") {
		t.Errorf("wire form leaks internals: %s", out)
	}
	for _, want := range []string{`"min_length":8`, `"enabled_clients":[]`, `"realms":["seeded"]`, `"blocked_fields":["name"`, `"character_types":[]`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("wire form lacks %s: %s", want, out)
		}
	}
	// 3 and 4 classes are expressed in Auth0's terms.
	c.PasswordOptions.Complexity = store.LegacyComplexity(10, 3)
	cx = FromConnection(c).Options.PasswordOptions.Complexity
	if cx.CharacterTypeRule != "three_of_four" || len(cx.CharacterTypes) != 4 || cx.MinCharacterClasses != 0 {
		t.Errorf("three classes = %+v", cx)
	}
}

// Options round-trips unknown keys through JSON, in both directions.
func TestOptionsJSONRoundTrip(t *testing.T) {
	in := `{"brute_force_protection":true,"disable_signup":false,"requires_username":false,
		"enabledDatabaseCustomization":false,"import_mode":false,"my_custom":{"a":[1,"x",null],"b":true},"mfa":{"active":true}}`
	var o Options
	if err := json.Unmarshal([]byte(in), &o); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	_ = json.Unmarshal([]byte(in), &a)
	_ = json.Unmarshal(out, &b)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("round trip\n got %s\nwant %s", out, in)
	}
	// Extra applied and read back keeps the value exactly.
	s := &Spec{Name: "a", Strategy: "auth0", Options: o}
	if errs := Normalize(s); len(errs) > 0 {
		t.Fatal(errs)
	}
	c := &store.Connection{}
	Apply(s, c)
	if !reflect.DeepEqual(c.Extra, o.Extra) {
		t.Errorf("stored extra = %v, want %v", c.Extra, o.Extra)
	}
	// Mutating the stored copy does not reach the spec.
	c.Extra["my_custom"].(map[string]any)["b"] = false
	if o.Extra["my_custom"].(map[string]any)["b"] != true {
		t.Error("Apply aliased Extra")
	}
}

// Apply leaves what the spec does not name, and replaces what it does.
func TestApplyPartial(t *testing.T) {
	c := &store.Connection{Name: "a", BruteForceProtection: true, UsernameMin: 2, UsernameMax: 9,
		Extra:           map[string]any{"keep": true},
		PasswordOptions: store.PasswordOptions{History: store.PasswordHistory{Active: true, Size: 7}}}
	s := &Spec{Name: "a", Strategy: "auth0", Options: Options{PasswordOptions: &PasswordOptions{Complexity: &Complexity{MinLength: intp(10)}}}}
	Apply(s, c)
	if !c.BruteForceProtection || c.UsernameMin != 2 || c.Extra["keep"] != true || !c.PasswordOptions.History.Active ||
		c.PasswordOptions.Complexity.MinLength != 10 {
		t.Errorf("partial apply = %+v", c)
	}
	// An API write replaces the whole.
	api := &Spec{Name: "a", Strategy: "auth0"}
	if errs := NormalizeAPI(api); len(errs) > 0 {
		t.Fatal(errs)
	}
	Apply(api, c)
	if c.UsernameMin != 0 || c.Extra != nil || c.PasswordOptions.History.Active || c.PasswordOptions.Complexity.MinLength != 15 {
		t.Errorf("full apply = %+v", c)
	}
}

// Option keys are case-sensitive: another spelling of a typed key is never
// typed, never stored, and never marshalled back (configuration is sealed
// and must not appear in plaintext).
func TestOptionKeyCase(t *testing.T) {
	for _, body := range []string{
		`{"CONFIGURATION":{"secret":"x"}}`,
		`{"Configuration":{"secret":"x"}}`,
		`{"Brute_Force_Protection":false}`,
		`{"PASSWORDPOLICY":"low"}`,
	} {
		s := decode(t, `{"name":"a","strategy":"auth0","options":`+body+`}`)
		if s.Options.Configuration != nil || s.Options.BruteForceProtection != nil || s.Options.PasswordPolicy != "" {
			t.Errorf("%s: typed field filled: %+v", body, s.Options)
		}
		errs := NormalizeAPI(s)
		if len(errs) == 0 {
			t.Errorf("%s: accepted", body)
		}
		out, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "secret") {
			t.Errorf("%s: plaintext marshalled: %s", body, out)
		}
	}
	// The exact spelling is typed and leaves Extra empty of it.
	s := decode(t, `{"name":"a","strategy":"auth0","options":{"configuration":{"K":"secret"},"brute_force_protection":false}}`)
	if s.Options.Configuration == nil || s.Options.BruteForceProtection == nil || len(s.Options.Extra) != 0 {
		t.Errorf("exact keys: %+v", s.Options)
	}
	// MarshalJSON skips a case variant even if set programmatically.
	o := Options{Extra: map[string]any{"CONFIGURATION": "secret", "Mfa": 1}}
	out, _ := json.Marshal(o)
	if strings.Contains(string(out), "secret") {
		t.Errorf("marshalled variant: %s", out)
	}
}

// An explicit 0 is refused where Auth0 refuses it; absence takes the default.
func TestExplicitZeroLimits(t *testing.T) {
	spec := func(po string) *Spec {
		return decode(t, `{"name":"a","strategy":"auth0","options":{"password_options":`+po+`}}`)
	}
	wantErr(t, "min_length 0", spec(`{"complexity":{"min_length":0}}`), true, "min_length")
	wantErr(t, "history size 0", spec(`{"history":{"active":true,"size":0}}`), true, "history.size")
	wantErr(t, "legacy history size 0", decode(t, `{"name":"a","strategy":"auth0","options":{"password_history":{"enable":true,"size":0}}}`), true, "history.size")
	wantErr(t, "seed min_length 0", &Spec{Name: "a", Options: Options{PasswordOptions: &PasswordOptions{Complexity: &Complexity{MinLength: intp(0)}}}}, false, "min_length")
	s := mustAPI(t, `{"name":"a","strategy":"auth0","options":{"password_options":{"complexity":{"character_types":[]},"history":{"active":true}}}}`)
	if deref(s.Options.PasswordOptions.Complexity.MinLength) != 15 || deref(s.Options.PasswordOptions.History.Size) != 3 {
		t.Errorf("absent values = %+v %+v", s.Options.PasswordOptions.Complexity, s.Options.PasswordOptions.History)
	}
	s = mustAPI(t, `{"name":"a","strategy":"auth0","options":{"password_history":{"enable":true}}}`)
	if deref(s.Options.PasswordOptions.History.Size) != 3 {
		t.Errorf("legacy absent size = %+v", s.Options.PasswordOptions.History)
	}
}
