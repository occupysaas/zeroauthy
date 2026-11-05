package connrules

import (
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPasskeyPolicy(t *testing.T) {
	good := func() *store.Connection {
		return &store.Connection{Strategy: store.StrategyDatabase, Extra: map[string]any{
			"authentication_methods": map[string]any{"password": map[string]any{"enabled": true}, "passkey": map[string]any{"enabled": true}},
		}}
	}
	prompts := map[string]any{"universal_login_experience": "new", "identifier_first": true}
	p, unmet := Passkeys(good(), prompts)
	if !p.Enabled || !p.Effective || len(unmet) != 0 || p.ChallengeUI != "both" || !p.Progressive || !p.Local {
		t.Fatalf("all met = %+v %v", p, unmet)
	}
	cases := []struct {
		name    string
		conn    func(*store.Connection)
		prompts map[string]any
		want    Unmet
	}{
		{"strategy", func(c *store.Connection) { c.Strategy = "google-oauth2" }, prompts, UnmetStrategy},
		{"classic", nil, map[string]any{"universal_login_experience": "classic", "identifier_first": true}, UnmetUniversalLogin},
		{"identifier first off", nil, map[string]any{"identifier_first": false}, UnmetIdentifierFirst},
		{"requires username", func(c *store.Connection) { c.RequiresUsername = true }, prompts, UnmetUsernameOrFlexible},
		{"custom db", func(c *store.Connection) { c.EnabledDatabaseCustomization = true }, prompts, UnmetCustomDBImport},
		{"password off", func(c *store.Connection) {
			c.Extra["authentication_methods"].(map[string]any)["password"] = map[string]any{"enabled": false}
		}, prompts, UnmetPasswordEnabled},
	}
	for _, c := range cases {
		conn := good()
		if c.conn != nil {
			c.conn(conn)
		}
		p, unmet := Passkeys(conn, c.prompts)
		if p.Effective || !slices.Contains(unmet, c.want) {
			t.Errorf("%s: %+v %v, want unmet %s", c.name, p, unmet, c.want)
		}
	}
	flexible := good()
	flexible.RequiresUsername = true
	flexible.Extra["attributes"] = map[string]any{"email": map[string]any{"identifier": map[string]any{"active": true}}}
	if p, unmet := Passkeys(flexible, prompts); !p.Effective {
		t.Errorf("flexible identifiers with requires_username: %+v %v", p, unmet)
	}
	imported := good()
	imported.EnabledDatabaseCustomization, imported.ImportMode = true, true
	if p, _ := Passkeys(imported, prompts); !p.Effective {
		t.Errorf("custom DB in import mode: %+v", p)
	}
	off := good()
	off.Extra["authentication_methods"].(map[string]any)["passkey"] = map[string]any{"enabled": false}
	if p, _ := Passkeys(off, prompts); p.Enabled || p.Effective {
		t.Errorf("disabled passkeys: %+v", p)
	}
	custom := good()
	custom.Extra["passkey_options"] = map[string]any{"challenge_ui": "button", "progressive_enrollment_enabled": false, "local_enrollment_enabled": false}
	if p, _ := Passkeys(custom, prompts); p.ChallengeUI != "button" || p.Progressive || p.Local {
		t.Errorf("custom options: %+v", p)
	}
}
