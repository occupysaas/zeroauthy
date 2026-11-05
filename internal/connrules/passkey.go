package connrules

import "github.com/zeroauthy/zeroauthy/internal/store"

// PasskeyPolicy is the stored configuration and its effective runtime policy.
type PasskeyPolicy struct {
	Enabled, Effective bool
	ChallengeUI        string
	Progressive, Local bool
}

// Unmet identifies a prerequisite that keeps passkeys unavailable.
type Unmet string

const (
	UnmetUniversalLogin     Unmet = "universal_login"
	UnmetIdentifierFirst    Unmet = "identifier_first"
	UnmetUsernameOrFlexible Unmet = "username_or_flexible"
	UnmetCustomDBImport     Unmet = "custom_db_import"
	UnmetPasswordEnabled    Unmet = "password_enabled"
	UnmetStrategy           Unmet = "strategy"
)

// Passkeys computes prerequisites without changing the stored options. The API
// permits combinations that hosted login cannot yet offer (LR33b-1).
func Passkeys(conn *store.Connection, prompts map[string]any) (PasskeyPolicy, []Unmet) {
	p := PasskeyPolicy{ChallengeUI: "both", Progressive: true, Local: true}
	unmet := []Unmet{}
	if prompts["universal_login_experience"] != "new" {
		unmet = append(unmet, UnmetUniversalLogin)
	}
	if prompts["identifier_first"] != true {
		unmet = append(unmet, UnmetIdentifierFirst)
	}
	if conn == nil {
		return p, append(unmet, UnmetStrategy)
	}
	if conn.RequiresUsername && conn.Extra["attributes"] == nil {
		unmet = append(unmet, UnmetUsernameOrFlexible)
	}
	if conn.EnabledDatabaseCustomization && !conn.ImportMode {
		unmet = append(unmet, UnmetCustomDBImport)
	}
	methods, _ := conn.Extra["authentication_methods"].(map[string]any)
	password, _ := methods["password"].(map[string]any)
	if password["enabled"] == false {
		unmet = append(unmet, UnmetPasswordEnabled)
	}
	if conn.Strategy != store.StrategyDatabase {
		unmet = append(unmet, UnmetStrategy)
	}
	passkey, _ := methods["passkey"].(map[string]any)
	p.Enabled = passkey["enabled"] == true
	opts, _ := conn.Extra["passkey_options"].(map[string]any)
	if ui, ok := opts["challenge_ui"].(string); ok && (ui == "both" || ui == "button" || ui == "autofill") {
		p.ChallengeUI = ui
	}
	if progressive, ok := opts["progressive_enrollment_enabled"].(bool); ok {
		p.Progressive = progressive
	}
	if local, ok := opts["local_enrollment_enabled"].(bool); ok {
		p.Local = local
	}
	p.Effective = p.Enabled && len(unmet) == 0
	return p, unmet
}
