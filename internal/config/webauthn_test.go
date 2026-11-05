package config

import "testing"

func TestConfigWebAuthnRestrict(t *testing.T) {
	env := []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__BASE_DOMAIN=example.test"}
	cfg, err := Load("", env)
	if err != nil || cfg.Security.WebAuthn.RestrictSharedRPIDs {
		t.Fatalf("default: %+v, %v", cfg, err)
	}
	cfg, err = Load("", append(env, "ZEROAUTHY_SECURITY__WEBAUTHN__RESTRICT_SHARED_RP_IDS=true"))
	if err != nil || !cfg.Security.WebAuthn.RestrictSharedRPIDs {
		t.Fatalf("env: %+v, %v", cfg, err)
	}
	path := writeFile(t, "webauthn.yaml", "security:\n  webauthn:\n    restrict_shared_rp_ids: true\n")
	cfg, err = Load(path, env)
	if err != nil || !cfg.Security.WebAuthn.RestrictSharedRPIDs {
		t.Fatalf("file: %+v, %v", cfg, err)
	}
}
