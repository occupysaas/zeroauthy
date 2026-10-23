package config

import "testing"

func TestLegacyProtectionPresence(t *testing.T) {
	cfg, err := Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__BASE_DOMAIN=example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.LoginMaxAttemptsExplicit || cfg.Security.LoginLockoutSecondsExplicit {
		t.Fatal("defaults marked explicit")
	}
	cfg, err = Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__BASE_DOMAIN=example.test", "ZEROAUTHY_SECURITY__LOGIN_MAX_ATTEMPTS=10", "ZEROAUTHY_SECURITY__LOGIN_LOCKOUT_SECONDS=900", "ZEROAUTHY_SECURITY__BREACHED_PASSWORDS__MODE=file", "ZEROAUTHY_SECURITY__BREACHED_PASSWORDS__FILE=/tmp/corpus"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Security.LoginMaxAttemptsExplicit || !cfg.Security.LoginLockoutSecondsExplicit || cfg.Security.BreachedPasswords.Mode != "file" {
		t.Fatal("explicit config lost")
	}
	if _, err = Load("", []string{"ZEROAUTHY_STORAGE__DSN=memory://", "ZEROAUTHY_SERVER__BASE_DOMAIN=example.test", "ZEROAUTHY_SECURITY__BREACHED_PASSWORDS__MODE=bad"}); err == nil {
		t.Fatal("invalid mode accepted")
	}
}
