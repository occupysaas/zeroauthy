package seed

import (
	"bytes"
	"context"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestProtectionSeedPrecedence(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(make([]byte, 32))
	f, err := Parse([]byte("tenants:\n- name: acme\n  friendly_name: First\n  session_lifetime: 3600\n  attack_protection:\n    brute-force-protection:\n      max_attempts: 19\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	if err := InitializeProtection(ctx, st, config.Security{LoginMaxAttempts: 3, LoginLockoutSeconds: 900, LoginMaxAttemptsExplicit: true}, slog.Default()); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if !tn.ProtectionSettingsInitialized || tn.ProtectionSettings.BruteForce.MaxAttempts != 19 || tn.SessionLifetime != 3600 {
		t.Fatal("initial policy/seconds lost")
	}
	tn.FriendlyName = "API edit"
	tn.SupportEmail = "help@example.test"
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	f, err = Parse([]byte("tenants:\n- name: acme\n  session_lifetime: 7200\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ = st.Tenants().GetByName(ctx, "acme")
	if tn.FriendlyName != "API edit" || tn.SupportEmail != "help@example.test" || tn.SessionLifetime != 7200 || tn.ProtectionSettings.BruteForce.MaxAttempts != 19 {
		t.Fatal("omitted settings overwritten")
	}
	f.Mode = ModeCreateOnly
	f.Tenants[0].SessionLifetime = 8000
	if err := Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ = st.Tenants().GetByName(ctx, "acme")
	if tn.SessionLifetime != 7200 {
		t.Fatal("create_only overwrote settings")
	}
}

func TestProtectionInitializationOnce(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, _ := Parse([]byte("tenants:\n- name: acme\n"))
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	var audit bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&audit, nil))
	cfg := config.Security{LoginMaxAttempts: 4, LoginLockoutSeconds: 900, LoginMaxAttemptsExplicit: true}
	if err := InitializeProtection(ctx, st, cfg, logger); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if tn.ProtectionSettings.BruteForce.MaxAttempts != 4 || tn.ProtectionSettings.LegacyLockoutSeconds != 900 {
		t.Fatal("explicit legacy not honored")
	}
	if !strings.Contains(audit.String(), tn.ID) || !strings.Contains(audit.String(), "legacy compatibility mode") || !strings.Contains(audit.String(), `"level":"WARN"`) {
		t.Fatal("missing initialization audit", audit.String())
	}
	firstAudit := audit.String()
	tn.ProtectionSettings.BruteForce.MaxAttempts = 21
	if err := st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := InitializeProtection(ctx, st, cfg, logger); err != nil {
		t.Fatal(err)
	}
	tn, _ = st.Tenants().GetByName(ctx, "acme")
	if audit.String() != firstAudit {
		t.Fatal("restart emitted another initialization audit")
	}
	if tn.ProtectionSettings.BruteForce.MaxAttempts != 21 {
		t.Fatal("restart overwrote policy")
	}
}

func TestSeedSettingsDuplicate(t *testing.T) {
	for _, extra := range []string{"session_lifetime: 3600\n  settings:\n    session_lifetime: 1", "branding:\n    logo_url: https://example.test/a\n  settings:\n    picture_url: https://example.test/b", "device_flow:\n    mask: XX\n  settings:\n    device_flow:\n      mask: XX"} {
		if _, err := Parse([]byte("tenants:\n- name: acme\n  " + extra + "\n")); err == nil {
			t.Fatal("duplicate setting accepted")
		}
	}
}

func TestProtectionDefaultInitialization(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, _ := Parse([]byte("tenants:\n- name: acme\n"))
	if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	cfg := config.Security{LoginMaxAttempts: 10, LoginLockoutSeconds: 900}
	if err := InitializeProtection(ctx, st, cfg, slog.Default()); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if !tn.ProtectionSettingsInitialized || tn.ProtectionSettings.BruteForce.MaxAttempts != 10 || tn.ProtectionSettings.LegacyLockoutSeconds != 0 || tn.ProtectionSettings.BreachedPassword.Enabled {
		t.Fatal("unsupplied config did not use defaults")
	}
}

func TestSeedCaptchaEncryptedAndOmittedNestedSettings(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(make([]byte, 32))
	f, err := Parse([]byte(`tenants:
- name: acme
  branding:
    logo_url: https://example.test/logo
    primary_color: '#112233'
  device_flow:
    charset: digits
    mask: '***-***-***'
  settings:
    support_email: help@example.test
  attack_protection:
    captcha:
      hcaptcha:
        site_key: site
        secret: secret-fixture
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	cipher := tn.ProtectionSettings.CAPTCHA.HCaptcha.Secret
	if cipher == "" || cipher == "secret-fixture" {
		t.Fatal("plaintext persisted")
	}
	f, err = Parse([]byte(`tenants:
- name: acme
  branding:
    primary_color: '#445566'
  device_flow:
    mask: '*** *** ***'
  settings:
    support_url: https://example.test/support
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, st, f, fixedNow, w); err != nil {
		t.Fatal(err)
	}
	tn, _ = st.Tenants().GetByName(ctx, "acme")
	if tn.Branding.LogoURL != "https://example.test/logo" || tn.PictureURL != tn.Branding.LogoURL || tn.DeviceFlowCharset != "digits" || tn.SupportEmail != "help@example.test" || tn.ProtectionSettings.CAPTCHA.HCaptcha.Secret != cipher {
		t.Fatal("nested omitted settings changed")
	}
}

func TestSeedDistinctNestedSettings(t *testing.T) {
	_, err := Parse([]byte(`tenants:
- name: acme
  branding:
    primary_color: '#112233'
  device_flow:
    charset: digits
  settings:
    picture_url: https://example.test/logo
    device_flow:
      mask: '***-***-***'
`))
	if err != nil {
		t.Fatal(err)
	}
}

func TestSeedSettingsReferences(t *testing.T) {
	for _, field := range []string{"default_audience", "default_directory"} {
		st := memory.New()
		f, err := Parse([]byte("tenants:\n- name: acme\n  settings:\n    " + field + ": missing\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(context.Background(), st, f, fixedNow, nil); err == nil {
			t.Fatal("unresolved reference accepted", field)
		}
		if _, err := st.Tenants().GetByName(context.Background(), "acme"); err == nil {
			t.Fatal("invalid seed was not rolled back")
		}
	}
}

func TestCreateOnlyIgnoresSettingsReferences(t *testing.T) {
	ctx := context.Background()
	for _, field := range []string{"default_audience", "default_directory"} {
		t.Run(field, func(t *testing.T) {
			st := memory.New()
			initial, _ := Parse([]byte("tenants:\n- name: acme\n"))
			if err := Apply(ctx, st, initial, fixedNow, nil); err != nil {
				t.Fatal(err)
			}
			tn, _ := st.Tenants().GetByName(ctx, "acme")
			tn.DefaultAudience = "existing-unresolved"
			tn.DefaultDirectory = "existing-unresolved"
			if err := st.Tenants().Update(ctx, tn); err != nil {
				t.Fatal(err)
			}
			f, err := Parse([]byte("tenants:\n- name: acme\n  settings:\n    " + field + ": ignored\n"))
			if err != nil {
				t.Fatal(err)
			}
			f.Mode = ModeCreateOnly
			if err := Apply(ctx, st, f, fixedNow, nil); err != nil {
				t.Fatal(err)
			}
			got, _ := st.Tenants().GetByName(ctx, "acme")
			if got.DefaultAudience != tn.DefaultAudience || got.DefaultDirectory != tn.DefaultDirectory {
				t.Fatal("create_only changed settings")
			}
		})
	}
}
