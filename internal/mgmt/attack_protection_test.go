package mgmt_test

import (
	"bytes"
	"context"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
)

func TestProtectionSettingsSecretsAndMerge(t *testing.T) {
	e := newClientsEnv(t)
	var logs bytes.Buffer
	e.h.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	patch := func(feature string, body any) int {
		rec, _ := e.call(t, e.tn, m2mCaller("update:attack_protection"), "PATCH", "/", body, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateProtection(w, r, feature) })
		if strings.Contains(rec.Body.String(), "private-value") || strings.Contains(rec.Body.String(), "zcap1.") {
			t.Fatal("response leaked secret")
		}
		return rec.Code
	}
	if code := patch("captcha", map[string]any{"active_provider_id": "hcaptcha", "hcaptcha": map[string]any{"site_key": "public", "secret": "private-value"}}); code != 200 {
		t.Fatal(code)
	}
	before, _ := e.st.Tenants().Get(context.Background(), e.tn.ID)
	if before.ProtectionSettings.CAPTCHA.HCaptcha.Secret == "private-value" {
		t.Fatal("plaintext persisted")
	}
	if code := patch("captcha", map[string]any{"simple_captcha": map[string]any{"nested": map[string]any{"n": 1}}}); code != 200 {
		t.Fatal(code)
	}
	after, _ := e.st.Tenants().Get(context.Background(), e.tn.ID)
	if before.ProtectionSettings.CAPTCHA.HCaptcha.Secret != after.ProtectionSettings.CAPTCHA.HCaptcha.Secret {
		t.Fatal("omitted credential changed")
	}
	opened, err := keys.OpenCAPTCHA(e.w, e.tn.ID, after.ProtectionSettings.CAPTCHA)
	if err != nil || opened.HCaptcha.Secret != "private-value" {
		t.Fatal("sealed credential cannot be opened", err)
	}
	for _, body := range []any{`null`, `{"hcaptcha":null}`, `{"hcaptcha":{"site_key":"changed"}}`, `{"active_provider_id":"recaptcha_v2"}`, `{"hcaptcha":{"site_key":"public","secret":""}}`} {
		if patch("captcha", body) != 400 {
			t.Fatalf("accepted invalid provider: %v", body)
		}
	}
	if patch("brute-force-protection", map[string]any{"shields": []string{}}) != 200 {
		t.Fatal("empty shields refused")
	}
	if patch("brute-force-protection", map[string]any{"shields": []string{"admin_notification"}}) != 400 {
		t.Fatal("wrong feature shield accepted")
	}
	var wg sync.WaitGroup
	for _, body := range []map[string]any{{"stage": map[string]any{"pre-login": map[string]any{"rate": 40000}}}, {"stage": map[string]any{"pre-user-registration": map[string]any{"max_attempts": 20}}}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if patch("suspicious-ip-throttling", body) != 200 {
				t.Error("concurrent patch")
			}
		}()
	}
	wg.Wait()
	after, _ = e.st.Tenants().Get(context.Background(), e.tn.ID)
	if after.ProtectionSettings.SuspiciousIP.Stage.PreLogin.Rate != 40000 || after.ProtectionSettings.SuspiciousIP.Stage.PreUserRegistration.MaxAttempts != 20 {
		t.Fatal("patch lost fields")
	}
	if strings.Contains(logs.String(), "private-value") || strings.Contains(logs.String(), "zcap1.") || !strings.Contains(logs.String(), `"actor":"m2m"`) {
		t.Fatalf("audit leaked or missed actor: %s", &logs)
	}
}

func TestProtectionPolicyGenerations(t *testing.T) {
	e := newClientsEnv(t)
	ctx := context.Background()
	e.h.Now = func() time.Time { return now }
	tenant, _ := e.st.Tenants().Get(ctx, e.tn.ID)
	tenant.ProtectionSettings = protectionrules.Defaults()
	tenant.ProtectionSettings.BruteForce.MaxAttempts = 1
	tenant.ProtectionSettingsInitialized = true
	if err := e.st.Tenants().Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	key := protection.LoginKey(e.tn.ID, "db", "a@example.test", "192.0.2.1", "count_per_identifier_and_ip")
	a, err := e.st.Protection().Reserve(ctx, []store.ProtectionLimit{{Key: key, Algorithm: "brute-force", Capacity: 1, Lockout: time.Hour}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.Protection().Complete(ctx, a.Receipt, "failure", now); err != nil {
		t.Fatal(err)
	}
	patch := func(feature string, body any) {
		rec, _ := e.call(t, e.tn, m2mCaller("update:attack_protection"), "PATCH", "/", body, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateProtection(w, r, feature) })
		if rec.Code != 200 {
			t.Fatalf("patch %s: %d %s", feature, rec.Code, rec.Body)
		}
	}
	patch("bot-detection", map[string]any{"bot_detection_level": "high"})
	patch("brute-force-protection", map[string]any{"shields": []string{}})
	bs, err := e.st.Protection().Blocks(ctx, e.tn.ID, store.ProtectionFilter{Kind: store.ProtectionBruteForce}, now)
	if err != nil || len(bs) != 1 {
		t.Fatal("unrelated policy edit erased block", bs, err)
	}
	patch("brute-force-protection", map[string]any{"max_attempts": 2})
	if err := e.st.Protection().Complete(ctx, a.Receipt, "failure", now); err != nil {
		t.Fatal(err)
	}
	bs, err = e.st.Protection().Blocks(ctx, e.tn.ID, store.ProtectionFilter{Kind: store.ProtectionBruteForce}, now)
	if err != nil || len(bs) != 0 {
		t.Fatal("threshold increase or stale completion retained block", bs, err)
	}
	rec, _ := e.call(t, e.sys, mgmt.Caller{Kind: mgmt.Operator}, "PATCH", "/", map[string]any{"max_attempts": 20}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateProtection(w, r, "brute-force-protection") })
	if rec.Code != 403 {
		t.Fatalf("reserved tenant mutated: %d", rec.Code)
	}
}
