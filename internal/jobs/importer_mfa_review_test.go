package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestImportMFAEncodedAliases(t *testing.T) {
	for _, secret := range []string{`TOP"SECRET`, `TOP\SECRET`, `TOP\"SECRET`, "猫☃SECRET", `"quoted-secret"`} {
		t.Run(secret, func(t *testing.T) {
			encode := func(v any) string {
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			encoded := encode(map[string]any{"alias": secret, "password": "*****", "public": "keep", "large_integer": json.Number("9007199254740993")})
			unicodeEscaped := strings.NewReplacer("猫", `\u732b`, "☃", `\u2603`).Replace(encoded)
			aliases := []any{secret, encoded, unicodeEscaped, encode(encoded), encode(map[string]any{"nested": encode([]any{map[string]any{"alias": secret}})}), encode(secret)}
			obj := map[string]any{"email": "bad@example.test", "mfa_factors": []any{map[string]any{"totp": map[string]any{"secret": secret}}}, "custom_password_hash": map[string]any{"algorithm": "sha256", "hash": map[string]any{"encoding": "hex", "value": "masked"}}, "user_metadata": map[string]any{"aliases": aliases}}
			got := (&importRecord{obj: obj}).echo().(map[string]any)
			assertNoEncodedMFAAlias(t, got, secret, 0)
			aliasesOut := got["user_metadata"].(map[string]any)["aliases"].([]any)
			var public map[string]any
			if err := json.Unmarshal([]byte(aliasesOut[1].(string)), &public); err != nil || public["public"] != "keep" || public["password"] != "*****" || !strings.Contains(aliasesOut[1].(string), "9007199254740993") {
				t.Fatal("encoded public/password mask shape changed", public, err)
			}
			hash := got["custom_password_hash"].(map[string]any)
			if hash["algorithm"] != "sha256" || hash["hash"].(map[string]any)["value"] != "*****" {
				t.Fatal("existing hash error shape changed", hash)
			}
			items := maskImportMFAErrors(obj, []store.JobErrorItem{{Message: encoded, Path: encode(encoded)}})
			assertNoEncodedMFAAlias(t, items[0].Message, secret, 0)
			assertNoEncodedMFAAlias(t, items[0].Path, secret, 0)
		})
	}
}
func assertNoEncodedMFAAlias(t *testing.T, v any, secret string, depth int) {
	t.Helper()
	if depth > 32 {
		t.Fatal("test alias nesting exceeded")
	}
	switch x := v.(type) {
	case string:
		if strings.Contains(x, secret) {
			t.Fatal("MFA secret survives error alias redaction")
		}
		trimmed := strings.TrimSpace(x)
		if len(trimmed) > 0 && strings.ContainsRune(`{["`, rune(trimmed[0])) {
			var decoded any
			if json.Unmarshal([]byte(trimmed), &decoded) == nil && !reflect.DeepEqual(decoded, x) {
				assertNoEncodedMFAAlias(t, decoded, secret, depth+1)
			}
		}
	case map[string]any:
		for k, v := range x {
			assertNoEncodedMFAAlias(t, k, secret, depth+1)
			assertNoEncodedMFAAlias(t, v, secret, depth+1)
		}
	case []any:
		for _, v := range x {
			assertNoEncodedMFAAlias(t, v, secret, depth+1)
		}
	}
}

func mfaReviewImportFile(t *testing.T, email, phone string) []byte {
	return fileOf(t, []any{map[string]any{"email": "remember@example.test", "mfa_factors": []any{map[string]any{"email": map[string]any{"value": email}}, map[string]any{"phone": map[string]any{"value": phone}}}}})
}
func mfaReviewBrowser(t *testing.T, e *impEnv) (*session.Manager, *http.Request, *store.User) {
	t.Helper()
	u := e.user("remember@example.test")
	manager := &session.Manager{Store: e.st, Now: func() time.Time { return e.now }}
	w := httptest.NewRecorder()
	if err := manager.SetMFABrowser(context.Background(), w, u, "remember"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://acme.example.test/", nil)
	for _, cookie := range w.Result().Cookies() {
		r.AddCookie(cookie)
	}
	valid, err := manager.MFABrowserValid(context.Background(), r, u, "remember")
	if err != nil || !valid {
		t.Fatal("remember setup invalid", err)
	}
	return manager, r, u
}
func TestImportMFAUpsertInvalidatesRememberBrowser(t *testing.T) {
	forEachStore(t, func(t *testing.T, st store.Store) {
		e := newImpEnv(t, st)
		p := e.importer()
		e.run(p, mfaReviewImportFile(t, "old@example.test", "+1234567"), nil)
		manager, r, u := mfaReviewBrowser(t, e)
		j, errs := e.run(p, mfaReviewImportFile(t, "new@example.test", "+7654321"), map[string]any{ParamUpsert: true, ParamSendCompletionEmail: false})
		if j.Summary.Updated != 1 || len(errs) != 0 {
			t.Fatal(j.Summary, errs)
		}
		current := e.user("remember@example.test")
		if current.RememberBrowserEpoch != u.RememberBrowserEpoch+1 {
			t.Fatalf("factor replacements did not invalidate exactly once: %d -> %d", u.RememberBrowserEpoch, current.RememberBrowserEpoch)
		}
		valid, err := manager.MFABrowserValid(context.Background(), r, current, "remember")
		if err != nil || valid {
			t.Fatal("old remembered browser survives factor replacement", err)
		}
	})
}

var errMFAReviewCheckpoint = errors.New("injected MFA import checkpoint failure")

type mfaReviewFailStore struct{ store.Store }

func (s mfaReviewFailStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(mfaReviewFailStore{tx}) })
}
func (s mfaReviewFailStore) Jobs() store.Jobs { return mfaReviewFailJobs{s.Store.Jobs()} }

type mfaReviewFailJobs struct{ store.Jobs }

func (mfaReviewFailJobs) Checkpoint(context.Context, string, string, string, int, store.JobSummary, []store.JobError) error {
	return errMFAReviewCheckpoint
}
func TestImportMFAFailedUpsertRollsBackRememberEpoch(t *testing.T) {
	forEachStore(t, func(t *testing.T, st store.Store) {
		e := newImpEnv(t, st)
		p := e.importer()
		e.run(p, mfaReviewImportFile(t, "old@example.test", "+1234567"), nil)
		manager, r, u := mfaReviewBrowser(t, e)
		old, err := e.st.MFA().ListAuthenticators(context.Background(), u.TenantID, u.UserID)
		if err != nil {
			t.Fatal(err)
		}
		e.newJob(mfaReviewImportFile(t, "new@example.test", "+7654321"), map[string]any{ParamUpsert: true, ParamSendCompletionEmail: false})
		j, lease := e.claim("w1")
		_, _, err = p.Run(context.Background(), mfaReviewFailStore{st}, j, lease)
		if !errors.Is(err, errMFAReviewCheckpoint) {
			t.Fatal("checkpoint injection missed", err)
		}
		current := e.user("remember@example.test")
		if current.RememberBrowserEpoch != u.RememberBrowserEpoch {
			t.Fatal("failed import advanced epoch")
		}
		valid, err := manager.MFABrowserValid(context.Background(), r, current, "remember")
		if err != nil || !valid {
			t.Fatal("rollback invalidated existing browser", err)
		}
		after, err := e.st.MFA().ListAuthenticators(context.Background(), u.TenantID, u.UserID)
		if err != nil || !reflect.DeepEqual(old, after) {
			t.Fatal("failed import retained new factor state", err)
		}
	})
}
func TestImportMFAEchoBounds(t *testing.T) {
	ctx := logscrub.WithCredentials(context.Background(), "secret")
	if maskImportMFAValue(ctx, strings.Repeat("x", (1<<20)+1)) != logscrub.Marker {
		t.Fatal("oversize alias did not fail closed")
	}
	var deep any = "leaf"
	for range 40 {
		deep = map[string]any{"nested": deep}
	}
	out := maskImportMFAValue(ctx, deep)
	encoded, err := json.Marshal(out)
	if err != nil || strings.Contains(string(encoded), "leaf") || !strings.Contains(string(encoded), logscrub.Marker) {
		t.Fatal("deep alias did not fail closed", err)
	}
}
func TestImportMFAAddingTypePreservesRememberEpoch(t *testing.T) {
	forEachStore(t, func(t *testing.T, st store.Store) {
		e := newImpEnv(t, st)
		p := e.importer()
		file := func(typ, value string) []byte {
			return fileOf(t, []any{map[string]any{"email": "remember@example.test", "mfa_factors": []any{map[string]any{typ: map[string]any{"value": value}}}}})
		}
		e.run(p, file("email", "old@example.test"), nil)
		manager, r, u := mfaReviewBrowser(t, e)
		if u.RememberBrowserEpoch != 0 {
			t.Fatal("initial import invalidated browser epoch")
		}
		j, errs := e.run(p, file("phone", "+1234567"), map[string]any{ParamUpsert: true, ParamSendCompletionEmail: false})
		if j.Summary.Updated != 1 || len(errs) != 0 {
			t.Fatal(j.Summary, errs)
		}
		current := e.user("remember@example.test")
		valid, err := manager.MFABrowserValid(context.Background(), r, current, "remember")
		if err != nil || !valid || current.RememberBrowserEpoch != u.RememberBrowserEpoch {
			t.Fatal("adding new type invalidated existing factor authority", err)
		}
	})
}
