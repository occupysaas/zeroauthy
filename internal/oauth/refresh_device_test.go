package oauth

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"net/url"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestRefreshTokenDevice(t *testing.T) {
	f := newFixture(t)
	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "scope", "openid offline_access"), header: map[string]string{"User-Agent": "issue-agent"}})
	if rec.Code != 200 {
		t.Fatalf("issue status=%d", rec.Code)
	}
	raw := body["refresh_token"].(string)
	rt := f.storedRT(t, raw)
	if rt.Device == nil || rt.Device.InitialUserAgent != "issue-agent" || rt.Device.InitialIP != "192.0.2.1" || rt.LastExchangedAt != nil {
		t.Fatal("initial device not recorded")
	}
	for i := 0; i < 2; i++ {
		at := fixedNow().Add(time.Duration(i+1) * time.Minute)
		f.h.Now = func() time.Time { return at }
		rec, body = f.call(t, true, tokenCall{host: "acme.example.test", form: pwRefresh("ropg", "ropg-secret", raw), header: map[string]string{"User-Agent": "exchange-agent"}})
		if rec.Code != 200 {
			t.Fatalf("exchange=%d %v", rec.Code, body)
		}
		if next, ok := body["refresh_token"].(string); ok {
			raw = next
		}
		rt = f.storedRT(t, raw)
		if rt.Device == nil || rt.Device.InitialUserAgent != "issue-agent" || rt.Device.LastUserAgent != "exchange-agent" || rt.LastExchangedAt == nil || !rt.LastExchangedAt.Equal(at) {
			t.Fatal("last device/exchange not recorded")
		}
	}
}
func pwRefresh(client, secret, raw string) mapValues {
	return mapValues{"grant_type": {"refresh_token"}, "client_id": {client}, "client_secret": {secret}, "refresh_token": {raw}}
}

type mapValues = url.Values

func TestRefreshTokenDeviceRotationConversion(t *testing.T) {
	for _, convert := range []bool{false, true} {
		t.Run(map[bool]string{false: "rotate", true: "convert"}[convert], func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			tid := f.tenantID(t, "acme")
			raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, acmeAPI)
			rt.Device = &store.RefreshTokenDevice{InitialIP: "203.0.113.10", InitialUserAgent: "first"}
			// Recreate a fresh family carrying recorded issuance details.
			if err := f.st.RefreshTokens().Revoke(ctx, tid, rt.ID, fixedNow()); err != nil {
				t.Fatal(err)
			}
			rt.ID += "device"
			rt.TokenHash += "device"
			rt.RevokedAt = nil
			if convert {
				rt.Rotating = false
			}
			if err := f.st.RefreshTokens().Create(ctx, rt); err != nil {
				t.Fatal(err)
			}
			// Use the same high-entropy token through its actual hash.
			raw = "device-" + raw
			rt2 := *rt
			rt2.ID += "next"
			rt2.TokenHash = secrets.HashToken(raw)
			if err := f.st.RefreshTokens().Create(ctx, &rt2); err != nil {
				t.Fatal(err)
			}
			rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw), header: map[string]string{"User-Agent": "second"}})
			if rec.Code != 200 {
				t.Fatalf("exchange=%d %v", rec.Code, body)
			}
			next := f.storedRT(t, body["refresh_token"].(string))
			if next.Device == nil || next.Device.InitialUserAgent != "first" || next.Device.LastUserAgent != "second" || next.LastExchangedAt == nil || !next.LastExchangedAt.Equal(fixedNow()) {
				t.Fatal("successor lost exchange history")
			}
			if !convert {
				old, e := f.st.RefreshTokens().Get(ctx, tid, rt2.ID)
				if e != nil || old.LastExchangedAt == nil {
					t.Fatal("rotated predecessor exchange missing")
				}
			}
		})
	}
}

func TestRefreshTokenExchangeRecordRollback(t *testing.T) {
	f := newFixture(t)
	raw, old := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, acmeAPI)
	f.h.Store = exchangeRecordFailure{f.st}
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw), header: map[string]string{"User-Agent": "failed-agent"}})
	if rec.Code != 500 || body["access_token"] != nil {
		t.Fatalf("write failure=%d", rec.Code)
	}
	current, e := f.st.RefreshTokens().Get(t.Context(), old.TenantID, old.ID)
	if e != nil || current.RotatedAt != nil || current.LastExchangedAt != nil || current.Device != nil {
		t.Fatal("failed mint changed source")
	}
	tokens, e := f.st.RefreshTokens().ListByUser(t.Context(), old.TenantID, old.UserID)
	if e != nil || len(tokens) != 1 {
		t.Fatal("failed mint stored successor")
	}
}

type exchangeRecordFailure struct{ store.Store }

func (s exchangeRecordFailure) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(exchangeRecordFailure{tx}) })
}
func (s exchangeRecordFailure) RefreshTokens() store.RefreshTokens {
	return exchangeRecordFailureTokens{s.Store.RefreshTokens()}
}

type exchangeRecordFailureTokens struct{ store.RefreshTokens }

func (r exchangeRecordFailureTokens) RecordExchange(ctx context.Context, tid, id, ip, ua string, at time.Time) error {
	if e := r.RefreshTokens.RecordExchange(ctx, tid, id, ip, ua, at); e != nil {
		return e
	}
	return errors.New("record exchange failed")
}
