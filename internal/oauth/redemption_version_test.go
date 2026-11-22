package oauth

import (
	"context"
	"net/url"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Supply an older read snapshot while keeping the final transaction on the
// current store. The revision being compared belongs to this redemption.
type priorUserSnapshot struct{ store.Store }

func (s priorUserSnapshot) Users() store.Users { return priorSnapshotUsers{s.Store.Users()} }

type priorSnapshotUsers struct{ store.Users }

func (u priorSnapshotUsers) Get(ctx context.Context, tid, uid string) (*store.User, error) {
	v, err := u.Users.Get(ctx, tid, uid)
	if err == nil {
		v.Version--
	}
	return v, err
}

func TestRedemptionUserVersion(t *testing.T) {
	for _, grant := range []string{"code", "device"} {
		for _, snapshot := range []string{"current", "stale"} {
			t.Run(grant+"/"+snapshot, func(t *testing.T) {
				f := newFixture(t)
				tid, uid := f.tenantID(t, "acme"), f.aliceID(t)
				scopes := []string{"openid", "offline_access"}
				var form url.Values
				if grant == "code" {
					const redirect = "https://rt.acme.test/cb"
					form = codeForm(f.issueCode(t, "rt-spa", redirect, acmeAPI, scopes, pkceChallenge), "rt-spa", redirect, pkceVerifier)
				} else {
					raw, _ := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, uid, scopes)
					form = deviceForm("dev", raw)
				}
				if _, err := f.st.Users().BumpVersion(t.Context(), tid, uid); err != nil {
					t.Fatal(err)
				}
				if snapshot == "stale" {
					f.h.Store = priorUserSnapshot{f.st}
				}
				rec, body := f.call(t, false, tokenCall{host: acmeHost, form: form})
				if snapshot == "current" {
					if rec.Code != 200 || body["refresh_token"] == nil {
						t.Fatalf("current redemption snapshot returned %d", rec.Code)
					}
					return
				}
				if body["error"] != "invalid_grant" || body["access_token"] != nil || body["refresh_token"] != nil {
					t.Fatal("final mint accepted an obsolete user revision")
				}
				got, err := f.st.RefreshTokens().ListByUser(t.Context(), tid, uid)
				if err != nil || len(got) != 0 {
					t.Fatal("stale redemption published a refresh row")
				}
			})
		}
	}
}
