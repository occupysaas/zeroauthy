package oauth

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func (f *fixture) rotationPolicy(t *testing.T, rotating bool, leeway int) {
	t.Helper()
	ctx := t.Context()
	c, err := f.st.Clients().Get(ctx, f.tenantID(t, "acme"), "rt-spa")
	if err != nil {
		t.Fatal(err)
	}
	c.RefreshToken.Rotating = rotating
	c.RefreshToken.Leeway = leeway
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) exchangeSuccessor(t *testing.T, raw string) string {
	t.Helper()
	status, body := f.refresh(t, refreshForm("rt-spa", raw))
	next, _ := body["refresh_token"].(string)
	if status != 200 || next == "" || next == raw {
		t.Fatalf("exchange status %d, error %v, new refresh token present %t", status, body["error"], next != "")
	}
	return next
}

func (f *fixture) requireInvalidRefresh(t *testing.T, raw string, extra ...string) {
	t.Helper()
	status, body := f.refresh(t, refreshForm("rt-spa", raw, extra...))
	if status != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil {
		t.Fatalf("exchange status %d, error %v", status, body["error"])
	}
}

func TestConvertToRotating(t *testing.T) {
	f := newFixture(t)
	f.rotationPolicy(t, false, 0)
	scopes := []string{"openid", "offline_access", "read:things"}
	_, old := f.issueRefresh(t, "rt-spa", scopes, acmeAPI)
	sibling, _ := f.issueRefresh(t, "rt-spa", scopes, acmeAPI)
	other, _ := f.issueRefresh(t, "rt-spa", scopes, "")
	// Add a grant with a concrete origin and device history.
	raw := secrets.RandomString(48)
	old.ID = "rt_" + secrets.RandomString(24)
	old.TokenHash = secrets.HashToken(raw)
	old.Access = "offline"
	old.Origin = "https://acme.example.test"
	old.Metadata = map[string]string{"deployment": "test"}
	old.Device = &store.RefreshTokenDevice{InitialUserAgent: "test browser"}
	if err := f.st.RefreshTokens().Create(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	f.rotationPolicy(t, true, 0)
	now := fixedNow().Add(time.Hour)
	f.h.Now = func() time.Time { return now }
	next := f.storedRT(t, f.exchangeSuccessor(t, raw))
	if !next.Rotating || next.FamilyID == "" || next.FamilyID == old.FamilyID || next.ParentID != "" ||
		!next.ExpiresAt.Equal(now.Add(DefaultRefreshTokenLifetime)) || !next.IdleExpiresAt.Equal(now.Add(DefaultRefreshTokenIdleLifetime)) {
		t.Fatal("converted token has incorrect family, rotation or lifetimes")
	}
	if !old.ValidSuccessor(next) || next.Access != "offline" || !slices.Equal(old.Scopes, next.Scopes) ||
		!next.AuthTime.Equal(old.AuthTime) || !maps.Equal(next.Metadata, old.Metadata) || next.Device == nil || next.Device.InitialUserAgent != old.Device.InitialUserAgent || next.Device.InitialIP != old.Device.InitialIP || next.Device.LastIP != "192.0.2.1" || next.LastExchangedAt == nil || !next.LastExchangedAt.Equal(now) {
		t.Fatal("conversion lost a grant binding or device detail")
	}
	f.requireInvalidRefresh(t, raw)
	f.requireInvalidRefresh(t, sibling)
	f.exchangeSuccessor(t, other)
}

func TestConvertToNonRotating(t *testing.T) {
	f := newFixture(t)
	f.rotationPolicy(t, true, 30)
	raw, old := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
	head := f.exchangeSuccessor(t, raw)
	otherFamily, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
	f.rotationPolicy(t, false, 30)
	next := f.exchangeSuccessor(t, raw) // immediate parent can convert inside leeway
	got := f.storedRT(t, next)
	if got.Rotating || got.FamilyID == "" || got.FamilyID == old.FamilyID || got.ParentID != "" {
		t.Fatal("conversion did not start a new non-rotating family")
	}
	for _, retired := range []string{raw, head, otherFamily} {
		f.requireInvalidRefresh(t, retired)
	}
	status, body := f.refresh(t, refreshForm("rt-spa", next))
	if status != 200 || body["refresh_token"] != nil {
		t.Fatalf("converted token status %d, error %v", status, body["error"])
	}
}

func TestConvertOneWinner(t *testing.T) {
	f := newFixture(t)
	f.rotationPolicy(t, false, 0)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, "")
	f.rotationPolicy(t, true, 0)
	type outcome struct {
		status       int
		hasSuccessor bool
		code         any
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			status, body := f.refresh(t, refreshForm("rt-spa", raw))
			next, _ := body["refresh_token"].(string)
			results <- outcome{status, next != "", body["error"]}
		}()
	}
	close(start)
	winners := 0
	for range 2 {
		res := <-results
		switch {
		case res.status == 200 && res.hasSuccessor:
			winners++
		case res.status == 400 && res.code == "invalid_grant" && !res.hasSuccessor:
		default:
			t.Fatalf("unexpected exchange result %+v", res)
		}
	}
	if winners != 1 {
		t.Fatalf("%d winning conversions", winners)
	}
}

func TestStrictLeewayPrevious(t *testing.T) {
	f := newFixture(t)
	f.rotationPolicy(t, true, 30)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, "")
	first := f.exchangeSuccessor(t, raw)
	second := f.exchangeSuccessor(t, raw)
	if first == second {
		t.Fatal("leeway did not issue a fresh token")
	}
	f.exchangeSuccessor(t, first) // the sibling remains a live token
}

func TestStrictLeewaySecondToLast(t *testing.T) {
	for name, extra := range map[string][]string{"audience": {"audience", "other"}, "scope": {"scope", "write:things"}} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.rotationPolicy(t, true, 30)
			raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
			middle := f.exchangeSuccessor(t, raw)
			head := f.exchangeSuccessor(t, middle)
			f.requireInvalidRefresh(t, raw, extra...)
			f.requireInvalidRefresh(t, head)
		})
	}
}

func TestLeewayExpired(t *testing.T) {
	f := newFixture(t)
	f.rotationPolicy(t, true, 30)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, "")
	head := f.exchangeSuccessor(t, raw)
	f.h.Now = func() time.Time { return fixedNow().Add(30 * time.Second) }
	f.requireInvalidRefresh(t, raw)
	f.requireInvalidRefresh(t, head)
}

func TestOfflineRecheck(t *testing.T) {
	for _, tc := range []struct {
		name       string
		convert    bool
		duringMint bool
	}{{"rotate", false, false}, {"convert", true, false}, {"at mint", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, acmeAPI)
			if tc.convert {
				f.rotationPolicy(t, false, 0)
			}
			disable := func() {
				rs, err := f.st.ResourceServers().GetByIdentifier(t.Context(), rt.TenantID, acmeAPI)
				if err != nil {
					t.Fatal(err)
				}
				rs.AllowOfflineAccess = false
				if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
					t.Fatal(err)
				}
			}
			if tc.duringMint {
				f.h.Store = changingRBACStore{f.st, disable}
			} else {
				disable()
			}
			f.requireInvalidRefresh(t, raw)
			if got := f.storedRT(t, raw); got.RotatedAt != nil || got.RevokedAt != nil {
				t.Fatal("disabled API consumed the token")
			}
		})
	}
}

func TestConvertAfterChecks(t *testing.T) {
	f := newFixture(t)
	f.rotationPolicy(t, false, 0)
	raw, old := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
	f.rotationPolicy(t, true, 0)
	u, err := f.st.Users().Get(t.Context(), old.TenantID, old.UserID)
	if err != nil {
		t.Fatal(err)
	}
	u.Blocked = true
	if err := f.st.Users().Update(t.Context(), u); err != nil {
		t.Fatal(err)
	}
	f.requireInvalidRefresh(t, raw)
	if got := f.storedRT(t, raw); got.Rotating || got.RotatedAt != nil || got.RevokedAt != nil {
		t.Fatal("blocked user's grant changed")
	}
}

type refreshProbeStore struct {
	store.Store
	err error
}

func (s refreshProbeStore) CheckRefreshTokensIISupport(context.Context) error { return s.err }

func TestRefreshLegacyNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		probe      error
		wantStatus int
	}{
		{"legacy", store.ErrRefreshTokensIIUnavailable, 200},
		{"lost", store.ErrRefreshTokensIISupportLost, 500},
		{"transport", errors.New("temporary probe failure"), 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.rotationPolicy(t, false, 0)
			raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, "")
			f.rotationPolicy(t, true, 0)
			f.h.Store = refreshProbeStore{f.st, tc.probe}
			status, body := f.refresh(t, refreshForm("rt-spa", raw))
			if status != tc.wantStatus || body["refresh_token"] != nil {
				t.Fatalf("status %d, error %v, successor present %t", status, body["error"], body["refresh_token"] != nil)
			}
		})
	}
}

func TestRefreshClientGrantAtCommit(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		name := "convert"
		if rotate {
			name = "rotate"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.rotationPolicy(t, rotate, 0)
			raw, record := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
			f.rotationPolicy(t, true, 0)
			f.h.Store = nativeBeforeTxStore{f.st, func() {
				c, err := f.st.Clients().Get(t.Context(), record.TenantID, record.ClientID)
				if err != nil {
					t.Fatal(err)
				}
				c.GrantTypes = slices.DeleteFunc(c.GrantTypes, func(g string) bool { return g == "refresh_token" })
				if err := f.st.Clients().Update(t.Context(), c); err != nil {
					t.Fatal(err)
				}
			}}
			status, body := f.refresh(t, refreshForm(record.ClientID, raw))
			if status == 200 || body["access_token"] != nil || body["refresh_token"] != nil {
				t.Fatal("published a response after the refresh grant was disabled")
			}
			got, err := f.st.RefreshTokens().Get(t.Context(), record.TenantID, record.ID)
			if err != nil || got.RotatedAt != nil || got.RevokedAt != nil || got.LastExchangedAt != nil {
				t.Fatal("client policy refusal changed the presentation")
			}
		})
	}
}

func TestRefreshPolicyAtCommit(t *testing.T) {
	f := newFixture(t)
	raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid"}, acmeAPI)
	f.h.Store = nativeBeforeTxStore{f.st, func() {
		rs, err := f.st.ResourceServers().GetByIdentifier(t.Context(), rt.TenantID, acmeAPI)
		if err != nil {
			t.Fatal(err)
		}
		rs.AllowOfflineAccess = false
		if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
			t.Fatal(err)
		}
	}}
	f.requireInvalidRefresh(t, raw)
	if got := f.storedRT(t, raw); got.RotatedAt != nil || got.RevokedAt != nil {
		t.Fatal("policy change at commit consumed the token")
	}
}

func TestRefreshReuseAtCommit(t *testing.T) {
	for _, rotating := range []bool{true, false} {
		name := "rotate"
		if !rotating {
			name = "convert"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.rotationPolicy(t, true, 30)
			raw, old := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
			head := f.storedRT(t, f.exchangeSuccessor(t, raw))
			f.rotationPolicy(t, rotating, 30)
			// Advance the family between the grant's preflight and its transaction.
			succ := *head
			succ.ID = "rt_" + secrets.RandomString(24)
			succ.TokenHash = secrets.HashToken(secrets.RandomString(48))
			f.h.Store = nativeBeforeTxStore{f.st, func() {
				if err := f.st.RefreshTokens().Rotate(t.Context(), old.TenantID, head.ID, &succ, fixedNow(), 30*time.Second); err != nil {
					t.Fatal(err)
				}
			}}
			f.requireInvalidRefresh(t, raw)
			got, err := f.st.RefreshTokens().Get(t.Context(), old.TenantID, succ.ID)
			if err != nil || got.RevokedAt == nil {
				t.Fatal("reuse did not commit the family revocation")
			}
		})
	}
}

func TestRefreshRotationPolicyAtCommit(t *testing.T) {
	f := newFixture(t)
	f.rotationPolicy(t, false, 0)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, "")
	f.h.Store = nativeBeforeTxStore{f.st, func() { f.rotationPolicy(t, true, 0) }}
	next := f.storedRT(t, f.exchangeSuccessor(t, raw))
	if !next.Rotating {
		t.Fatal("exchange used the client's previous rotation policy")
	}
}

// Exercise successor construction independently of the HTTP proof protocol.
func TestRefreshSuccessorBinding(t *testing.T) {
	for name, plan := range map[string]refreshPlan{"rotate": rotateRefresh, "enable": convertToRotating, "disable": convertToNonRotating} {
		t.Run(name, func(t *testing.T) {
			repo := memory.New().RefreshTokens()
			at := fixedNow()
			old := &store.RefreshToken{
				TenantID: "tenant", ID: secrets.RandomString(24), FamilyID: secrets.RandomString(32),
				TokenHash: secrets.HashToken(secrets.RandomString(48)), Rotating: plan != convertToRotating,
				Origin: "https://app.test", ClientID: "app", Audience: acmeAPI, Access: "offline",
				DPoPJKT: secrets.RandomString(32), UserID: "user", OrganizationID: "org",
				OrganizationConnectionID: "connection", SessionID: "session", AuthTime: at.Add(-time.Hour),
				Scopes: []string{"offline_access"}, Metadata: map[string]string{"label": "test"},
				Device: &store.RefreshTokenDevice{InitialUserAgent: "test client"}, LastExchangedAt: &at,
			}
			if err := repo.Create(t.Context(), old); err != nil {
				t.Fatal(err)
			}
			c := &store.Client{ClientID: old.ClientID, RefreshToken: store.RefreshTokenPolicy{Rotating: plan != convertToNonRotating}}
			raw, err := plan.exchange(t.Context(), repo, old, c, old.Origin, at.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			next, err := repo.GetByTokenHash(t.Context(), old.TenantID, secrets.HashToken(raw))
			if err != nil {
				t.Fatal(err)
			}
			if !old.ValidSuccessor(next) || !slices.Equal(next.Scopes, old.Scopes) || !next.AuthTime.Equal(old.AuthTime) ||
				!maps.Equal(next.Metadata, old.Metadata) || next.Device == nil || *next.Device != *old.Device ||
				next.LastExchangedAt == nil || !next.LastExchangedAt.Equal(at) {
				t.Fatal("successor lost a grant binding or exchange history")
			}
		})
	}
}

func TestRefreshSuppressedReuseAtMint(t *testing.T) {
	f := newActionsFixture(t)
	f.rotationPolicy(t, true, 30)
	raw, old := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, acmeAPI)
	head := f.storedRT(t, f.exchangeSuccessor(t, raw))
	f.actions.PostLogin(t, f.tid, "drop", `exports.onExecutePostLogin = async (event, api) => {
		api.accessToken.removeScope("offline_access");
	};`)
	succ := *head
	succ.ID = "rt_" + secrets.RandomString(24)
	succ.TokenHash = secrets.HashToken(secrets.RandomString(48))
	f.h.Store = nativeBeforeTxStore{f.st, func() {
		if err := f.st.RefreshTokens().Rotate(t.Context(), old.TenantID, head.ID, &succ, fixedNow(), 30*time.Second); err != nil {
			t.Fatal(err)
		}
	}}
	f.requireInvalidRefresh(t, raw)
	got, err := f.st.RefreshTokens().Get(t.Context(), old.TenantID, succ.ID)
	if err != nil || got.RevokedAt == nil {
		t.Fatal("suppressed refresh did not commit family revocation")
	}
}

func TestRefreshNonExpiringSourceAtMint(t *testing.T) {
	for _, change := range []string{"revoke", "delete"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			tid := f.tenantID(t, "acme")
			c, err := f.st.Clients().Get(t.Context(), tid, "rt-spa")
			if err != nil {
				t.Fatal(err)
			}
			c.RefreshToken = store.RefreshTokenPolicy{}
			if err := f.st.Clients().Update(t.Context(), c); err != nil {
				t.Fatal(err)
			}
			raw, old := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
			f.h.Store = nativeBeforeTxStore{f.st, func() {
				repo := f.st.RefreshTokens()
				if change == "revoke" {
					if err := repo.Revoke(t.Context(), tid, old.ID, fixedNow()); err != nil {
						t.Fatal(err)
					}
					return
				}
				next := *old
				next.Rotating = true
				next.ID = "rt_" + secrets.RandomString(24)
				next.TokenHash = secrets.HashToken(secrets.RandomString(48))
				next.FamilyID = "rtf_" + secrets.RandomString(32)
				if err := repo.ConvertNonRotating(t.Context(), tid, old.ID, &next); err != nil {
					t.Fatal(err)
				}
			}}
			f.requireInvalidRefresh(t, raw)
		})
	}
}

func TestRefreshClockAtMint(t *testing.T) {
	t.Run("conversion lifetime", func(t *testing.T) {
		f := newFixture(t)
		f.rotationPolicy(t, false, 0)
		raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
		f.rotationPolicy(t, true, 0)
		later := fixedNow().Add(2 * time.Minute)
		f.h.Store = nativeBeforeTxStore{f.st, func() { f.h.Now = func() time.Time { return later } }}
		next := f.storedRT(t, f.exchangeSuccessor(t, raw))
		if !next.CreatedAt.Equal(later) || !next.ExpiresAt.Equal(later.Add(DefaultRefreshTokenLifetime)) || !next.IdleExpiresAt.Equal(later.Add(DefaultRefreshTokenIdleLifetime)) {
			t.Fatal("successor lifetimes did not start at conversion")
		}
	})
	t.Run("retry at leeway deadline", func(t *testing.T) {
		f := newFixture(t)
		f.rotationPolicy(t, true, 30)
		raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
		head := f.exchangeSuccessor(t, raw)
		deadline := fixedNow().Add(30 * time.Second)
		f.h.Store = nativeBeforeTxStore{f.st, func() { f.h.Now = func() time.Time { return deadline } }}
		f.requireInvalidRefresh(t, raw)
		if got := f.storedRT(t, head); got.RevokedAt == nil || !got.RevokedAt.Equal(deadline) {
			t.Fatal("leeway deadline passed before mint without a family revocation")
		}
	})
	for _, expiry := range []string{"absolute", "idle"} {
		t.Run(expiry, func(t *testing.T) {
			f := newFixture(t)
			tid := f.tenantID(t, "acme")
			c, err := f.st.Clients().Get(t.Context(), tid, "rt-spa")
			if err != nil {
				t.Fatal(err)
			}
			c.RefreshToken.TokenLifetime, c.RefreshToken.IdleTokenLifetime = 10, 60
			if expiry == "idle" {
				c.RefreshToken.TokenLifetime, c.RefreshToken.IdleTokenLifetime = 60, 10
			}
			if err := f.st.Clients().Update(t.Context(), c); err != nil {
				t.Fatal(err)
			}
			raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
			f.h.Store = nativeBeforeTxStore{f.st, func() { f.h.Now = func() time.Time { return fixedNow().Add(10 * time.Second) } }}
			f.requireInvalidRefresh(t, raw)
			if got := f.storedRT(t, raw); got.RotatedAt != nil || got.RevokedAt != nil {
				t.Fatal("expired source was consumed")
			}
		})
	}
}
