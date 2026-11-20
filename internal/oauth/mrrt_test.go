package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const billingAPI = "https://billing.acme.test"

func (f *fixture) mrrtClient(t *testing.T, policies ...store.MRRTPolicy) *store.Client {
	t.Helper()
	c, err := f.st.Clients().Get(t.Context(), f.tenantID(t, "acme"), "rt-spa")
	if err != nil {
		t.Fatal(err)
	}
	c.RefreshToken.Policies = policies
	if err := f.st.Clients().Update(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMRRTNoAudience(t *testing.T) {
	for _, audience := range []string{"", acmeAPI} {
		for _, consent := range []bool{false, true} {
			f := newFixture(t)
			c := f.mrrtClient(t, store.MRRTPolicy{Audience: acmeAPI, Scope: []string{"write:things", "unknown"}})
			rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), c.TenantID, acmeAPI)
			rs.SkipConsentForVerifiableFirstPartyClients = !consent
			if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
				t.Fatal(err)
			}
			raw, _ := f.issueRefresh(t, c.ClientID, []string{"openid", "offline_access", "read:things"}, acmeAPI)
			code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", audience, "scope", "read:things unrecognized"))
			want := "read:things write:things"
			if consent {
				want = "read:things"
			}
			if code != 200 || body["scope"] != want || body["id_token"] == nil {
				t.Fatalf("own audience %q consent %v: status=%d scope=%v id_token present=%v", audience, consent, code, body["scope"], body["id_token"] != nil)
			}
		}
	}
}

func TestMRRTOtherAudience(t *testing.T) {
	f := newFixture(t)
	c := f.mrrtClient(t, store.MRRTPolicy{Audience: billingAPI, Scope: []string{"read:invoices", "write:invoices", "undefined", "openid"}})
	rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), c.TenantID, billingAPI)
	secret := secrets.RandomString(40)
	var err error
	rs.SigningAlg = "HS256"
	rs.SigningSecretSealed, err = keys.SealAPISigningSecret(f.wrapper, c.TenantID, rs.ID, secret)
	if err != nil {
		t.Fatal(err)
	}
	rs.TokenLifetime = 143
	rs.EnforcePolicies = true
	rs.Scopes = append(rs.Scopes, store.Scope{Value: "write:invoices"}, store.Scope{Value: "pay:invoices"})
	if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", "openid read:invoices write:invoices pay:invoices undefined"} {
		raw, rt := f.issueRefresh(t, c.ClientID, []string{"openid", "email", "offline_access", "read:things"}, acmeAPI)
		if err := f.st.RBAC().ChangeUserPermissions(t.Context(), c.TenantID, rt.UserID, true, []store.PermissionKey{{ResourceServerIdentifier: billingAPI, PermissionName: "read:invoices"}, {ResourceServerIdentifier: billingAPI, PermissionName: "pay:invoices"}}); err != nil {
			t.Fatal(err)
		}
		code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", billingAPI, "scope", scope))
		wantScope := "read:invoices"
		if scope != "" {
			wantScope += " openid"
		}
		if code != 200 || body["scope"] != wantScope || body["expires_in"] != float64(143) || body["id_token"] == nil {
			t.Fatalf("status=%d scope=%v expires_in=%v id_token present=%v", code, body["scope"], body["expires_in"], body["id_token"] != nil)
		}
		idt, _ := verifyToken(t, f.keys, c.TenantID, body["id_token"].(string))
		if idt["email"] != "alice@acme.test" || idt["aud"] != c.ClientID || idt["at_hash"] == nil {
			t.Fatal("ID token did not use the family’s identity scopes and client")
		}
		at, _ := hs256Claims(t, body["access_token"].(string), secret)
		if at["aud"] != billingAPI || at["scope"] != "read:invoices" {
			t.Fatalf("aud=%v scope=%v", at["aud"], at["scope"])
		}
	}
}

func TestMRRTRequestedCredentialScopes(t *testing.T) {
	f := newFixture(t)
	c := f.mrrtClient(t, store.MRRTPolicy{Audience: billingAPI, Scope: []string{"read:invoices"}})
	for _, tc := range []struct {
		name     string
		family   []string
		response string
	}{
		{"id and continued offline grant", []string{"openid", "offline_access"}, "read:invoices openid offline_access"},
		{"no identity grant", []string{"offline_access"}, "read:invoices offline_access"},
		{"no offline grant in historic scopes", []string{"openid"}, "read:invoices openid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := f.issueRefresh(t, c.ClientID, tc.family, acmeAPI)
			code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", billingAPI, "scope", "openid offline_access online_access read:invoices"))
			if code != 200 || body["scope"] != tc.response {
				t.Fatalf("status=%d response scope=%v", code, body["scope"])
			}
			claims, _ := verifyToken(t, f.keys, c.TenantID, body["access_token"].(string))
			if claims["aud"] != billingAPI || claims["scope"] != "read:invoices" {
				t.Fatal("second API access token exceeded its policy")
			}
		})
	}
}

func TestMRRTRefusals(t *testing.T) {
	for _, why := range []string{"unlisted", "skip consent disabled", "deleted API", "third party", "Management API", "operator API", "legacy", "lost support", "source offline disabled"} {
		t.Run(why, func(t *testing.T) {
			f := newFixture(t)
			target := billingAPI
			switch why {
			case "Management API":
				target = "https://acme.example.test/api/v2/"
			case "operator API":
				target = tenant.OperatorAudience
			}
			c := f.mrrtClient(t, store.MRRTPolicy{Audience: target, Scope: []string{"read:invoices"}})
			raw, rt := f.issueRefresh(t, c.ClientID, []string{"offline_access"}, acmeAPI)
			wantCode, wantErr := 400, "invalid_request"
			switch why {
			case "unlisted":
				target = "urn:elsewhere"
			case "third party":
				c.IsFirstParty = false
				if err := f.st.Clients().Update(t.Context(), c); err != nil {
					t.Fatal(err)
				}
			case "skip consent disabled", "deleted API", "source offline disabled":
				id := target
				if why == "source offline disabled" {
					id = acmeAPI
					wantErr = "invalid_grant"
				}
				rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), rt.TenantID, id)
				var err error
				if why == "deleted API" {
					err = f.st.ResourceServers().Delete(t.Context(), rt.TenantID, rs.ID)
				} else {
					rs.SkipConsentForVerifiableFirstPartyClients = false
					rs.AllowOfflineAccess = false
					err = f.st.ResourceServers().Update(t.Context(), rs)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "legacy":
				f.h.Store = refreshProbeStore{Store: f.st, err: store.ErrRefreshTokensIIUnavailable}
			case "lost support":
				f.h.Store = refreshProbeStore{Store: f.st, err: store.ErrRefreshTokensIISupportLost}
				wantCode, wantErr = 500, "server_error"
			}
			code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", target))
			if code != wantCode || body["error"] != wantErr || f.storedRT(t, raw).RotatedAt != nil {
				t.Fatalf("status=%d error=%v", code, body["error"])
			}
		})
	}
}

func TestMRRTFamilyUnchanged(t *testing.T) {
	f := newFixture(t)
	c := f.mrrtClient(t, store.MRRTPolicy{Audience: billingAPI, Scope: []string{"read:invoices"}})
	f.rotationPolicy(t, false, 0)
	raw, before := f.issueRefresh(t, c.ClientID, []string{"offline_access", "read:things"}, acmeAPI)
	code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", billingAPI))
	if code != 200 || body["scope"] != "read:invoices" || body["id_token"] != nil {
		t.Fatalf("status=%d scope=%v", code, body["scope"])
	}
	after := f.storedRT(t, raw)
	if !slices.Equal(before.Scopes, after.Scopes) || after.Audience != before.Audience {
		t.Fatal("MRRT changed the stored family")
	}
	code, body = f.refresh(t, refreshForm(c.ClientID, raw))
	if code != 200 || body["scope"] != "offline_access read:things" {
		t.Fatalf("plain refresh status=%d scope=%v", code, body["scope"])
	}
}

func TestMRRTRotation(t *testing.T) {
	for _, conversion := range []bool{false, true} {
		f := newFixture(t)
		c := f.mrrtClient(t, store.MRRTPolicy{Audience: billingAPI, Scope: []string{"read:invoices"}})
		if conversion {
			f.rotationPolicy(t, false, 0)
		}
		raw, before := f.issueRefresh(t, c.ClientID, []string{"offline_access", "read:things"}, acmeAPI)
		if conversion {
			f.rotationPolicy(t, true, 0)
		}
		code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", billingAPI))
		next, _ := body["refresh_token"].(string)
		if code != 200 || next == "" {
			t.Fatalf("status=%d successor present=%v", code, next != "")
		}
		after := f.storedRT(t, next)
		if after.Audience != before.Audience || !slices.Equal(after.Scopes, before.Scopes) {
			t.Fatal("successor changed authorization")
		}
	}
}

func TestMRRTActionEvent(t *testing.T) {
	f := newActionsFixture(t)
	c := f.mrrtClient(t, store.MRRTPolicy{Audience: billingAPI, Scope: []string{"read:invoices"}})
	f.actions.PostLogin(t, f.tid, "policies", `exports.onExecutePostLogin = async (event, api) => {
		const policy = event.client.refresh_token.policies[0];
		api.accessToken.setCustomClaim("target", event.resource_server.identifier);
		api.accessToken.setCustomClaim("policy", policy.audience + " " + policy.scope[0]);
		api.transaction.addTargetScope("write:things");
		api.accessToken.addScope("write:things");
	};`)
	raw, _ := f.issueRefresh(t, c.ClientID, []string{"offline_access", "read:things"}, acmeAPI)
	code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", billingAPI))
	if code != 200 || body["scope"] != "read:invoices" {
		t.Fatalf("status=%d scope=%v", code, body["scope"])
	}
	at, _ := verifyToken(t, f.keys, c.TenantID, body["access_token"].(string))
	if at["target"] != billingAPI || at["policy"] != billingAPI+" read:invoices" {
		t.Fatal("wrong target API or policies in event")
	}
}

func TestMRRTPolicyAtMint(t *testing.T) {
	for _, change := range []string{"remove policy", "remove scope", "require consent", "delete target", "disable source offline"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			c := f.mrrtClient(t, store.MRRTPolicy{Audience: billingAPI, Scope: []string{"read:invoices"}})
			raw, _ := f.issueRefresh(t, c.ClientID, []string{"offline_access"}, acmeAPI)
			f.h.Store = nativeBeforeTxStore{f.st, func() {
				switch change {
				case "remove policy":
					f.mrrtClient(t)
				case "remove scope":
					f.mrrtClient(t, store.MRRTPolicy{Audience: billingAPI, Scope: []string{}})
				default:
					id := billingAPI
					if change == "disable source offline" {
						id = acmeAPI
					}
					rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), c.TenantID, id)
					var err error
					if change == "delete target" {
						err = f.st.ResourceServers().Delete(t.Context(), c.TenantID, rs.ID)
					} else {
						rs.SkipConsentForVerifiableFirstPartyClients = false
						rs.AllowOfflineAccess = false
						err = f.st.ResourceServers().Update(t.Context(), rs)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}}
			want := "invalid_request"
			if change == "disable source offline" {
				want = "invalid_grant"
			}
			code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", billingAPI))
			if code != 400 || body["error"] != want || f.storedRT(t, raw).RotatedAt != nil {
				t.Fatalf("status=%d error=%v", code, body["error"])
			}
		})
	}
}

// With all requested scopes removed, an OAuth client must be told that its
// request was narrowed, including when the issued scope set is empty.
func TestMRRTEmptyScope(t *testing.T) {
	f := newFixture(t)
	c := f.mrrtClient(t, store.MRRTPolicy{Audience: billingAPI, Scope: []string{"read:invoices"}})
	raw, _ := f.issueRefresh(t, c.ClientID, []string{"offline_access"}, acmeAPI)
	code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", billingAPI, "scope", "pay:invoices"))
	if code != 200 || body["scope"] != "" {
		t.Fatalf("status=%d scope=%v", code, body["scope"])
	}
}

func TestMRRTAuthorizationAtMint(t *testing.T) {
	for _, change := range []string{"RBAC permission revoked", "grant type disabled", "consent revoked"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			target, declared := billingAPI, "read:invoices"
			if change == "consent revoked" {
				target, declared = acmeAPI, "write:things"
			}
			c := f.mrrtClient(t, store.MRRTPolicy{Audience: target, Scope: []string{declared}})
			raw, rt := f.issueRefresh(t, c.ClientID, []string{"offline_access"}, acmeAPI)
			rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), c.TenantID, target)
			permission := []store.PermissionKey{{ResourceServerIdentifier: target, PermissionName: declared}}
			g := &store.UserGrant{ID: "mrrt-consent", TenantID: c.TenantID, ClientID: c.ClientID, UserID: rt.UserID, Audience: target, Scopes: []string{declared}}
			if change == "consent revoked" {
				rs.SkipConsentForVerifiableFirstPartyClients = false
				if _, err := f.st.UserGrants().Upsert(t.Context(), g); err != nil {
					t.Fatal(err)
				}
			}
			if change == "RBAC permission revoked" {
				rs.EnforcePolicies = true
				if err := f.st.RBAC().ChangeUserPermissions(t.Context(), c.TenantID, rt.UserID, true, permission); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
				t.Fatal(err)
			}
			f.h.Store = nativeBeforeTxStore{f.st, func() {
				var err error
				switch change {
				case "RBAC permission revoked":
					err = f.st.RBAC().ChangeUserPermissions(t.Context(), c.TenantID, rt.UserID, false, permission)
				case "grant type disabled":
					c.GrantTypes = []string{"authorization_code"}
					err = f.st.Clients().Update(t.Context(), c)
				case "consent revoked":
					err = f.st.UserGrants().Delete(t.Context(), c.TenantID, g.ID)
				}
				if err != nil {
					t.Fatal(err)
				}
			}}
			code, body := f.refresh(t, refreshForm(c.ClientID, raw, "audience", target))
			if code != 400 || body["error"] != "invalid_request" || f.storedRT(t, raw).RotatedAt != nil {
				t.Fatalf("status=%d error=%v", code, body["error"])
			}
		})
	}
}

func TestMRRTFirstPolicyAtMint(t *testing.T) {
	f := newActionsFixture(t)
	f.actions.PostLogin(t, f.tid, "add permission", `exports.onExecutePostLogin = async (_, api) => api.accessToken.addScope("write:things");`)
	raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access", "read:things"}, acmeAPI)
	f.h.Store = nativeBeforeTxStore{f.st, func() {
		f.mrrtClient(t, store.MRRTPolicy{Audience: acmeAPI, Scope: []string{"read:things"}})
	}}
	status, body := f.refresh(t, refreshForm("rt-spa", raw))
	if status != 400 || body["error"] != "invalid_request" || body["access_token"] != nil || body["refresh_token"] != nil {
		t.Fatalf("first policy at mint: status=%d error=%v scope=%v", status, body["error"], body["scope"])
	}
	if got := f.storedRT(t, raw); got.RotatedAt != nil || got.RevokedAt != nil {
		t.Fatal("first policy activation consumed the family")
	}
	f.h.Store = f.st
	status, body = f.refresh(t, refreshForm("rt-spa", raw))
	if status != 200 || body["scope"] != "offline_access read:things" {
		t.Fatalf("retry with policy: status=%d scope=%v", status, body["scope"])
	}
}

func TestMRRTDeletionBeforeSigning(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		frozen, plain, deleteUser bool
	}{
		{name: "target during snapshot"}, {name: "target after Action snapshot", frozen: true},
		{name: "user during snapshot", deleteUser: true}, {name: "original API in plain refresh", plain: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newActionsFixture(t)
			target := billingAPI
			if tc.plain {
				target = acmeAPI
			} else {
				f.mrrtClient(t, store.MRRTPolicy{Audience: target, Scope: []string{"read:invoices"}})
			}
			rs, err := f.st.ResourceServers().GetByIdentifier(t.Context(), f.tid, target)
			if err != nil {
				t.Fatal(err)
			}
			raw, rt := f.issueRefresh(t, "rt-spa", []string{"offline_access", "read:things"}, acmeAPI)
			if tc.frozen {
				rs.EnforcePolicies = true
				if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
					t.Fatal(err)
				}
				relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := f.st.ResourceServers().Delete(r.Context(), f.tid, rs.ID); err != nil {
						http.Error(w, "delete target", 500)
						return
					}
					w.WriteHeader(204)
				}))
				defer relay.Close()
				f.actions.PostLogin(t, f.tid, "remove target", fmt.Sprintf(`exports.onExecutePostLogin = async (event) => {
					if (event.resource_server.identifier === %q && !(await fetch(%q)).ok) throw Error("delete target");
				};`, target, relay.URL))
			} else {
				f.h.Store = changingRBACStore{f.st, func() {
					var err error
					if tc.deleteUser {
						err = f.st.Users().Delete(t.Context(), f.tid, rt.UserID)
					} else {
						err = f.st.ResourceServers().Delete(t.Context(), f.tid, rs.ID)
					}
					if err != nil {
						t.Fatal(err)
					}
				}}
			}
			status, body := f.refresh(t, refreshForm("rt-spa", raw, "audience", target))
			if tc.plain || tc.deleteUser {
				if status != 400 || body["error"] != "invalid_grant" {
					t.Fatalf("status=%d error=%v", status, body["error"])
				}
				return
			}
			if status != 400 || body["error"] != "invalid_request" || body["error_description"] != disallowedMRRTAudience {
				t.Fatalf("status=%d error=%v description=%v", status, body["error"], body["error_description"])
			}
			f.h.Store = f.st
			if status, body := f.refresh(t, refreshForm("rt-spa", raw)); status != 200 || body["scope"] != "offline_access read:things" {
				t.Fatalf("original audience after deletion: status=%d scope=%v", status, body["scope"])
			}
		})
	}
}
