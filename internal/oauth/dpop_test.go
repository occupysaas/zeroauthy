package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/authz"
	"github.com/zeroauthy/zeroauthy/internal/dpop"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func dpopKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func dpopJWT(t *testing.T, k *ecdsa.PrivateKey, path, nonce string) string {
	t.Helper()
	s, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k}, (&jose.SignerOptions{}).WithType("dpop+jwt").WithHeader("jwk", jose.JSONWebKey{Key: &k.PublicKey}))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(map[string]any{"htm": "POST", "htu": "https://acme.example.test" + path, "iat": fixedNow().Unix(), "jti": secrets.RandomString(24), "nonce": nonce})
	v, e := s.Sign(b)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := v.CompactSerialize()
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestDPoPCodeAndRefresh(t *testing.T) {
	f := newFixture(t)
	f.h.DPoP = &dpop.Service{Store: f.st, Wrapper: f.wrapper, Now: fixedNow}
	k := dpopKey(t)
	code := f.issueCode(t, "rt-spa", "https://app.acme.test/cb", acmeAPI, []string{"openid", "offline_access", "read:things"}, pkceChallenge)
	form := codeForm(code, "rt-spa", "https://app.acme.test/cb", pkceVerifier)
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": dpopJWT(t, k, "/oauth/token", "")}})
	if rec.Code != 400 || body["error"] != "use_dpop_nonce" {
		t.Fatalf("challenge status %d", rec.Code)
	}
	ac, e := f.st.AuthCodes().Get(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(code))
	if e != nil || ac.UsedAt != nil {
		t.Fatal("challenge consumed code")
	}
	nonce := rec.Header().Get("DPoP-Nonce")
	rec, body = f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": dpopJWT(t, k, "/oauth/token", nonce)}})
	if rec.Code != 200 {
		t.Fatalf("issue %d %v", rec.Code, body["error"])
	}
	rt := f.storedRT(t, body["refresh_token"].(string))
	if rt.DPoPJKT == "" {
		t.Fatal("refresh not bound")
	}
	ac, e = f.st.AuthCodes().Get(context.Background(), rt.TenantID, secrets.HashToken(code))
	if e != nil || ac.DPoPJKT != rt.DPoPJKT {
		t.Fatal("redeemed authorization code did not retain its issued credential's key")
	}
	if body["token_type"] != "Bearer" {
		t.Fatal("unconfigured API access bound")
	}
	raw := body["refresh_token"].(string)
	rec, _ = f.call(t, false, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw)})
	if rec.Code != 400 {
		t.Fatal("missing proof accepted")
	}
	current := f.storedRT(t, raw)
	if current.RotatedAt != nil || current.RevokedAt != nil {
		t.Fatal("missing proof mutated family")
	}
	rec, body = f.call(t, false, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw), header: map[string]string{"DPoP": dpopJWT(t, k, "/oauth/token", nonce)}})
	if rec.Code != 200 {
		t.Fatalf("refresh %d %v", rec.Code, body["error"])
	}
	next := f.storedRT(t, body["refresh_token"].(string))
	if next.DPoPJKT != rt.DPoPJKT {
		t.Fatal("binding lost")
	}
}
func TestCodeClaimSerializesProofBinding(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	tn, err := f.st.Tenants().Get(ctx, tid)
	if err != nil {
		t.Fatal(err)
	}
	res := tenant.Resolved{Tenant: tn, Host: acmeHost}
	const hash = "synthetic-code-row"
	if err := f.st.AuthCodes().Create(ctx, &store.AuthCode{TenantID: tid, CodeHash: hash, ClientID: "spa"}); err != nil {
		t.Fatal(err)
	}
	type claim struct {
		key string
		err error
	}
	start, done := make(chan struct{}), make(chan claim, 2)
	for _, key := range []string{"first", "second"} {
		go func() {
			<-start
			_, err := f.h.claimAuthorizationCode(dpop.WithProof(ctx, &dpop.Proof{JKT: key}), res, "spa", hash, fixedNow())
			done <- claim{key, err}
		}()
	}
	close(start)
	var winner string
	for range 2 {
		result := <-done
		if result.err == nil {
			if winner != "" {
				t.Fatal("multiple winning claims")
			}
			winner = result.key
		} else if failure, ok := result.err.(*Error); !ok || failure.Code != "invalid_dpop_proof" {
			t.Fatal("unexpected competing claim result")
		}
	}
	_, err = f.h.claimAuthorizationCode(ctx, res, "spa", hash, fixedNow())
	if failure, ok := err.(*Error); !ok || failure.Code != "invalid_dpop_proof" {
		t.Fatal("claim without the winning key was accepted")
	}
	code, err := f.st.AuthCodes().Get(ctx, tid, hash)
	if err != nil || winner == "" || code.DPoPJKT != winner || code.ReplayedAt != nil {
		t.Fatal("competing claims changed the winning binding or replay marker")
	}
}

func TestDPoPPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                                    string
		pop                                     *store.ProofOfPossession
		required, proof, public, bound, refused bool
	}{
		{"userinfo", nil, false, true, true, true, false}, {"API allowed", &store.ProofOfPossession{Mechanism: "dpop"}, false, true, true, true, false}, {"API bearer", &store.ProofOfPossession{Mechanism: "dpop"}, false, false, true, false, false}, {"required", &store.ProofOfPossession{Mechanism: "dpop", Required: true}, false, false, true, false, true}, {"public only", &store.ProofOfPossession{Mechanism: "dpop", Required: true, RequiredFor: "public_clients"}, false, false, false, false, false}, {"client requires", nil, true, false, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &store.Client{RequireProofOfPossession: tc.required, TokenEndpointAuthMethod: store.AuthMethodClientSecretBasic}
			if tc.public {
				c.TokenEndpointAuthMethod = store.AuthMethodNone
			}
			var rs *store.ResourceServer
			if tc.name != "userinfo" {
				rs = &store.ResourceServer{ProofOfPossession: tc.pop}
			}
			ctx := context.Background()
			if tc.proof {
				ctx = dpop.WithProof(ctx, &dpop.Proof{JKT: "key"})
			}
			jkt, e := accessProof(ctx, c, rs)
			if (jkt != "") != tc.bound || (e != nil) != tc.refused {
				t.Fatalf("bound=%v error=%v", jkt != "", e)
			}
		})
	}
}

func TestDPoPPARBinding(t *testing.T) {
	for _, mode := range []string{"parameter", "header", "matching", "mismatch", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			k := dpopKey(t)
			jwk := jose.JSONWebKey{Key: &k.PublicKey}
			thumb, _ := jwk.Thumbprint(crypto.SHA256)
			jkt := base64.RawURLEncoding.EncodeToString(thumb)
			form := parForm()
			if mode != "header" {
				form.Set("dpop_jkt", jkt)
			}
			if mode == "mismatch" {
				form.Set("dpop_jkt", strings.Repeat("b", 43))
			}
			r := httptest.NewRequest("POST", "https://acme.example.test/oauth/par", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", formType)
			if mode != "parameter" {
				r.Header.Set("DPoP", dpopJWT(t, k, "/oauth/par", ""))
			}
			if mode == "invalid" {
				r.Header.Set("DPoP", "invalid")
			}
			rec := httptest.NewRecorder()
			tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthPar)).ServeHTTP(rec, r)
			if mode == "mismatch" || mode == "invalid" {
				if rec.Code != 400 {
					t.Fatalf("status %d", rec.Code)
				}
				return
			}
			if rec.Code != 201 {
				t.Fatalf("status %d", rec.Code)
			}
			var out map[string]any
			json.Unmarshal(rec.Body.Bytes(), &out)
			id := strings.TrimPrefix(out["request_uri"].(string), authz.RequestURIPrefix)
			p, e := f.st.PushedAuthRequests().Consume(context.Background(), f.tenantID(t, "acme"), secrets.HashToken(id), fixedNow())
			if e != nil || p.Params["dpop_jkt"] != jkt {
				t.Fatal("binding lost")
			}
		})
	}
}

func TestDPoPAccessPolicyAndWrongKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid := f.tenantID(t, "acme")
	rs, _ := f.st.ResourceServers().GetByIdentifier(ctx, tid, acmeAPI)
	rs.ProofOfPossession = &store.ProofOfPossession{Mechanism: "dpop"}
	if e := f.st.ResourceServers().Update(ctx, rs); e != nil {
		t.Fatal(e)
	}
	k := dpopKey(t)
	code := f.issueCode(t, "rt-spa", "https://app.acme.test/cb", acmeAPI, []string{"openid", "offline_access", "read:things"}, pkceChallenge)
	form := codeForm(code, "rt-spa", "https://app.acme.test/cb", pkceVerifier)
	rec, _ := f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": dpopJWT(t, k, "/oauth/token", "")}})
	nonce := rec.Header().Get("DPoP-Nonce")
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": dpopJWT(t, k, "/oauth/token", nonce)}})
	if rec.Code != 200 || body["token_type"] != "DPoP" {
		t.Fatalf("bound %d", rec.Code)
	}
	at, _ := verifyToken(t, f.keys, tid, body["access_token"].(string))
	rt := f.storedRT(t, body["refresh_token"].(string))
	if at["cnf"].(map[string]any)["jkt"] != rt.DPoPJKT {
		t.Fatal("cnf differs")
	}
	wrong := dpopKey(t)
	rec, _ = f.call(t, false, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", body["refresh_token"].(string)), header: map[string]string{"DPoP": dpopJWT(t, wrong, "/oauth/token", nonce)}})
	if rec.Code != 400 {
		t.Fatal("wrong key accepted")
	}
	if current := f.storedRT(t, body["refresh_token"].(string)); current.RotatedAt != nil || current.RevokedAt != nil {
		t.Fatal("wrong key changed family")
	}
}

func TestDPoPPolicyAtMint(t *testing.T) {
	f := newFixture(t)
	raw, rt := f.issueRefresh(t, "rt-spa", []string{"openid", "offline_access"}, acmeAPI)
	f.h.Store = nativeBeforeTxStore{f.st, func() {
		rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), rt.TenantID, acmeAPI)
		rs.ProofOfPossession = &store.ProofOfPossession{Mechanism: "dpop", Required: true}
		if e := f.st.ResourceServers().Update(t.Context(), rs); e != nil {
			t.Fatal(e)
		}
	}}
	code, _ := f.refresh(t, refreshForm("rt-spa", raw))
	if code == 200 {
		t.Fatal("policy changed during signing but minted")
	}
	if got := f.storedRT(t, raw); got.RotatedAt != nil || got.RevokedAt != nil {
		t.Fatal("policy refusal consumed family")
	}
}

func TestDPoPCodeBindingBeforeConsume(t *testing.T) {
	f := newFixture(t)
	key := dpopKey(t)
	jwk := jose.JSONWebKey{Key: &key.PublicKey}
	thumb, _ := jwk.Thumbprint(crypto.SHA256)
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	code := f.issueCode(t, "rt-spa", "https://app.acme.test/cb", acmeAPI, []string{"openid", "offline_access"}, pkceChallenge)
	ac, _ := f.st.AuthCodes().Get(t.Context(), f.tenantID(t, "acme"), secrets.HashToken(code))
	f2 := newFixture(t) // use a separate generated record so immutable code storage is honored
	ac.TenantID = f2.tenantID(t, "acme")
	ac.DPoPJKT = jkt
	ac.CodeHash = secrets.HashToken("binding-" + code)
	if e := f2.st.AuthCodes().Create(t.Context(), ac); e != nil {
		t.Fatal(e)
	}
	form := codeForm("binding-"+code, "rt-spa", "https://app.acme.test/cb", pkceVerifier)
	for _, header := range []map[string]string{nil, {"DPoP": dpopJWT(t, dpopKey(t), "/oauth/token", "")}} {
		rec, _ := f2.call(t, false, tokenCall{host: "acme.example.test", form: form, header: header})
		if rec.Code != 400 {
			t.Fatalf("wrong/missing proof %d", rec.Code)
		}
		got, _ := f2.st.AuthCodes().Get(t.Context(), ac.TenantID, ac.CodeHash)
		if got.UsedAt != nil || got.ReplayedAt != nil {
			t.Fatal("proof failure consumed code")
		}
	}
}
func TestDPoPUnboundAndLegacyRefresh(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(strconv.FormatBool(strict), func(t *testing.T) {
			f := newFixture(t)
			tn, _ := f.st.Tenants().Get(t.Context(), f.tenantID(t, "acme"))
			tn.SettingsExtra["dpop_strict_refresh_token_binding"] = strict
			f.st.Tenants().Update(t.Context(), tn)
			raw, _ := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
			key := dpopKey(t)
			call := tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw), header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", "")}}
			rec, _ := f.call(t, false, call)
			nonce := rec.Header().Get("DPoP-Nonce")
			call.header["DPoP"] = dpopJWT(t, key, "/oauth/token", nonce)
			rec, body := f.call(t, false, call)
			if rec.Code != 200 {
				t.Fatalf("status %d", rec.Code)
			}
			next := f.storedRT(t, body["refresh_token"].(string))
			if next.DPoPJKT != "" {
				t.Fatal("unbound refresh silently upgraded")
			}
		})
	}
}

func TestInitialRefreshBindingAtMint(t *testing.T) {
	for _, tc := range []struct {
		name      string
		before    bool
		current   any
		wantBound bool
	}{
		{"enabled", false, true, true},
		{"explicit per-API", true, false, false},
		{"upgraded tenant with absent setting", false, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			ctx, tid := t.Context(), f.tenantID(t, "acme")
			prior, err := f.st.Tenants().Get(ctx, tid)
			if err != nil {
				t.Fatal(err)
			}
			prior.SettingsExtra["dpop_strict_refresh_token_binding"] = tc.before
			current, err := f.st.Tenants().Get(ctx, tid)
			if err != nil {
				t.Fatal(err)
			}
			delete(current.SettingsExtra, "dpop_strict_refresh_token_binding")
			if tc.current != nil {
				current.SettingsExtra["dpop_strict_refresh_token_binding"] = tc.current
			}
			if err := f.st.Tenants().Update(ctx, current); err != nil {
				t.Fatal(err)
			}
			c, err := f.st.Clients().Get(ctx, tid, "rt-spa")
			if err != nil {
				t.Fatal(err)
			}
			const redirect = "https://rt.acme.test/cb"
			raw := f.issueCode(t, c.ClientID, redirect, acmeAPI, []string{"offline_access"}, pkceChallenge)
			const key = "verified-presentation"
			ctx = dpop.WithProof(ctx, &dpop.Proof{JKT: key})
			resp, failure := f.h.authorizationCode(ctx, tenant.Resolved{Tenant: prior, Host: acmeHost}, c, codeForm(raw, c.ClientID, redirect, pkceVerifier))
			if failure != nil || resp.RefreshToken == nil || resp.TokenType != "Bearer" {
				t.Fatal("bearer API issuance failed")
			}
			rt := f.storedRT(t, *resp.RefreshToken)
			ac, err := f.st.AuthCodes().Get(ctx, tid, secrets.HashToken(raw))
			if err != nil || (rt.DPoPJKT == key) != tc.wantBound || ac.DPoPJKT != rt.DPoPJKT {
				t.Fatal("new credential binding differs from the committed tenant policy")
			}
		})
	}
}

func TestDPoPBoundRevocation(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(strconv.FormatBool(expired), func(t *testing.T) {
			f := newFixture(t)
			key := dpopKey(t)
			jwk := jose.JSONWebKey{Key: &key.PublicKey}
			thumb, _ := jwk.Thumbprint(crypto.SHA256)
			_, source := f.issueRefresh(t, "rt-spa", []string{"offline_access"}, acmeAPI)
			raw := secrets.RandomString(48)
			source.ID = "rt_" + secrets.RandomString(24)
			source.TokenHash = secrets.HashToken(raw)
			source.FamilyID = "rtf_" + secrets.RandomString(24)
			source.DPoPJKT = base64.RawURLEncoding.EncodeToString(thumb)
			if expired {
				source.IdleExpiresAt = fixedNow()
			}
			if e := f.st.RefreshTokens().Create(t.Context(), source); e != nil {
				t.Fatal(e)
			}
			f.revokeGrantFlag(t, source.TenantID, true)
			_, e := f.st.UserGrants().Upsert(t.Context(), &store.UserGrant{TenantID: source.TenantID, ID: "g-proof", ClientID: source.ClientID, UserID: source.UserID, Audience: acmeAPI})
			if e != nil {
				t.Fatal(e)
			}
			u, _ := f.st.Users().Get(t.Context(), source.TenantID, source.UserID)
			call := func(proof string) *httptest.ResponseRecorder {
				form := url.Values{"client_id": {"rt-spa"}, "token": {raw}}
				r := httptest.NewRequest("POST", "https://acme.example.test/oauth/revoke", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", formType)
				if proof != "" {
					r.Header.Set("DPoP", proof)
				}
				rec := httptest.NewRecorder()
				tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthRevoke)).ServeHTTP(rec, r)
				return rec
			}
			for _, value := range []string{"", dpopJWT(t, dpopKey(t), "/oauth/revoke", "")} {
				rec := call(value)
				if rec.Code != 400 {
					t.Fatalf("proof refusal status %d", rec.Code)
				}
				current := f.storedRT(t, raw)
				if current.RevokedAt != nil {
					t.Fatal("missing/wrong proof revoked family")
				}
				if _, e := f.st.UserGrants().Find(t.Context(), source.TenantID, source.ClientID, source.UserID, acmeAPI); e != nil {
					t.Fatal("missing/wrong proof deleted grant")
				}
				after, _ := f.st.Users().Get(t.Context(), source.TenantID, source.UserID)
				if after.Version != u.Version {
					t.Fatal("missing/wrong proof changed version")
				}
			}
			rec := call(dpopJWT(t, key, "/oauth/revoke", ""))
			if rec.Code != 400 || rec.Header().Get("DPoP-Nonce") == "" {
				t.Fatal("revocation nonce missing")
			}
			rec = call(dpopJWT(t, key, "/oauth/revoke", rec.Header().Get("DPoP-Nonce")))
			if rec.Code != 200 {
				t.Fatalf("valid revoke %d", rec.Code)
			}
			if got := f.storedRT(t, raw); got.RevokedAt == nil {
				t.Fatal("valid proof did not revoke")
			}

			if expired {
				if _, e := f.st.UserGrants().Find(t.Context(), source.TenantID, source.ClientID, source.UserID, acmeAPI); e != nil {
					t.Fatal("expired bound token removed consent")
				}
				after, _ := f.st.Users().Get(t.Context(), source.TenantID, source.UserID)
				if after.Version != u.Version {
					t.Fatal("expired bound token changed version")
				}
			}
		})
	}
}

func TestDPoPDefaultAudienceBeforeGrant(t *testing.T) {
	f := newFixture(t)
	tid := f.tenantID(t, "acme")
	rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), tid, acmeAPI)
	rs.ProofOfPossession = &store.ProofOfPossession{Mechanism: "dpop", Required: true}
	f.st.ResourceServers().Update(t.Context(), rs)
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: pw("ropg", "ropg-secret", "alice@acme.test", "incorrect password")})
	if rec.Code != 400 || body["error"] != "invalid_dpop_proof" {
		t.Fatalf("required proof did not precede password grant: %d %v", rec.Code, body["error"])
	}
}

func TestDPoPDeviceStoredAudienceBeforePoll(t *testing.T) {
	for i, tc := range []struct{ defaultAudience, requestAudience string }{
		{"", ""}, {"", "https://different-api.example.test"},
		{"https://different-api.example.test", ""}, {"https://different-api.example.test", "https://different-api.example.test"},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			f := newFixture(t)
			tid := f.tenantID(t, "acme")
			tn, _ := f.st.Tenants().Get(t.Context(), tid)
			tn.DefaultAudience = tc.defaultAudience
			if err := f.st.Tenants().Update(t.Context(), tn); err != nil {
				t.Fatal(err)
			}
			rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), tid, acmeAPI)
			rs.ProofOfPossession = &store.ProofOfPossession{Mechanism: "dpop", Required: true}
			if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
				t.Fatal(err)
			}
			raw, hash := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, f.aliceID(t), []string{"openid", "offline_access"})
			form := deviceForm("dev", raw)
			// An exchange-supplied audience cannot replace the stored approval.
			if tc.requestAudience != "" {
				form.Set("audience", tc.requestAudience)
			}
			for _, proof := range []string{"", "invalid"} {
				var header map[string]string
				if proof != "" {
					header = map[string]string{"DPoP": proof}
				}
				rec, body := f.call(t, false, tokenCall{host: acmeHost, form: form, header: header})
				if rec.Code != 400 || body["error"] != "invalid_dpop_proof" {
					t.Fatalf("refusal %d %v", rec.Code, body["error"])
				}
				dc, err := f.st.DeviceCodes().Get(t.Context(), tid, hash)
				if err != nil || dc.Status != store.DeviceCodeApproved || dc.LastPolledAt != nil {
					t.Fatal("proof refusal changed approved device code")
				}
			}
			key := dpopKey(t)
			rec, _ := f.call(t, false, tokenCall{host: acmeHost, form: form, header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", "")}})
			nonce := rec.Header().Get("DPoP-Nonce")
			if nonce == "" {
				t.Fatal("missing nonce challenge")
			}
			rec, body := f.call(t, false, tokenCall{host: acmeHost, form: form, header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", nonce)}})
			if rec.Code != 200 || body["token_type"] != "DPoP" {
				t.Fatalf("later valid exchange %d %v", rec.Code, body["error"])
			}
		})
	}
}

func TestDPoPWrongClientCodeBeforeMutation(t *testing.T) {
	for _, redeemed := range []bool{false, true} {
		t.Run(strconv.FormatBool(redeemed), func(t *testing.T) {
			f := newFixture(t)
			key := dpopKey(t)
			jwk := jose.JSONWebKey{Key: &key.PublicKey}
			thumb, _ := jwk.Thumbprint(crypto.SHA256)
			original := f.issueCode(t, "rt-spa", "https://app.acme.test/cb", acmeAPI, []string{"openid", "offline_access"}, pkceChallenge)
			ac, _ := f.st.AuthCodes().Get(t.Context(), f.tenantID(t, "acme"), secrets.HashToken(original))
			raw := secrets.RandomString(24)
			ac.CodeHash, ac.DPoPJKT = secrets.HashToken(raw), base64.RawURLEncoding.EncodeToString(thumb)
			if err := f.st.AuthCodes().Create(t.Context(), ac); err != nil {
				t.Fatal(err)
			}
			var refresh string
			if redeemed {
				form := codeForm(raw, "rt-spa", "https://app.acme.test/cb", pkceVerifier)
				rec, _ := f.call(t, false, tokenCall{host: acmeHost, form: form, header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", "")}})
				rec, body := f.call(t, false, tokenCall{host: acmeHost, form: form, header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", rec.Header().Get("DPoP-Nonce"))}})
				if rec.Code != 200 {
					t.Fatalf("legitimate exchange %d %v", rec.Code, body["error"])
				}
				refresh = body["refresh_token"].(string)
			}
			before, _ := f.st.AuthCodes().Get(t.Context(), ac.TenantID, ac.CodeHash)
			rec, body := f.call(t, false, tokenCall{host: acmeHost, form: codeForm(raw, "code-spa", "https://app.acme.test/cb", pkceVerifier)})
			if rec.Code != 400 || body["error"] != "invalid_grant" {
				t.Fatalf("wrong client %d %v", rec.Code, body["error"])
			}
			after, _ := f.st.AuthCodes().Get(t.Context(), ac.TenantID, ac.CodeHash)
			if (before.UsedAt == nil) != (after.UsedAt == nil) || after.ReplayedAt != nil {
				t.Fatal("wrong client changed code use/replay markers")
			}
			if before.UsedAt != nil && !before.UsedAt.Equal(*after.UsedAt) {
				t.Fatal("wrong client changed use time")
			}
			if refresh != "" && f.storedRT(t, refresh).RevokedAt != nil {
				t.Fatal("wrong client revoked legitimate family")
			}
		})
	}
}
