package dirsync

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

var fixedNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

const (
	adminRefresh = "1//admin-refresh-secret"
	adminAccess  = "ya29.admin-access-secret"
	provSecret   = "provider-secret"
)

// directory is a fixture Google: OAuth token endpoint, JWKS and the Admin
// SDK Directory API (users, groups, members) for one domain.
type directory struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey
	mu  sync.Mutex
	// users and groups are the directory's content; members by group ID.
	users   []map[string]any
	groups  []Group
	members map[string][]Member
	// revoked makes the refresh grant invalid_grant; forbidden answers the
	// Directory API with 403 (a non-administrator).
	revoked, forbidden bool
	// idClaims are the consent's ID token claims; codes map code → nonce.
	idClaims map[string]any
	codes    map[string]string
	refresh  string
	requests []string
}

func newDirectory(t *testing.T) *directory {
	d := &directory{t: t, members: map[string][]Member{}, codes: map[string]string{}, refresh: adminRefresh,
		idClaims: map[string]any{"sub": "100", "email": "admin@corp.example.com", "email_verified": true, "hd": "corp.example.com"}}
	d.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	d.srv = httptest.NewTLSServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *directory) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *directory) serve(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	switch {
	case r.URL.Path == "/jwks":
		d.json(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &d.key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
		return
	case r.URL.Path == "/token":
		_ = r.ParseForm()
		if r.PostForm.Get("client_id") != "ws-client" || r.PostForm.Get("client_secret") != provSecret {
			d.json(w, 401, map[string]any{"error": "invalid_client"})
			return
		}
		switch r.PostForm.Get("grant_type") {
		case "refresh_token":
			if d.revoked || r.PostForm.Get("refresh_token") != adminRefresh {
				d.json(w, 400, map[string]any{"error": "invalid_grant", "error_description": "Token has been expired or revoked."})
				return
			}
			d.json(w, 200, map[string]any{"access_token": adminAccess, "token_type": "Bearer", "expires_in": 3599})
		case "authorization_code":
			nonce, ok := d.codes[r.PostForm.Get("code")]
			delete(d.codes, r.PostForm.Get("code"))
			if !ok || r.PostForm.Get("code_verifier") == "" {
				d.json(w, 400, map[string]any{"error": "invalid_grant"})
				return
			}
			c := map[string]any{"iss": d.srv.URL, "aud": "ws-client", "nonce": nonce, "iat": fixedNow.Unix(), "exp": fixedNow.Add(time.Hour).Unix()}
			for k, v := range d.idClaims {
				c[k] = v
			}
			payload, _ := json.Marshal(c)
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: d.key}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
			obj, _ := signer.Sign(payload)
			tok, _ := obj.CompactSerialize()
			out := map[string]any{"access_token": adminAccess, "token_type": "Bearer", "expires_in": 3599, "id_token": tok}
			if d.refresh != "" {
				out["refresh_token"] = d.refresh
			}
			d.json(w, 200, out)
		default:
			d.json(w, 400, map[string]any{"error": "unsupported_grant_type"})
		}
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/directory/") {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+adminAccess {
		d.json(w, 401, map[string]any{"error": map[string]any{"code": 401}})
		return
	}
	if d.forbidden {
		d.json(w, 403, map[string]any{"error": map[string]any{"code": 403, "message": "Not Authorized to access this resource/api"}})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/directory")
	q := r.URL.Query()
	switch {
	case path == "/users":
		if q.Get("domain") != "corp.example.com" {
			d.json(w, 400, map[string]any{})
			return
		}
		// Two users per page exercise paging.
		start := 0
		if p := q.Get("pageToken"); p != "" {
			start = int(p[0] - '0')
		}
		end := min(start+2, len(d.users))
		if q.Get("maxResults") == "1" {
			end = min(start+1, len(d.users))
		}
		out := map[string]any{"users": d.users[start:end]}
		if end < len(d.users) && q.Get("maxResults") != "1" {
			out["nextPageToken"] = string(rune('0' + end))
		}
		d.json(w, 200, out)
	case path == "/groups":
		d.json(w, 200, map[string]any{"groups": d.groups})
	case strings.HasPrefix(path, "/groups/") && strings.HasSuffix(path, "/members"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/groups/"), "/members")
		d.json(w, 200, map[string]any{"members": d.members[id]})
	case strings.HasPrefix(path, "/groups/"):
		id := strings.TrimPrefix(path, "/groups/")
		for _, g := range d.groups {
			if g.ID == id {
				d.json(w, 200, g)
				return
			}
		}
		d.json(w, 404, map[string]any{})
	default:
		http.NotFound(w, r)
	}
}

func (d *directory) providers() *federation.Providers {
	pool := x509.NewCertPool()
	pool.AddCert(d.srv.Certificate())
	b := d.srv.URL
	return federation.NewProviders(federation.FixturePolicy(pool), func() time.Time { return fixedNow }).WithGoogleFixture(federation.GoogleOverride{
		Issuer: b, DirectoryURL: b + "/directory",
		Endpoints: store.FederationEndpoints{AuthorizationURL: b + "/authorize", TokenURL: b + "/token", JWKSURL: b + "/jwks", TokenAuthMethod: "client_secret_post"}})
}

func wsUser(email, given string, suspended bool) map[string]any {
	return map[string]any{"id": "id-" + strings.Split(email, "@")[0], "primaryEmail": email, "suspended": suspended,
		"name": map[string]any{"givenName": given, "familyName": "Example", "fullName": given + " Example"}}
}

// env is a memory store with tenant ten_a and the google-apps connection
// con_ws ("workspace") whose directory provisioning has a grant.
type env struct {
	st   *memory.Store
	w    keys.Wrapper
	dir  *directory
	sync *Syncer
	now  time.Time
}

func newEnv(t *testing.T, doc string, groups bool) *env {
	t.Helper()
	ctx := context.Background()
	e := &env{st: memory.New(), dir: newDirectory(t), now: fixedNow}
	e.w, _ = keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	for _, tid := range []string{"ten_a", "ten_b"} {
		if err := e.st.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: strings.TrimPrefix(tid, "ten_")}); err != nil {
			t.Fatal(err)
		}
	}
	spec := connrules.Spec{Name: "workspace", Strategy: "google-apps",
		Options: connrules.Options{Extra: map[string]any{"client_id": "ws-client", "domain": "corp.example.com", "api_enable_groups": groups}}}
	c := &store.Connection{TenantID: "ten_a", ID: "con_ws", CreatedAt: fixedNow, Origin: store.OriginAPI}
	connrules.Apply(&spec, c)
	sealed, err := federation.SealCredentials(e.w, "ten_a", "con_ws", federation.Credentials{ClientSecret: provSecret})
	if err != nil {
		t.Fatal(err)
	}
	c.FederationSecretsSealed, c.FederationRevision = sealed, 1
	if err := e.st.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	grant, err := SealGrant(e.w, "ten_a", "con_ws", adminRefresh)
	if err != nil {
		t.Fatal(err)
	}
	if doc == "" {
		doc = `{"mapping":[{"auth0":"email","scim":"primaryEmail"},{"auth0":"given_name","scim":"name.givenName"},{"auth0":"name","scim":"name.fullName"}],"synchronize_automatically":true}`
	}
	if err := e.st.DirectorySync().CreateProvisioning(ctx, &store.DirectoryProvisioning{TenantID: "ten_a", ConnectionID: "con_ws",
		Doc: json.RawMessage(doc), AdminGrant: grant, CreatedAt: fixedNow, UpdatedAt: fixedNow}); err != nil {
		t.Fatal(err)
	}
	e.sync = &Syncer{Store: e.st, Wrapper: e.w, Providers: e.dir.providers(), Now: func() time.Time { return e.now }}
	return e
}

// runNow requests and runs one synchronization.
func (e *env) runNow(t *testing.T) *store.DirectoryProvisioning {
	t.Helper()
	ctx := context.Background()
	p, err := e.st.DirectorySync().GetProvisioning(ctx, "ten_a", "con_ws")
	if err != nil {
		t.Fatal(err)
	}
	Schedule(p, e.now)
	p.LeaseUntil = nil
	if err := e.st.DirectorySync().UpdateProvisioning(ctx, p); err != nil {
		t.Fatal(err)
	}
	if n, err := e.sync.RunDue(ctx); err != nil || n != 1 {
		t.Fatalf("ran %d: %v", n, err)
	}
	p, _ = e.st.DirectorySync().GetProvisioning(ctx, "ten_a", "con_ws")
	return p
}

func (e *env) user(t *testing.T, email string) *store.User {
	t.Helper()
	u, err := e.st.Users().FindByIdentity(context.Background(), "ten_a", "con_ws", email)
	if err != nil {
		t.Fatalf("%s: %v", email, err)
	}
	return u
}
