package federation

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"reflect"
	"testing"
)

func TestUserinfoFetchedOnlyWhenReferenced(t *testing.T) {
	for _, referenced := range []bool{false, true} {
		p := newIDP(t)
		p.userinfo = map[string]any{"sub": "Subject-1", "name": "Userinfo Name"}
		ps := p.providers()
		in := p.exchangeInput(t, ps)
		in.Config.AttrMap = &rules.AttrMap{Mode: "use_map", Attributes: map[string]string{"name": "${context.tokenset.name}"}}
		if referenced {
			in.Config.AttrMap.Attributes["name"] = "${context.userinfo.name}"
		}
		r, e := ps.For(in.Config).Exchange(context.Background(), in)
		if e != nil {
			t.Fatal(e)
		}
		p.mu.Lock()
		hits := p.userinfoHits
		p.mu.Unlock()
		wantHits := 0
		if referenced {
			wantHits = 1
		}
		if hits != wantHits {
			t.Fatalf("userinfo calls=%d", hits)
		}
		want := "A"
		if referenced {
			want = "Userinfo Name"
		}
		if r.Profile.Name == nil || *r.Profile.Name != want {
			t.Fatal(r.Profile.Name)
		}
		if referenced {
			p.userinfo["sub"] = "different"
			if _, e := ps.For(in.Config).Exchange(context.Background(), in); e == nil {
				t.Fatal("userinfo sub mismatch accepted")
			}
		}
	}
}
func TestUseMapProfile(t *testing.T) {
	p := newIDP(t)
	p.claims = func(c map[string]any) { c["roles"] = []any{"staff"} }
	ps := p.providers()
	in := p.exchangeInput(t, ps)
	in.Config.AttrMap = &rules.AttrMap{Mode: "use_map", Attributes: map[string]string{"name": "Mapped Name", "nickname": "user|${context.tokenset.sub}", "federated_groups": "${context.tokenset.roles}"}}
	r, e := ps.For(in.Config).Exchange(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	if r.Profile.Name == nil || *r.Profile.Name != "Mapped Name" || r.Profile.Email != nil || !reflect.DeepEqual(r.Profile.ProviderData["federated_groups"], []any{"staff"}) {
		t.Fatal(r.Profile)
	}
}
func TestBindAllDropsRestricted(t *testing.T) {
	p := newIDP(t)
	p.claims = func(c map[string]any) {
		c["blocked"] = true
		c["app_metadata"] = map[string]any{"admin": true}
		c["federated_groups"] = []any{"staff"}
	}
	ps := p.providers()
	in := p.exchangeInput(t, ps)
	in.Config.AttrMap = &rules.AttrMap{Mode: "bind_all"}
	r, e := ps.For(in.Config).Exchange(context.Background(), in)
	if e != nil {
		t.Fatal(e)
	}
	if r.Profile.ProviderData["blocked"] != nil || r.Profile.ProviderData["app_metadata"] != nil || !reflect.DeepEqual(r.Profile.ProviderData["federated_groups"], []any{"staff"}) {
		t.Fatal(r.Profile)
	}
}
func TestMappedProviderDataSync(t *testing.T) {
	e := newIdentityEnv(t, "on_each_login")
	r := result("mapped", nil)
	r.Profile.ProviderData = map[string]any{"federated_groups": []any{"staff"}}
	u, err := e.login(e.conn, r)
	if err != nil {
		t.Fatal(err)
	}
	if u.Identities[0].Linked() {
		t.Fatal("primary identity turned into a linked identity")
	}
	r.Profile.ProviderData = map[string]any{"federated_groups": []any{"staff", "ops"}}
	u, err = e.login(e.conn, r)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(u.Identities[0].ProviderData["federated_groups"], []any{"staff", "ops"}) {
		t.Fatal(u.Identities)
	}
}

func TestOktaIssuer(t *testing.T) {
	s := configSpec(t, "okta", `{"client_id":"client","client_secret":"fixture","domain":"DEV-1.OKTA.COM","scope":"openid"}`)
	cfg, e := ParseConfig(s)
	if e != nil || cfg.Issuer != "https://dev-1.okta.com" || cfg.DiscoveryURL != "https://dev-1.okta.com/.well-known/openid-configuration" || cfg.IsSocial {
		t.Fatal(cfg, e)
	}
	conn := &store.Connection{Name: "corp", Strategy: "okta"}
	if got := identityUserID(conn, "subject"); got != "corp|subject" {
		t.Fatal(got)
	}

}
func TestSetUserRootAttributesWithMap(t *testing.T) {
	e := newIdentityEnv(t, "on_first_login")
	r := result("once", nil)
	r.Profile.Name = strp("First mapped name")
	r.Profile.ProviderData = map[string]any{"federated_groups": []any{"staff"}}
	if _, err := e.login(e.conn, r); err != nil {
		t.Fatal(err)
	}
	r.Profile.Name = strp("Second mapped name")
	r.Profile.ProviderData = map[string]any{"federated_groups": []any{"ops"}}
	u, err := e.login(e.conn, r)
	if err != nil || u.Name != "First mapped name" {
		t.Fatal(u, err)
	}
}

func TestMappedUsername(t *testing.T) {
	p, e := mappedProfile(Config{Strategy: "oidc", Channel: "back_channel", AttrMap: &rules.AttrMap{Mode: "use_map", Attributes: map[string]string{"username": "mapped-user"}}}, "con", "sub", map[string]any{}, nil, TokenSet{})
	if e != nil {
		t.Fatal(e)
	}
	env := newIdentityEnv(t, "on_each_login")
	u, e := env.login(env.conn, ProviderResult{Profile: p})
	if e != nil || u.Username != "mapped-user" {
		t.Fatal(u, e)
	}
}
