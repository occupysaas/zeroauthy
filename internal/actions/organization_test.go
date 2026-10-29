package actions_test

import (
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions"
)

// Actual Action commands cannot spoof an organization's reserved claims,
// including when the grant has no organization claim to overwrite.
func TestOrganizationReservedClaims(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", actions.TriggerPostLogin, "org-spoof", `exports.onExecutePostLogin=async(event,api)=>{for(const token of [api.idToken,api.accessToken]){token.setCustomClaim("org_id","org_forged");token.setCustomClaim("org_name","forged");token.setCustomClaim("https://example.test/control","kept");}};`, nil, false)
	h.bind("t1", actions.TriggerPostLogin, a)
	result := h.mustPostLogin("t1")
	for i, custom := range []map[string]any{result.Effects.AccessClaims, result.Effects.IDClaims} {
		claims, err := actions.FilterClaims(actions.ClaimTarget(i), nil, custom, false)
		if err != nil {
			t.Fatal(err)
		}
		if claims["org_id"] != nil || claims["org_name"] != nil || claims["https://example.test/control"] != "kept" {
			t.Fatalf("custom claims=%v", claims)
		}
	}
}

// The post-login engine resolves the bound ID once and preserves its event
// snapshot across a redirect even when the organization is renamed meanwhile.
func TestOrganizationActionsEventSnapshot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	org := &store.Organization{TenantID: "t1", ID: "org_0000000000000001", Name: "acme", DisplayName: "Acme", Metadata: map[string]string{"tier": "gold"}}
	if err := h.st.Organizations().Create(ctx, org, nil); err != nil {
		t.Fatal(err)
	}
	a := h.action("t1", actions.TriggerPostLogin, "org-event", `const check=(e)=>{if(JSON.stringify(e.organization)!=='{"display_name":"Acme","id":"org_0000000000000001","metadata":{"tier":"gold"},"name":"acme"}')throw Error('organization changed: '+JSON.stringify(e.organization))};exports.onExecutePostLogin=(e,a)=>{check(e);a.redirect.sendUserTo('https://step.test/')};exports.onContinuePostLogin=(e,a)=>{check(e);a.idToken.setCustomClaim('urn:org',e.organization.id)};`, nil, false)
	h.bind("t1", a.Trigger, a)
	in := redirectInput(h)
	in.OrganizationID = org.ID
	// A caller-supplied snapshot cannot replace the bound organization.
	in.Organization = &store.Organization{ID: "org_forged"}
	r, err := h.eng.PostLogin(ctx, in)
	state := redirectState(t, r, err)
	org.DisplayName = "Changed"
	org.Metadata["tier"] = "silver"
	if err := h.st.Organizations().Update(ctx, org); err != nil {
		t.Fatal(err)
	}
	r, err = resume(t, h, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test"})
	if err != nil || r.Effects.IDClaims["urn:org"] != org.ID {
		t.Fatalf("resume=%+v err=%v", r, err)
	}
	in.OrganizationID = ""
	if _, err = h.eng.PostLogin(ctx, in); err == nil {
		t.Fatal("unbound snapshot leaked into event")
	}
}

// The queued canonical event, not a later organization lookup, is sealed.
func TestOrganizationActionsEventJob(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	org := &store.Organization{TenantID: "t1", ID: "org_0000000000000001", Name: "acme", DisplayName: "Acme", Metadata: map[string]string{"tier": "gold"}}
	in := actions.RegistrationInput{Tenant: h.loginInput("t1").Tenant, Organization: org, User: h.user("t1")}
	pre := h.action("t1", actions.TriggerPreUserRegistration, "org-pre", `exports.onExecutePreUserRegistration=(e,a)=>{if(e.organization.name!=='acme'||e.organization.metadata.tier!=='gold')throw Error('missing org');a.user.setAppMetadata('org',e.organization.id)};`, nil, false)
	post := h.action("t1", actions.TriggerPostUserRegistration, "org-post", `exports.onExecutePostUserRegistration=(e)=>{if(e.organization.display_name!=='Acme'||e.organization.metadata.tier!=='gold')throw Error('lost snapshot')}`, nil, false)
	h.bind("t1", pre.Trigger, pre)
	h.bind("t1", post.Trigger, post)
	result, err := h.eng.PreUserRegistration(ctx, in)
	if err != nil || result.Effects.AppMetadata["org"] != org.ID {
		t.Fatalf("pre=%+v %v", result, err)
	}
	if err := h.st.WithTx(ctx, func(tx store.Store) error { return h.eng.EnqueuePostUserRegistration(ctx, tx, in) }); err != nil {
		t.Fatal(err)
	}
	org.DisplayName = "Changed"
	org.Metadata["tier"] = "silver"
	j := claimJob(t, h)
	plain, err := keys.OpenBound(h.eng.Secrets, "action-job/v1", []string{j.TenantID, j.ID, j.Trigger}, j.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct{ Input map[string]any }
	if err = json.Unmarshal(plain, &payload); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(payload.Input["organization"])
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"display_name":"Acme","id":"org_0000000000000001","metadata":{"tier":"gold"},"name":"acme"}` {
		t.Fatalf("sealed org=%s", raw)
	}
	if n := finishJob(t, h, &j); n.Status != "done" {
		t.Fatalf("job=%+v", n)
	}
}
