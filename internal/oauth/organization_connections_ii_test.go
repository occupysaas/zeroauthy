package oauth

import (
	"context"
	"testing"
)

func TestOrganizationConnectionsIIDisabledDuringLogin(t *testing.T) {
	f := newOrganizationFixture(t)
	ctx := context.Background()
	link, err := f.st.Organizations().GetConnection(ctx, f.tid, f.org.ID, f.connID)
	if err != nil {
		t.Fatal(err)
	}
	link.OrganizationAccessLevel = "full"
	link.OrganizationMemberAccessLevel = "full"
	if err = f.st.Organizations().PutConnection(ctx, *link, false); err != nil {
		t.Fatal(err)
	}
	status, body := f.exchange(t, f.org.ID)
	if status != 200 {
		t.Fatalf("initial exchange %d %v", status, body["error"])
	}
	refresh := body["refresh_token"].(string)
	code := f.code(t, f.org.ID)
	link.IsEnabled = false
	link.IsEnabledSet = true
	if err = f.st.Organizations().PutConnection(ctx, *link, false); err != nil {
		t.Fatal(err)
	}
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: codeForm(code, "rt-spa", "https://app.acme.test/cb", pkceVerifier)})
	if rec.Code != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil {
		t.Fatalf("disabled code %d %v", rec.Code, body)
	}
	status, body = f.refresh(t, refreshForm("rt-spa", refresh))
	if status != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil {
		t.Fatalf("disabled refresh %d %v", status, body)
	}
	// Full access metadata cannot bypass membership or auto-enroll during mint.
	link.IsEnabled = true
	if err = f.st.Organizations().PutConnection(ctx, *link, false); err != nil {
		t.Fatal(err)
	}
	if err = f.st.Organizations().RemoveMembers(ctx, f.tid, f.org.ID, []string{f.uid}); err != nil {
		t.Fatal(err)
	}
	status, body = f.exchange(t, f.org.ID)
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("metadata authorized nonmember %d %v", status, body)
	}
}
