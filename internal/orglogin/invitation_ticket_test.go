package orglogin_test

import (
	"bytes"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/url"
	"testing"
)

func TestInvitationURLReservedParameters(t *testing.T) {
	got, err := orglogin.BuildInvitationURL("https://app.example/login?keep=a%2Bb&invitation=old&organization=wrong&organization_name=old", "a+b/&?", "org_a", "A & B")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("keep") != "a+b" || q.Get("invitation") != "a+b/&?" || q.Get("organization") != "org_a" || q.Get("organization_name") != "A & B" || len(q["invitation"]) != 1 {
		t.Fatal(got)
	}
	for _, bad := range []string{"", "http://app.example/login", "/login", "https://user:pass@app.example/login", "https://app.example/login#fragment", "https://app.example/?bad=%ZZ"} {
		if _, err := orglogin.BuildInvitationURL(bad, "t", "o", "n"); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
func TestOrganizationInvitationTicketSealed(t *testing.T) {
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{3}, 32))
	in := &store.OrganizationInvitation{TenantID: "t", OrganizationID: "org_a", ID: "uinv_a"}
	data, err := orglogin.IssueInvitationTicket(w, in, "https://app.example/login", "Org")
	if err != nil {
		t.Fatal(err)
	}
	if len(data.TicketID) < 43 || bytes.Contains(in.WrappedTicket, []byte(data.TicketID)) || in.TicketHash == data.TicketID {
		t.Fatal("unprotected ticket")
	}
	opened, err := orglogin.OpenInvitationTicket(w, in)
	if err != nil || opened != data {
		t.Fatalf("%v %v", opened, err)
	}
	in.TenantID = "foreign"
	if _, err := orglogin.OpenInvitationTicket(w, in); err == nil {
		t.Fatal("cross tenant open")
	}
}
