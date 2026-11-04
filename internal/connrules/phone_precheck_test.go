package connrules

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestPhonePrecheck(t *testing.T) {
	st := memory.New()
	ctx := context.Background()
	for _, u := range []store.User{{UserID: "a", PhoneNumber: "+1 415 555 0100"}, {UserID: "b", PhoneNumber: "+14155550100"}, {UserID: "c", PhoneNumber: "bad"}} {
		u.TenantID = "t"
		u.CreatedAt = time.Now()
		u.Identities = []store.Identity{{Provider: "auth0", Connection: "db", UserID: u.UserID}}
		if err := st.Users().Create(ctx, &u); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := st.Users().Get(ctx, "t", "a")
	conflicts, err := PhonePrecheck(ctx, st, "t", "db")
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 2 {
		t.Fatalf("conflicts: %+v", conflicts)
	}
	for _, c := range conflicts {
		if c.Reason != "invalid" && c.Reason != "duplicate" {
			t.Fatal(c)
		}
	}
	u, _ := st.Users().Get(ctx, "t", "a")
	if u.PhoneNumber != "+1 415 555 0100" || u.PhoneNormalized != before.PhoneNormalized {
		t.Fatal("precheck rewrote data")
	}
}

func TestPhoneAttributeValidation(t *testing.T) {
	for _, body := range []string{
		`{"name":"db","strategy":"auth0","options":{"attributes":{"phone_number":{"identifier":{"active":"yes"}}}}}`,
		`{"name":"db","strategy":"auth0","options":{"attributes":{"phone_number":{"signup":{"status":"unknown"}}}}}`,
		`{"name":"db","strategy":"auth0","options":{"attributes":{"phone_number":{"signup":{"verification":{"active":"yes"}}}}}}`,
	} {
		if errs := NormalizeAPI(decode(t, body)); len(errs) == 0 {
			t.Errorf("accepted malformed phone attributes: %s", body)
		}
	}
}
