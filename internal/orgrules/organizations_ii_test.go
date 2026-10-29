package orgrules

import (
	"math"
	"testing"
	"time"
)

// This contract gate catches omitted routes before handlers are built against
// an incomplete inventory. Expectations are independent of the inventory data.
func TestOrganizationsIIInventory(t *testing.T) {
	want := map[string]int{
		"GET /api/v2/organizations/search":                                          200,
		"POST /api/v2/organizations/{id}/invitations":                               200,
		"GET /api/v2/organizations/{id}/invitations":                                200,
		"GET /api/v2/organizations/{id}/invitations/{invitation_id}":                200,
		"DELETE /api/v2/organizations/{id}/invitations/{invitation_id}":             204,
		"GET /api/v2/organizations/{id}/clients":                                    200,
		"POST /api/v2/organizations/{id}/clients":                                   201,
		"DELETE /api/v2/organizations/{id}/clients":                                 204,
		"GET /api/v2/organizations/{id}/clients/{client_id}":                        200,
		"PATCH /api/v2/organizations/{id}/clients/{client_id}":                      200,
		"GET /api/v2/organizations/{id}/client-grants":                              200,
		"POST /api/v2/organizations/{id}/client-grants":                             201,
		"DELETE /api/v2/organizations/{id}/client-grants/{client_grant_id}":         204,
		"GET /api/v2/organizations/{id}/discovery-domains":                          200,
		"POST /api/v2/organizations/{id}/discovery-domains":                         201,
		"GET /api/v2/organizations/{id}/discovery-domains/name/{discovery_domain}":  200,
		"GET /api/v2/organizations/{id}/discovery-domains/{discovery_domain_id}":    200,
		"PATCH /api/v2/organizations/{id}/discovery-domains/{discovery_domain_id}":  200,
		"DELETE /api/v2/organizations/{id}/discovery-domains/{discovery_domain_id}": 204,
	}
	for _, op := range OrganizationsIIInventory() {
		key := op.Method + " " + op.Path
		status, ok := want[key]
		if !ok {
			t.Errorf("unexpected/duplicate %s", key)
			continue
		}
		delete(want, key)
		if op.SuccessStatus != status {
			t.Errorf("%s status=%d want %d", key, op.SuccessStatus, status)
		}
		if len(op.RequiredScopes) == 0 || op.SourceURL == "" || op.RequestShape == "" || op.ResponseShape == "" || op.Pagination == "" || len(op.ErrorStatuses) == 0 {
			t.Errorf("%s incomplete contract", key)
		}
	}
	for key := range want {
		t.Errorf("missing contract %s", key)
	}
}

func TestInvitationTTL(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		want    time.Duration
		invalid bool
	}{
		{0, 604800 * time.Second, false},
		{1, time.Second, false},
		{2592000, 2592000 * time.Second, false},
		{-1, 0, true},
		{2592001, 0, true},
		{math.MaxInt64, 0, true},
	} {
		got, err := InvitationTTL(tc.seconds)
		if (err != nil) != tc.invalid || got != tc.want {
			t.Errorf("InvitationTTL(%d)=%s,%v; want %s invalid=%v", tc.seconds, got, err, tc.want, tc.invalid)
		}
	}
}
