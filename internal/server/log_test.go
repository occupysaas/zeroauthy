package server

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

// The AD/LDAP provisioning ticket in the path is never logged (Plan 38a).
func TestLogPathHidesADTicket(t *testing.T) {
	for in, want := range map[string]string{
		"/p/ad/TICKETxyz/info": "/p/ad/" + logscrub.Marker + "/info",
		"/p/ad/TICKETxyz":      "/p/ad/" + logscrub.Marker,
		"/authorize":           "/authorize",
	} {
		if got := logPath(in); got != want {
			t.Errorf("logPath(%q) = %q", in, got)
		}
	}
}
