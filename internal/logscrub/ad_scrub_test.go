package logscrub_test

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

// The AD/LDAP Connector's signing key and the provisioning ticket URL are
// secrets (Plan 38a): whoever holds them can send requests to the connector
// or register one.
func TestADConnectorKeysSensitive(t *testing.T) {
	for _, key := range []string{"signingKey", "signing_key", "TENANT_SIGNING_KEY", "provisioning_ticket_url", "provisioningTicket", "ticket"} {
		if !logscrub.SensitiveKey(key) {
			t.Errorf("AD key %q is public", key)
		}
	}
	got := logscrub.ScrubValue(map[string]any{"signingKey": "k", "provisioning_ticket_url": "https://x/p/ad/t", "connectionName": "corp"}).(map[string]any)
	if got["signingKey"] != logscrub.Marker || got["provisioning_ticket_url"] != logscrub.Marker || got["connectionName"] != "corp" {
		t.Fatalf("scrubbed %v", got)
	}
}
