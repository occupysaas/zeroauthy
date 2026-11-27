package clientrules

import (
	"strings"
	"testing"
)

// The CIBA grant is for first-party confidential clients with the email
// channel (D-0100, LR41c-2).
func TestCIBAClientRules(t *testing.T) {
	no := false
	ok := Spec{AppType: "regular_web", GrantTypes: []string{GrantAuthorizationCode, GrantCIBA}, AsyncApprovalNotificationChannels: []string{"email", "guardian-push"}}
	if errs := Normalize(&ok, false); len(errs) > 0 {
		t.Fatalf("valid CIBA client: %v", errs)
	}
	for name, tc := range map[string]struct {
		s    Spec
		want string
	}{
		"public":      {Spec{AppType: "spa", GrantTypes: []string{GrantCIBA}, AsyncApprovalNotificationChannels: []string{"email"}}, "confidential"},
		"third party": {Spec{AppType: "regular_web", IsFirstParty: &no, ThirdPartySecurityMode: "permissive", GrantTypes: []string{GrantCIBA}, AsyncApprovalNotificationChannels: []string{"email"}}, "third-party"},
		"no channels": {Spec{AppType: "regular_web", GrantTypes: []string{GrantCIBA}}, "email"},
		"push only":   {Spec{AppType: "regular_web", GrantTypes: []string{GrantCIBA}, AsyncApprovalNotificationChannels: []string{"guardian-push"}}, "guardian-push is not available"},
		"bad channel": {Spec{AppType: "regular_web", AsyncApprovalNotificationChannels: []string{"sms"}}, "async_approval_notification_channels"},
		"duplicate":   {Spec{AppType: "regular_web", AsyncApprovalNotificationChannels: []string{"email", "email"}}, "async_approval_notification_channels"},
		"empty list":  {Spec{AppType: "regular_web", AsyncApprovalNotificationChannels: []string{}}, "async_approval_notification_channels"},
	} {
		errs := Normalize(&tc.s, false)
		joined := ""
		for _, e := range errs {
			joined += e.Error() + "; "
		}
		if !strings.Contains(joined, tc.want) {
			t.Errorf("%s: %v, want %q", name, errs, tc.want)
		}
	}
	// Channels without the grant are stored as given.
	stored := Spec{AppType: "regular_web", AsyncApprovalNotificationChannels: []string{"guardian-push"}}
	if errs := Normalize(&stored, false); len(errs) > 0 {
		t.Fatalf("channels without the grant: %v", errs)
	}
}
