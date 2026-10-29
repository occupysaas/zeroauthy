package actions

import (
	"encoding/json"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestOrganizationActionsEvent(t *testing.T) {
	org := &store.Organization{ID: "org_bound", TenantID: "t", Name: "acme", DisplayName: "Acme", Metadata: map[string]string{"tier": "gold"}}
	for _, present := range []bool{false, true} {
		reg := RegistrationInput{}
		post := PostLoginInput{}
		if present {
			reg.Organization = org
			post.Organization = org
		}
		for name, event := range map[string]map[string]any{"pre": registrationEvent(&reg, newAccum(TriggerPreUserRegistration, nil, nil, false)), "post": postRegistrationEvent(&reg, newAccum(TriggerPostUserRegistration, nil, nil, false)), "login": postLoginEvent(&post, nil, newAccum(TriggerPostLogin, nil, nil, false))} {
			value, exists := event["organization"]
			if !present {
				if exists {
					t.Errorf("%s individual event includes organization", name)
				}
				continue
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != `{"display_name":"Acme","id":"org_bound","metadata":{"tier":"gold"},"name":"acme"}` {
				t.Errorf("%s organization=%s", name, raw)
			}
		}
	}
}
