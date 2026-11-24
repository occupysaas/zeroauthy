package mgmt

import (
	"encoding/json"
	"testing"
)

func TestCheckSchema(t *testing.T) {
	for body, ok := range map[string]bool{
		`{"name":"Partners"}`: true,
		`{"name":"Partners","branding":{"logo_url":"https://logo.test/a.png","colors":{"primary":"#123abc"}},"allowed_strategies":["samlp","oidc"]}`: true,
		`{"name":""}`:              false,
		`{}`:                       false,
		`{"name":"x","unknown":1}`: false,
		`{"name":"x","branding":{"logo_url":"http://a"}}`:              false,
		`{"name":"x","branding":{"colors":{"primary":"red"}}}`:         false,
		`{"name":"x","allowed_strategies":["ldap"]}`:                   false,
		`{"name":"x","description":"` + string(make([]byte, 0)) + `"}`: false,
	} {
		err := checkSchema("CreateSelfServiceProfileRequestContent", json.RawMessage(body))
		if (err == nil) != ok {
			t.Errorf("%s: %v", body, err)
		}
	}
	if err := checkSchema("NoSuchSchema", json.RawMessage(`{}`)); err == nil {
		t.Error("unknown schema accepted")
	}
}
