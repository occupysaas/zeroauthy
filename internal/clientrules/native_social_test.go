package clientrules_test

import (
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"testing"
)

func TestNativeSocialLoginSchema(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `true`, `{"apple":{}}`, `{"other":{"enabled":true}}`, `{"apple":{"enabled":true,"unexpected":1}}`, `{"apple":{"enabled":null}}`, `{"apple":{"enabled":1}}`} {
		if _, err := clientrules.ParseNativeSocialLogin(json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"apple":{"enabled":true},"facebook":{"enabled":false},"google":{"enabled":true}}`} {
		if _, err := clientrules.ParseNativeSocialLogin(json.RawMessage(raw)); err != nil {
			t.Errorf("rejected %s: %v", raw, err)
		}
	}
}
