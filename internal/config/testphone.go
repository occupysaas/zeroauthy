package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// TestPhone redirects the Twilio and SNS adapters to local fakes (D-0060 LR4).
type TestPhone struct{ Twilio, SNS, Gateway string }

// Active reports whether any endpoint is overridden.
func (t TestPhone) Active() bool { return t.Twilio != "" || t.SNS != "" || t.Gateway != "" }

// TestPhoneEndpoints reads ZA_TEST_MODE and ZA_TEST_PHONE_ENDPOINTS from
// environ ("KEY=value" entries). The latter is "twilio=URL,sns=URL" and is an
// error unless ZA_TEST_MODE is exactly 1.
func TestPhoneEndpoints(environ []string) (TestPhone, error) {
	var mode, raw string
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "ZA_TEST_MODE":
			mode = v
		case "ZA_TEST_PHONE_ENDPOINTS":
			raw = v
		}
	}
	if raw == "" {
		return TestPhone{}, nil
	}
	if mode != "1" {
		return TestPhone{}, errors.New("config: ZA_TEST_PHONE_ENDPOINTS requires ZA_TEST_MODE=1")
	}
	var out TestPhone
	for _, part := range strings.Split(raw, ",") {
		name, endpoint, ok := strings.Cut(strings.TrimSpace(part), "=")
		u, err := url.Parse(endpoint)
		if !ok || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return TestPhone{}, errors.New("config: ZA_TEST_PHONE_ENDPOINTS entries must be twilio=URL, sns=URL or gateway=URL")
		}
		switch name {
		case "twilio":
			out.Twilio = endpoint
		case "sns":
			out.SNS = endpoint
		case "gateway":
			out.Gateway = endpoint
		default:
			return TestPhone{}, fmt.Errorf("config: ZA_TEST_PHONE_ENDPOINTS: unknown provider %q", name)
		}
	}
	return out, nil
}
