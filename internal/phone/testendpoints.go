package phone

import (
	"net/http"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/httpx"
)

// EndpointSet holds the provider base URLs. SNS may contain "{region}".
type EndpointSet struct{ Twilio, SNS, Gateway string }

// Endpoints are the fixed vendor URLs (D-0060 LR4). Tenants cannot change
// them; only SetTestEndpoints, fed by config.TestPhoneEndpoints under
// ZA_TEST_MODE=1, redirects them to local fakes.
var Endpoints = EndpointSet{Twilio: "https://api.twilio.com", SNS: "https://sns.{region}.amazonaws.com/"}

var testEndpoints bool

// SetTestEndpoints redirects the adapters to local fakes. Empty values keep
// the vendor URL. It also allows the guarded client to reach loopback.
func SetTestEndpoints(twilio, sns string, gateway ...string) {
	if twilio != "" {
		Endpoints.Twilio = strings.TrimRight(twilio, "/")
	}
	if sns != "" {
		Endpoints.SNS = sns
	}
	if len(gateway) > 0 {
		Endpoints.Gateway = gateway[0]
	}
	testEndpoints = twilio != "" || sns != "" || Endpoints.Gateway != ""
}

// NewHTTPClient returns the provider client: SSRF-guarded dialer (private
// addresses only while test endpoints are active), 10 s bound, no redirects.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{DialContext: httpx.GuardedDialer(testEndpoints)},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func snsURL(region string) string { return strings.ReplaceAll(Endpoints.SNS, "{region}", region) }
