package authz

import (
	"net/url"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// WSFedBindingPrefix marks a Request.SAML binding that belongs to a
// WS-Federation sign-in (Plan 37b) rather than a SAML IdP request. Like every
// binding it is server-only: request parameters never set Request.SAML.
const WSFedBindingPrefix = "wsfed:"

// IsWSFedBinding reports whether binding is a WS-Fed sign-in's.
func IsWSFedBinding(binding string) bool { return strings.HasPrefix(binding, WSFedBindingPrefix) }

// WSFedReplyAllowed reports whether reply may receive a WS-Fed token for
// client: an absolute http or https URL without a fragment that one of the
// application's callbacks allows, with the callback wildcard rules of
// redirect_uri (Plan 37b). The add-on must be enabled.
func WSFedReplyAllowed(client *store.Client, reply string) bool {
	if client == nil || client.Addons == nil || client.Addons.WSFed == nil {
		return false
	}
	u, err := url.Parse(reply)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	return callbackAllowed(client.Callbacks, reply)
}
