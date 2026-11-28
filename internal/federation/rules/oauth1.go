package rules

import (
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/federation/oauth1sig"
)

// OAuth1Settings are the OAuth 1.0a endpoints and signature method of an
// oauth1 connection or a Twitter connection on protocol oauth1 (LR39b-9).
type OAuth1Settings struct {
	RequestTokenURL      string
	AccessTokenURL       string
	UserAuthorizationURL string
	// SignatureMethod is HMAC-SHA1 or RSA-SHA1; PLAINTEXT is never used.
	SignatureMethod string
	// EmptySecret accepts an empty oauth_token_secret (Evernote, LR39d-4).
	EmptySecret bool
}

// NeedsSocialCapability reports whether identities of strategy need the
// social.v1 store capability: the descriptor strategies and oauth1.
func NeedsSocialCapability(strategy string) bool {
	return strategy == OAuth1 || IsDescriptorSocial(strategy)
}

// parseOAuth1 validates a generic oauth1 connection. signatureMethod absent
// signs with HMAC-SHA1; "RSA-SHA1", the only value Auth0's OpenAPI allows,
// makes client_secret a PEM RSA private key.
func parseOAuth1(o map[string]any, out *Settings, hasSealedSecret bool) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	for _, k := range []string{"authorizationURL", "tokenURL", "scope"} {
		if _, ok := o[k]; ok {
			fail("options.%s is not an oauth1 option", k)
		}
	}
	s := &OAuth1Settings{
		RequestTokenURL:      endpoint(o, "requestTokenURL", false, fail),
		AccessTokenURL:       endpoint(o, "accessTokenURL", false, fail),
		UserAuthorizationURL: endpoint(o, "userAuthorizationURL", false, fail),
		SignatureMethod:      oauth1sig.HMACSHA1,
	}
	if v, named := o["signatureMethod"]; named {
		if v != oauth1sig.RSASHA1 {
			fail("options.signatureMethod must be absent (HMAC-SHA1) or RSA-SHA1")
		} else {
			s.SignatureMethod = oauth1sig.RSASHA1
			secret, isStr := o["client_secret"].(string)
			if isStr && secret != "" {
				if _, err := oauth1sig.ParsePrivateKey(secret); err != nil {
					fail("options.client_secret must be a PEM RSA private key of at least %d bits for RSA-SHA1", oauth1sig.MinRSABits)
				}
			} else if !hasSealedSecret {
				fail("options.client_secret is required")
			}
		}
	}
	parseScript(o, out, fail)
	out.OAuth1 = s
	out.AuthorizationURL, out.TokenURL = s.UserAuthorizationURL, s.AccessTokenURL
	return errs
}
