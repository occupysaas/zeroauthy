package federation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
)

func init() {
	socialHooks[providers.HookFacebook] = socialHook{decorate: facebookAppSecretProof}
	socialHooks[providers.HookLinkedIn] = socialHook{begin: linkedinVersion}
	socialHooks[providers.HookSalesforce] = socialHook{profileURL: salesforceIdentityURL}
	socialHooks[providers.HookLine] = socialHook{after: lineEmail}
	socialHooks[providers.HookShopify] = socialHook{begin: shopifyShop}
	// Twitter's protocol oauth1 runs on the OAuth 1.0a provider (Config.OAuth1);
	// protocol oauth2 needs no hook.
	socialHooks[providers.HookTwitter] = socialHook{}
}

// lineIssuer is the iss of LINE ID tokens.
const lineIssuer = "https://access.line.me"

// lineEmail reads the email claim of the ID token through LINE's verify
// endpoint, only when the email flag requested it. The claims must name this
// channel, LINE's issuer and the profile's user; the email is never marked
// verified (LR39b-4).
func lineEmail(ctx context.Context, ps *Providers, d *providers.Descriptor, in ExchangeInput, t TokenSet, p *Profile) error {
	if !slices.Contains(in.Config.Scopes, "email") || t.IDToken == "" {
		return nil
	}
	form := url.Values{"id_token": {t.IDToken}, "client_id": {in.Config.ClientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ps.socialURL(d.Strategy, d.VerifyURL), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: line verify URL", ErrProviderResponse)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := ps.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: line verify request: %w", ErrProviderResponse, redact(err))
	}
	body, err := readAll(resp)
	if err != nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: line verify response", ErrProviderResponse)
	}
	var claims struct {
		Iss, Sub, Email string
		Aud             any
	}
	if json.Unmarshal(body, &claims) != nil || claims.Iss != lineIssuer || claims.Sub != p.Subject || claims.Aud != in.Config.ClientID {
		return fmt.Errorf("%w: line ID token claims do not match", ErrProviderResponse)
	}
	if claims.Email != "" {
		if s, err := profileString("email", claims.Email, 254); err == nil {
			verified := false
			p.Email, p.EmailVerified = &s, &verified
		}
	}
	return nil
}

// shopifyShopRE is a shop name: lowercase letters, digits and hyphens, not
// starting with a hyphen.
var shopifyShopRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,59}$`)

// shopifyShop builds the per-shop endpoints from login_hint, "<name>" or
// "<name>.myshopify.com" (LR39b-8, SP-9). Anything else refuses the login, so
// no configuration or browser input can point the token request elsewhere.
func shopifyShop(_ *providers.Descriptor, _ Config, loginHint string, e *Endpoints) error {
	name := strings.TrimSuffix(strings.ToLower(loginHint), ".myshopify.com")
	if !shopifyShopRE.MatchString(name) {
		return fmt.Errorf("%w: shopify needs login_hint naming a myshopify.com shop", ErrConnectionUnusable)
	}
	host := name + ".myshopify.com"
	e.AuthorizationURL = strings.Replace(e.AuthorizationURL, providers.ShopPlaceholder, host, 1)
	e.TokenURL = strings.Replace(e.TokenURL, providers.ShopPlaceholder, host, 1)
	e.UserInfoURL = strings.Replace(e.UserInfoURL, providers.ShopPlaceholder, host, 1)
	return nil
}

// salesforceIdentityURL reads the identity URL from the token response's id.
// It is used only when it is an https URL on the token endpoint's host, so a
// token response can never send the access token elsewhere (LR39b-7).
func salesforceIdentityURL(e Endpoints, token map[string]any) (string, error) {
	raw, ok := token["id"].(string)
	if !ok || raw == "" {
		return "", fmt.Errorf("%w: salesforce token response lacks the identity URL", ErrProviderResponse)
	}
	id, err := url.Parse(raw)
	tok, terr := url.Parse(e.TokenURL)
	if err != nil || terr != nil || id.Scheme != "https" || id.User != nil || id.Host == "" || !strings.EqualFold(id.Host, tok.Host) {
		return "", fmt.Errorf("%w: salesforce identity URL is not on the token endpoint host", ErrProviderResponse)
	}
	return id.String(), nil
}

// facebookAppSecretProof adds appsecret_proof, HMAC-SHA256 of the access
// token keyed with the app secret, to every Graph call. The proof is a
// credential: it travels only in the outbound query and never in an error.
func facebookAppSecretProof(req *http.Request, accessToken, clientSecret string) {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(accessToken))
	q := req.URL.Query()
	q.Set("appsecret_proof", hex.EncodeToString(mac.Sum(nil)))
	req.URL.RawQuery = q.Encode()
}

// linkedinVersion refuses strategy_version 1 and 2 at login: LinkedIn retired
// those APIs (LR39b-6, SP-8). They stay stored and returned.
func linkedinVersion(_ *providers.Descriptor, cfg Config, _ string, _ *Endpoints) error {
	if cfg.Social == nil || cfg.Social.StrategyVersion != 3 {
		return fmt.Errorf("%w: linkedin strategy_version 1 and 2 are retired; use 3", ErrConnectionUnusable)
	}
	return nil
}
