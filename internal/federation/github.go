package federation

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// GitHubEndpoints are GitHub's fixed OAuth endpoints. GitHub issues no ID
// token; UserInfoURL is the REST /user resource.
func GitHubEndpoints() Endpoints {
	return Endpoints{AuthorizationURL: rules.GitHubAuthorizationURL, TokenURL: rules.GitHubTokenURL,
		UserInfoURL: rules.GitHubAPIBase + "/user", TokenAuthMethod: authPost}
}

// GitHubOverride replaces GitHub's fixed endpoints and REST API base for a
// local provider harness. It is set only at construction (WithGitHubFixture);
// no configuration or API reaches it.
type GitHubOverride struct {
	Endpoints Endpoints
	APIBase   string
}

// WithGitHubFixture points github at a local harness; tests and the E2E
// harness only.
func (ps *Providers) WithGitHubFixture(o GitHubOverride) *Providers {
	ps.githubFix = &o
	return ps
}

// github returns the GitHub endpoints and REST API base in use. Connection
// options never reach them.
func (ps *Providers) github() (Endpoints, string) {
	if ps.githubFix != nil {
		e := ps.githubFix.Endpoints
		e.TokenAuthMethod = authPost
		if e.UserInfoURL == "" {
			e.UserInfoURL = ps.githubFix.APIBase + "/user"
		}
		return e, ps.githubFix.APIBase
	}
	return GitHubEndpoints(), rules.GitHubAPIBase
}

// githubEmailEnabled reports the connection's email option. parseGitHub adds
// user:email to the effective scope exactly when email is on, and no other
// option adds it.
func githubEmailEnabled(cfg Config) bool {
	return slices.Contains(cfg.Scopes, "user:email")
}

// githubProvider is GitHub's OAuth app / GitHub App user flow: S256 PKCE, one
// client_secret_post exchange, then the REST profile. There is no ID token.
type githubProvider struct{ ps *Providers }

func (p githubProvider) AuthorizationURL(in StartInput) (string, error) {
	e, _ := p.ps.github()
	in.LoginHint = "" // GitHub's own login parameter is never sent
	return authorizationURL(e.AuthorizationURL, in.Config, in, false)
}

// Exchange redeems the code once and builds the profile. Every error path
// drops the access token; no error carries it or a response body.
func (p githubProvider) Exchange(ctx context.Context, in ExchangeInput) (ProviderResult, error) {
	e, apiBase := p.ps.github()
	tokens, err := p.ps.exchangeCode(ctx, e.TokenURL, authPost, in)
	if err != nil {
		return ProviderResult{}, err
	}
	if !strings.EqualFold(tokens.TokenType, "bearer") {
		return ProviderResult{}, fmt.Errorf("%w: token response token_type is not bearer", ErrProviderResponse)
	}
	profile, err := p.ps.githubUser(ctx, apiBase, tokens.AccessToken)
	if err != nil {
		return ProviderResult{}, err
	}
	if githubEmailEnabled(in.Config) {
		email, err := p.ps.githubEmails(ctx, apiBase, tokens.AccessToken)
		if err != nil {
			return ProviderResult{}, err
		}
		verified := true
		profile.Email, profile.EmailVerified = &email, &verified
	}
	return ProviderResult{Profile: profile, Tokens: tokens}, nil
}
