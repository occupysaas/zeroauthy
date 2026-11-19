# GitHub connection evidence

Reviewed 2026-11-18 for Plan 39c Task 1. Public documentation only: no live
Auth0 or GitHub request was made. The executable contract is the `github`
sections of `internal/federation/inventory.json`; the decision record is D-0181.

## Auth0 (read 2026-11-18)

Sources: [GitHub social connection](https://auth0.com/docs/authenticate/identity-providers/social-identity-providers/github),
[user profile structure](https://auth0.com/docs/manage-users/user-accounts/user-profiles/user-profile-structure),
[Create a connection](https://auth0.com/docs/api/management/v2/connections/post-connections).

The GitHub page says only "Most applications need Email address for the user's
email and Read user for profile information." The following are **not
documented** and are recorded as unavailable, not confirmed:

- email handling, including a GitHub user without a verified primary email;
- `email_verified` for GitHub users;
- whether `scope` is derived from the boolean flags or stored independently;
- the format of the GitHub `user_id` (the local `github|<numeric id>` follows
  Auth0's general `provider|id` form and the design's ruling).

The option wire names come from the Auth0 .NET SDK `ConnectionOptionsGitHub`,
an SDK source; the Management API reference was not found to contradict it.

## GitHub (read 2026-11-18)

| Fact | URL |
|---|---|
| Scope names `repo`, `repo:status`, `repo_deployment`, `public_repo`, `admin:repo_hook`, `write:repo_hook`, `read:repo_hook`, `admin:org`, `write:org`, `read:org`, `admin:public_key`, `write:public_key`, `read:public_key`, `gist`, `notifications`, `read:user`, `user:email`, `user:follow`, `delete_repo` all exist. `read:user` grants profile data, `user:email` read access to email addresses, `user:follow` follow/unfollow. Every flag-to-scope mapping in the brief matches; no change to the spec table. | [Scopes for OAuth apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps) |
| `code_challenge_method` must be `S256` (`plain` unsupported); `code_verifier` required at the token endpoint when a challenge was sent. `redirect_uri` is "strongly recommended"; if omitted GitHub uses the first registered callback. The page does not mention the `X-OAuth-Scopes` header. | [Authorizing OAuth apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) |
| Token endpoint errors are JSON objects with `error`, `error_description`, `error_uri` (for example `incorrect_client_credentials`, `redirect_uri_mismatch`, `bad_verification_code`, `unverified_user_email`). The page states no HTTP status, so a 200 carrying `error` is **not documented either way**. The local rule (error body is a failure regardless of status) is deliberately defensive. | [Troubleshooting access token request errors](https://docs.github.com/en/apps/oauth-apps/maintaining-oauth-apps/troubleshooting-oauth-app-access-token-request-errors) |
| `GET /user/emails` returns `email`, `primary`, `verified`, `visibility`; statuses 200, 304, 401, 403, 404. OAuth app tokens need `user:email`. | [REST Emails](https://docs.github.com/en/rest/users/emails) |
| `GET /user/emails` for a GitHub App user token needs the "Email addresses" user permission, read. | [Permissions required for GitHub Apps](https://docs.github.com/en/rest/overview/permissions-required-for-github-apps) |
| Supported `X-GitHub-Api-Version` values: `2026-03-10` (released 2026-03-10, end of support not scheduled) and `2022-11-28` (supported until 2028-03-10; the default without the header). **Pinned: `2026-03-10`**, the newest listed. | [API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions) |
| Primary and secondary rate limits both answer `403` or `429`. Primary: `x-ratelimit-remaining: 0` with `x-ratelimit-reset`. Secondary: a `retry-after` header, or `x-ratelimit-remaining: 0`. Recorded as `rate_limit_signals`. | [Rate limits for the REST API](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) |

Previously read facts (callbacks, token response format, expiring tokens, GitHub
App `scope`, PKCE changelog) are in design section 4.

## Remaining unavailable

Live behaviour of GitHub (an error body with HTTP 200) and of Auth0 (the items
above) is unobserved. Neither is claimed as passed.
