# Branding, themes and prompts — observation availability

- **Recorded:** 2026-10-25
- **Status:** Upstream behavior unavailable in this implementation workspace. No authorized separate observer session or tenant credentials were supplied here; no upstream Management request was made.
- **Scope requested of a future separate observer:** documented `GET/PATCH /api/v2/branding`, `GET/PUT/DELETE /api/v2/branding/templates/universal-login`, `POST/GET/PATCH/DELETE /api/v2/branding/themes`, `GET/PATCH /api/v2/prompts`, `GET/PUT /api/v2/prompts/{prompt}/custom-text/{language}`, and `GET/PUT /api/v2/prompts/{prompt}/partials` on a tenant the maintainer owns. Confirm status/media type, fields, scopes, empty/null, default theme activation/deletion, template tag validation, partial replacement and quota behavior. No dashboard/hosted-page capture or undocumented endpoint.
- **Public references:** https://auth0.com/docs/api/management/v2/branding/post-branding-theme ; https://auth0.com/docs/api/management/v2/branding/put-universal-login ; https://auth0.com/docs/api/management/v2/prompts/put-partials ; https://auth0.com/docs/customize/login-pages/universal-login/customize-signup-and-login-prompts .
- **Implementation distinction:** `internal/brandingrules/inventory.json` labels documented and local choices. This file records no observed upstream defaults or successful upstream tests.
