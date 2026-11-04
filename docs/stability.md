# Stability

zeroauthy 1.0 is an **early preview**. This page is the preview's promise:
what we will try hard not to break between 1.x releases, and what may change.
Breaking changes to anything in the first list need a major version, or, if a
security fix forces one, a clear entry in the [changelog](../CHANGELOG.md).

## Covered

- **The Auth0-compatible HTTP APIs.** The Authentication API (`/authorize`,
  `/oauth/*`, `/userinfo`, `/dbconnections/*`, `/passwordless/*`, logout,
  discovery and JWKS) and the Management API under `/api/v2/`, as listed on
  the [compatibility page](compatibility.md). Where zeroauthy differs from
  Auth0, we may change it to match Auth0's documented behaviour; that is a
  fix, not a break, and it is called out in the changelog.
- **Configuration file keys** and their `ZEROAUTHY_*` environment variables.
  A key may be deprecated with a startup warning before it is removed in a
  major version.
- **The storage plugin protocol** `store.v1` (gRPC, `pkg/storeplugin`), with
  capabilities negotiated at startup. New features arrive as new capabilities;
  a plugin that lacks one keeps working, and the routes needing it answer 501
  or startup tells you which capability is missing.
- **The database upgrade path.** Every 1.x release migrates a database from
  any earlier 1.x release with `zeroauthy migrate`. Migrations are
  forward-only; see [upgrading](upgrading.md).
- **Tokens and keys already issued.** Upgrades keep existing signing keys,
  client secrets, refresh tokens and password hashes valid.

## Not covered

- **The admin console UI**: screens, layout, wording and its routes.
- **zeroauthy's own extension APIs** used by the console, under
  `/api/system/` and `/api/console/`.
- **Internal Go packages** (`internal/...`) and the command-line output
  format. The Go packages under `pkg/` are covered only as far as the
  plugin protocol needs them.
- **Log message text** and the server's own (non-tenant) log fields.
- **Behaviour marked stored-only, preview or not enforced** in the guides.
  Enforcing a stored setting later is not a break.
- **Hosted login page HTML and CSS** beyond the documented branding and
  template variables.

## Supported versions

Security fixes go to the latest 1.x release. See [SECURITY.md](../SECURITY.md).
