# The admin console

zeroauthy ships a web console at `/admin/` on the **system host**. It manages
tenants and their applications through the same public APIs that scripts use
([management-api.md](management-api.md)); it has no private endpoints.

## Where it lives

The console is served by the `system` tenant, zeroauthy's own tenant whose
users are the operators:

- with `server.base_domain: example.com`, at `https://system.example.com/admin/`;
- otherwise at `https://<server.system_host>/admin/`, for example
  `server.system_host: system.localhost:8443` in development.

No other tenant may use that host. The console is built into the binary
(`console/dist`, embedded with `go:embed`), so it needs no Node.js at run
time.

## The first operator

On the server, with the same configuration file as `serve`:

```bash
zeroauthy admin create --email you@example.com --config zeroauthy.yaml
```

It prints a one-time link, valid for one hour. Open it, choose a password
(at least 12 characters), then go to `/admin/` and sign in. Run the command
again for a new link. Automated installs can set
`ZEROAUTHY_BOOTSTRAP__ADMIN_EMAIL`: on a start that finds no operator, the
server creates that one and logs the link once. Passwords are never taken
from configuration.

More operators can be invited from the system API
(`POST /api/system/operators`); every operator manages every tenant for now.

## Signing in

Signing in is an ordinary authorization code flow with PKCE against the
system tenant's hosted login page, for the client `zeroauthy-console`.
The console keeps its tokens in memory only. Reloading a page signs in
again silently through the system tenant's session; signing out ends that
session.

## Screens

- **Header:** the tenant switcher (with "Create tenant"), links to the docs
  and the source, and the account menu (theme, sign out).
- **Home:** the tenant's domain, discovery URL and Management API
  identifier, the number of applications, and a banner when the seed file
  defines the tenant: edits to what the seed defines are overwritten at the
  next start.
- **Applications:** a paged list with a type filter; **Create** asks for a
  name and a type (native, single-page, regular web, machine to machine)
  and applies defaults for that type; each application has
  - **Settings:** domain, client ID and secret (masked, with reveal and
    copy), name, callback, logout and origin URLs. Validation errors from
    the API appear on the field they concern;
  - **Advanced:** grant types, token endpoint authentication, ID token
    lifetime, refresh token rotation and expiration, PAR, and whether it is
    a first- or third-party application (fixed at creation);
  - **Danger zone:** rotate the secret (the old one stops working at once)
    and delete (type the name to confirm).

Applications created in the console are never touched by the seed.

## Security

- Its own Content Security Policy: only its own scripts and styles, no
  inline code, `connect-src` limited to the system host and the tenants'
  hosts, `frame-ancestors 'none'`.
- The Management API and system API accept cross-origin calls only from the
  system host's origin.
- Operator tokens are bound to the console client and checked against the
  stored operator on every request, so removing an operator takes effect
  at once.
- Light and dark themes; every control is keyboard-accessible (target: WCAG
  2.2 AA). English only; the strings live in `console/src/strings.ts`.

## Developing

```bash
make console      # npm ci, lint, typecheck, Vitest, regenerate API types, build dist/
```

The console signs in against the origin it is served from, so try changes
by rebuilding and restarting zeroauthy, then opening `/admin/` on the system
host.

`console/dist` and the generated `console/src/api/schema.d.ts` are committed;
CI rebuilds them and fails on a difference.
