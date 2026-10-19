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

More operators can be invited from the **Operators** screen (system tenant
only) or the system API (`POST /api/system/operators`); every operator
manages every tenant for now.

## Signing in

Signing in is an ordinary authorization code flow with PKCE against the
system tenant's hosted login page, for the client `zeroauthy-console`.
The console keeps its tokens in memory only. Reloading a page signs in
again silently through the system tenant's session; signing out ends that
session.

## Screens

- **Header:** the brand (black bar, "authy" in red), the tenant switcher
  (with "Create tenant"), links to the docs and the source, the language
  menu (globe icon) and the account menu (theme, sign out). Below 768px the
  sidebar moves behind a Menu button in the header (a drawer; Escape or a
  link closes it).
- **Sidebar:** one list of sections in groups: Home; Applications
  (Applications, APIs); Authentication (Database, Social); User management
  (Users, Roles, Organizations); Security (Attack protection, Multi-factor);
  Actions; Branding (Universal Login, Email templates, Custom domains);
  Monitoring (Logs); Settings (Tenant settings); System (Operators, system
  tenant only). Items read black and bold; sections that are not built yet
  carry a "Planned" tag.
- **Planned sections:** every section that is not built yet has its own
  page (a direct link works), showing a banner with the slice that will
  deliver it and the Management API it will use, and a disabled preview of
  the page: the fields and tables Auth0's reference lists, with empty states
  and no sample data. Controls do nothing and the pages make no requests;
  only in-page navigation (the Tenant settings tabs, the Email templates
  picker) works. Actions is a placeholder only: triggers, the code editor and
  the deploy flow need their own design.
- **Home:** the tenant's domain, discovery URL and Management API
  identifier, the number of applications, and a banner when the seed file
  defines the tenant: edits to what the seed defines are overwritten at the
  next start. With `seed_mode: create_only` the seed never overwrites, so
  there is no banner.
- **APIs:** a paged list of the tenant's APIs, system ones marked. **Create
  API** asks for a name and an identifier (fixed afterwards). Each API has
  - **Settings:** name, identifier, signing algorithm (RS256, fixed), token
    lifetimes, offline access, skipping consent, and the user and application
    access policies;
  - **Permissions:** the scopes the API defines; removing one that is
    granted to applications asks first and removes it from those grants;
  - **Machine-to-machine applications:** a switch per application of that
    type that authorizes it for the API, the permissions it gets (or all of
    them, including ones added later), and a shortcut to create an
    application;
  - **Danger zone:** delete (type the name or identifier), which also
    deletes the API's grants and users' consents. The tenant's own
    Management API shows only the token lifetimes and cannot be deleted.
- **Connections:** a paged list of the tenant's database connections with the
  number of applications each is enabled for. **Create connection** asks for a
  name (letters, digits, hyphens). Each connection has
  - **Settings:** sign-up and username options; options zeroauthy stores but
    does not act on yet sit in their own group, marked "saved, not enforced
    yet";
  - **Password policy:** length, character types, identical and sequential
    characters, over-long passwords (truncate or refuse; switching to refuse
    locks out users who still type a long one), history, dictionary (en_10k,
    en_100k, your own words), personal data and brute-force protection, with a
    checker that tries a password in the browser (it does not have the embedded
    dictionary lists);
  - **Custom database:** the scripts in an editor, configuration values and
    **Try**. Configuration values are write-only: once saved they are never
    shown again. Try runs the saved script with test arguments and shows the
    result, console output and errors on the page only; configuration values
    in them are replaced with `■■■■■■■■`, but a script that encodes or splits
    a value can still reveal it, and console output is lost when a script
    times out. Ten tries per minute;
  - **Applications:** a switch per application that enables the connection;
  - **Danger zone:** delete (type the name), which shows the user count and
    deletes the connection's users.
- **Applications:** a paged list with a type filter; **Create** asks for a
  name and a type (native, single-page, regular web, machine to machine)
  and applies defaults for that type; each application has
  - **Settings:** domain, client ID and secret (masked, with reveal and
    copy), name, callback, logout and origin URLs. Validation errors from
    the API appear on the field they concern;
  - **Advanced:** grant types, token endpoint authentication, ID token
    lifetime, refresh token rotation and expiration, PAR, and whether it is
    a first- or third-party application (fixed at creation);
  - **Connections:** the database connections the application can sign users
    in with, a switch each;
  - **APIs:** the APIs the application may request tokens for, with the
    permissions it has for each; authorize another, change permissions or
    revoke;
  - **Quick start:** snippets with the application's details filled in. A
    machine-to-machine application gets the token request and a call with it
    for each API it is authorized for; other types get the authorization URL
    and configuration for auth0-spa-js, auth0-react, nextjs-auth0 and
    express-openid-connect. The secret appears only after you reveal it. The
    panel reminds you to enable a connection in the Connections tab, since
    no user can sign in with an application until you do;
  - **Danger zone:** rotate the secret (the old one stops working at once)
    and delete (type the name to confirm).
- **Operators** (system tenant): the operators, **Invite operator** (shows a
  one-hour link once) and remove (never the last one).

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
- Light and dark themes (system, light or dark, chosen in the account menu
  and kept in the browser); every control is keyboard-accessible (target:
  WCAG 2.2 AA).
- Language: English only for now. The strings live in the vue-i18n catalog
  `console/src/locales/en.ts`; the globe menu lists the available languages
  and keeps the choice in the browser, so a second language is a new
  catalog file (the parity test checks it has every key).
- Font: Glacial Indifference (Regular and Bold) by Alfredo Marco Pradil,
  SIL Open Font License 1.1, converted to WOFF2 and bundled; the license
  text ships as `assets/OFL.txt` next to the fonts and is listed in `NOTICE`.

## Developing

```bash
make console      # npm ci, lint, typecheck, Vitest, regenerate API types, build dist/
```

State lives in Pinia stores (tenants, preferences, session; tokens are never
stored in one), styling is Tailwind v4 over theme tokens, and the sections
are defined once in `console/src/layout/sections.ts`, which drives the
sidebar and the routes. To ship a planned section, set its status to live
and replace its preview.

The console signs in against the origin it is served from, so try changes
by rebuilding and restarting zeroauthy, then opening `/admin/` on the system
host.

`console/dist` and the generated `console/src/api/schema.d.ts` are committed;
CI rebuilds them and fails on a difference.
