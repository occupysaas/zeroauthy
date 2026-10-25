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
  link closes it); the Docs and Source links move to the bottom of the drawer and
  the tenant and account chips shorten, so the header never scrolls sideways.
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
  only in-page navigation (such as the Email templates picker) works. Actions is a placeholder only: triggers, the code editor and
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
- **Users:** a paged list (50 a page; only the first 1000 results can be
  paged through) with columns for name and email, connection, logins, last
  login and a Blocked tag, sortable by clicking the headings. The search box
  takes Auth0's v3 query syntax (`name:ada`, `blocked:true`,
  `app_metadata.plan:pro`); the help button beside it lists examples and links
  to the [query guide](user-search.md). A connection filter narrows the list.
  **Create user** asks for a connection, an email (and a username when the
  connection requires one), a password, checked as you type against the
  connection's rules, and whether to send the verification email. Each user has
  - **Details:** the user ID, created date, email and phone (the phone is only
    stored; no code is sent to it), and the profile: name, given name, family
    name, nickname and picture URL. **Actions** blocks or unblocks the user,
    changes the password or email, creates a password-change link or a
    verification link (shown once), queues a verification email and deletes
    the user (type the name). Blocking does not end
    sessions or refresh tokens the user already holds; revoke them in the
    Sessions tab;
  - **Metadata:** `user_metadata` and `app_metadata` as JSON. **Review changes**
    shows what was added, changed and removed before it is sent. `app_metadata`
    is read-only when your account cannot change it;
  - **Identities:** the user's linked identities, **Unlink** for each
    secondary, and **Link another user**, which searches database users to
    merge into this one (the other user stops existing as a separate user);
  - **Sessions and devices:** sign-in sessions and refresh tokens with
    device, IP address and applications, revoked one by one or all at once.
    Ending sessions leaves refresh tokens alone, and the reverse;
  - **Authorized applications:** the users' grants (consents), each revocable;
  - **Raw JSON:** the user as the API returns it.
- **Operators** (system tenant): the operators, **Invite operator** (shows a
  one-hour link once) and remove (never the last one).

Applications created in the console are never touched by the seed. Users are managed through the same Management API ([management-api.md](management-api.md#users)) the console calls.

## Import and export

Open **Users → Import and export**. Select a JSON file and a database
connection; custom databases appear only in import mode. Choose whether to
upsert existing users and send completion email. The file picker refuses
files above 511000 bytes, leaving room for multipart framing within the
server's 512000-byte request limit. The jobs list polls pending work every three
seconds while the page is visible, shows the final summary and weak-hash
count, and opens masked errors with their codes and paths.

For export, choose one connection or all, CSV or newline-delimited JSON,
an optional limit, and fields. Add metadata subfields and output names as
needed (30 fields maximum). **Download** fetches a fresh short-lived URL on
every click. Job history and files are retained for 24 hours. User detail's
**Actions → Send verification email** queues a job; the list shows its result.
See [user-import.md](user-import.md) for supported hashes and reset advice.

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
  catalog file (`console/src/locales/parity.test.ts` finds every catalog and
  checks it has exactly the English keys).
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


## Tenant settings and protection

**Tenant settings** is live: General, Sessions, Languages and Advanced tabs
save only edited fields. Session units are explicit; hosted language choices
are independent of console language. Stored-only settings and seed overwrite
behavior are labeled. See [tenant-settings.md](tenant-settings.md).

**Attack protection** is live with five independently saved feature panels,
checker-availability information and IP anomaly lookup/unblock. CAPTCHA
credential inputs stay blank after save; editing a provider requires complete
replacement credentials. Unsupported providers and deferred notifications
remain labeled. Tenant switches discard dirty state and ignore stale replies.

User detail's **Automatic blocks** controls inspect and clear login blocks,
with confirmation, separately from administrative Block. See
[attack-protection.md](attack-protection.md#inspect-unblock-and-recover) for
recovery using an independent Management client if console login is blocked.
