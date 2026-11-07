# Passkeys and WebAuthn

Plan 33b adds passkeys as a first factor on database connections, security
keys and device biometrics as MFA factors, and the native Passkey APIs for
mobile apps. This guide covers setup and the places where zeroauthy decides
something Auth0's documentation leaves open. Each such local ruling has an
`LR33b` number recorded in
[D-0062](compat/decisions.md#d-0062--passkeys-and-webauthn-mfa-contracts-and-local-rulings),
together with what it would cost if Auth0 turns out to behave differently.
For security keys and biometrics as second factors, see also
[Multi-factor authentication](mfa.md).

## Prerequisites

Passkeys belong to a database connection (`strategy: auth0`). Turn them on
with `options.authentication_methods.passkey.enabled: true`. zeroauthy offers
them only when every prerequisite holds; otherwise the stored setting has no
effect (LR33b-1).

| Prerequisite | Where to fix it |
| --- | --- |
| The tenant uses the new Universal Login experience | Prompt settings, `universal_login_experience: new` |
| Identifier First is on | Prompt settings, `identifier_first: true` |
| The connection does not require a username, or flexible identifiers are configured | Connection `requires_username`, or `options.attributes` |
| A custom database connection runs in import mode | Connection `import_mode` |
| Password authentication stays enabled | `options.authentication_methods.password.enabled` (LR33b-2) |

The Management API stores any combination, as it always has; it does not
refuse a passkey setting whose prerequisites are unmet. The console shows
each prerequisite with its status and a link to its setting, and blocks
enabling passkeys until all of them hold. Operators can read the same list
from the extension route
`GET /api/system/tenants/{tenant}/connections/{id}/passkey-prerequisites`
(`{"effective": …, "unmet": ["identifier_first", …]}`).

Turning passkeys off hides existing passkeys at login; it never deletes them.
A passkey does not replace a password or any other credential.

## Relying party IDs and custom domains

Every passkey and WebAuthn key is bound to a relying party (RP) ID, and a
browser only uses it on hosts under that ID. zeroauthy resolves one RP ID
per host (LR33b-4):

- the tenant's canonical host uses itself;
- a verified custom domain uses its `relying_party_identifier`, or the
  domain itself when the field is null;
- an operator alias from the seed `domains` list uses its
  `relying_party_identifier`, or the alias itself.

The RP ID may be the host or any registrable parent of it, for example
`example.com` for `login.example.com`, so that passkeys work across the
customer's own sites and apps. A public suffix such as `com` or `co.uk` is
refused. There is no tenant-wide default RP ID because no Management API
documents one; the console's relying party ID page lists every host with its
effective RP ID and edits the custom-domain field.

Each RP ID has its own passkeys and security keys (LR33b-5). A user who
signs in on two custom domains with different RP IDs enrolls on each.
Changing a domain's RP ID makes credentials created for the old value
unusable on that host; they stay listed in the API and console so you can
remove them, and users enroll again.

**Shared hosting.** By default an RP ID may also be a parent of the
deployment's `server.base_domain`, which suits a single organization hosting
its own login. A deployment that hosts unrelated tenants should set
`security.webauthn.restrict_shared_rp_ids: true`. It then refuses any RP ID
that covers the base domain, the system host, the origin suffix or another
tenant's host. A stored RP ID that this rule or the registrable-suffix rule
refuses is never silently replaced: ceremonies on that host fail closed, the
server logs a warning, and the console marks the domain.

Hosted pages accept only `https://<request host>` as the ceremony origin.
Origins are compared exactly, including the port, and cross-origin or framed
ceremonies are refused.

## Login and signup choices

`options.passkey_options.challenge_ui` chooses how the identifier page
offers passkeys: `autofill` (the browser suggests passkeys in the identifier
field), `button` (a "continue with a passkey" button) or `both`, the default.
Where the browser cannot autofill, the button and the password remain.
Without JavaScript the page is the ordinary identifier page.

The passkey's own user wins over whatever identifier was typed (LR33b-16).
A blocked user is told so; every other failure shows the same generic
message, so the page never reveals whether an account or passkey exists.
After a passkey login, Actions, MFA, organizations and consent run exactly
as after a password login.

Signup splits into an identifier page and a choice between creating a
passkey and creating a password, but only while passkeys are effective
(LR33b-15). A user who signs up with a passkey has no password
(LR33b-36): a password attempt gets the normal wrong-credentials answer,
and they can set one through password reset. Invitation signups never offer
the passkey choice (LR33b-32); progressive enrollment covers those users
later. `/dbconnections/signup` still requires a password (LR33b-3).

## Enrollment prompts

Two optional prompts add passkeys to existing accounts. Both appear after
any MFA the login required and before consent and the redirect, and only
where the browser supports WebAuthn.

- **Progressive enrollment** (`progressive_enrollment_enabled`, default on)
  follows a password login when the user has no passkey for this RP ID.
  "Don't show again" hides it for 30 days for that user and RP ID
  (LR33b-13).
- **Local enrollment** (`local_enrollment_enabled`, default on) follows a
  login with a passkey from another device, such as a phone scanned by QR
  code, when this device has its own platform authenticator. "Don't show
  again" hides it for 30 days for that user in this browser (LR33b-14).

The device-biometrics MFA prompt has "Remind me later" (14 days) and "Not
on this device" (365 days) choices (LR33b-18), and recognizes devices by
their user agent (LR33b-19).

## Security keys and device biometrics

Enable `webauthn-roaming` (security keys) and `webauthn-platform` (device
biometrics) with `PUT /api/v2/guardian/factors/{name}` or in the console.
Device biometrics may be enabled alone, but a user is offered them only after
another confirmed factor (LR33b-20). Both factors use the same RP ID as
passkeys on the host.

Auth0 sets security-key user verification only in its Dashboard. zeroauthy
keeps it in the Guardian configuration (LR33b-22): `discouraged` ("Never",
the default), `preferred` ("If supported") or `required`. Set it in the
console, through the extension route
`PUT /api/system/tenants/{tenant}/guardian/factors/webauthn-roaming/settings`,
or in the seed:

```yaml
tenants:
  - name: acme
    guardian:
      factors: {webauthn-roaming: true, webauthn-platform: true}
      webauthn_roaming: {user_verification: preferred}
```

No Deploy CLI handler carries this setting, so set it again on the target
after a migration.

## Native apps

Native apps use `POST /passkey/register`, `POST /passkey/challenge` and the
token grant `urn:okta:params:oauth:grant-type:webauthn`. The application must
be first party, list that grant in `grant_types`, and call a custom domain
or operator alias; the canonical host answers `400 invalid_request`
(LR33b-25). Without an effective passkey connection, or on a store plugin
without `webauthn.v1`, the endpoints answer `404`.

Describe the app in the client's `mobile` object:

```yaml
clients:
  - client_id: ios-and-android
    app_type: native
    token_endpoint_auth_method: none
    grant_types: [authorization_code, refresh_token, "urn:okta:params:oauth:grant-type:webauthn"]
    mobile:
      ios: {team_id: ABCDE12345, app_bundle_identifier: com.example.app}
      android:
        app_package_name: com.example.app
        sha256_cert_fingerprints: ["AA:BB:…:99"]
```

Each custom domain and operator alias then serves
`/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json`
built from the tenant's first-party passkey clients, or `404` when there are
none (LR33b-27). If the RP ID is a parent domain, publish the same files on
that domain yourself. A native ceremony accepts the request host, the
client's `web_origins` under the RP ID, and Android certificate key hashes
(LR33b-26). Android fingerprints are 32 colon-separated hex bytes; a
malformed entry is ignored when the origins and files are built.

Grant failures answer `400 invalid_grant` and log
`passkey_challenge_failed`. When MFA is required, the grant returns
`mfa_required`, and the following MFA grants log `sepkotpft`, `sepkoobft` or
`sepkrcft` (LR33b-28).

## Limits

| Limit | Value |
| --- | --- |
| Passkeys per user | 20, enforced atomically; the Management API answers `400 invalid_body` for the 21st (LR33b-29) |
| Hosted challenge lifetime | 5 minutes, single use; a failed attempt consumes it (LR33b-6) |
| Native challenge | `timeout` 60000 ms, plus 10 seconds of grace |
| Key nickname | 1–20 characters (LR33b-31) |
| Attestation object, client data, COSE key | 64 KiB, 16 KiB, 16 KiB (LR33b-34) |
| Credential ID | 1023 bytes |

A user handle is 32 random bytes, shared by all of a user's passkeys
(LR33b-7). Registration asks for `none` attestation and accepts the other
known formats without checking them; there is no authenticator allow-list
(LR33b-9). A sign-count that goes backwards is refused (LR33b-10).

## Logs, Actions and the Management API

Hosted passkey login failures log `gd_webauthn_challenge_failed` with
`details.first_factor: true`; native failures log `passkey_challenge_failed`
(LR33b-17). See [logs](logs.md) for every code. In Actions,
`event.authentication.methods` contains `passkey` after a passkey login; a
passkey is not an MFA factor, so it is absent from
`event.user.enrolledFactors`, and the ID token's `amr` does not change
(LR33b-12). See [Actions](actions.md).

`GET /api/v2/users/{id}/authentication-methods` lists passkeys with their RP
ID, sync and backup state and AAGUID. You can rename or delete them, and
`POST` with `type: passkey` imports one; `key_id` and `public_key` are
required and the other fields have defaults (LR33b-23). Linking accounts
moves the secondary user's passkeys to the primary user; unlinking moves
them back (LR33b-24). No `user.updated` event is emitted for passkey changes
(LR33b-33).

Failed WebAuthn MFA attempts count in the MFA throttle. Passkey login
failures spend the login budget of suspicious-IP throttling, a brute-force
block refuses passkey logins too, and a successful passkey login resets the
counter (LR33b-30). See [attack protection](attack-protection.md).

## Seed and Deploy CLI

The seed configures every passkey setting: connection options (as above),
client `mobile` and the grant, Guardian factors and `webauthn_roaming`, and
alias RP IDs:

```yaml
tenants:
  - name: acme
    domains:
      - login.example.com
      - {host: id.example.com, relying_party_identifier: example.com}
```

Client `mobile` and alias RP IDs need a store with `webauthn.v1`; with an
older store plugin the seed fails and names the capability instead of
dropping them. The pinned Deploy CLI 9.1.0 carries client `mobile` and the
grant, database connection passkey options (through its `databases`
handler), custom-domain `relying_party_identifier` and the WebAuthn factor
flags. See [Deploy CLI migration](deploy-cli.md).

## Differences from Auth0

These follow from documentation gaps or conflicts; each is a local ruling
in D-0062, and the spec's ruling table states its cost.

- Unmet prerequisites are not refused by the API (LR33b-1).
- Users enroll per RP ID on every custom domain, not on the first domain
  only (LR33b-5).
- Hosted ceremony pages use `rp.name` equal to the RP ID and a fixed
  five-minute window (LR33b-6).
- Passkey ceremonies request user verification as `preferred` and do not
  require the flag (LR33b-8).
- Registration offers algorithms -8, -7 and -257; assertions also verify
  -35, -36 and -37 keys imported through the API (LR33b-11).
- The MFA API lists WebAuthn authenticators with the factor name as
  `authenticator_type` and refuses to associate or challenge them
  (LR33b-21).
- Customized passkey screen partials are stored but not rendered
  (LR33b-35).
- The new screens use zeroauthy's own `/u/` paths (LR33b-37):
  `/u/login/passkey`, `/u/signup/passkey`, `/u/passkey-enrollment`,
  `/u/passkey-enrollment-local` and the `/u/mfa-webauthn-*` pages.

Points not yet observed against a live Auth0 tenant (exact method IDs, error
bodies, snooze details and log details) are listed as W1–W12 in
[the follow-ups](superpowers/plan-1-followups.md).
