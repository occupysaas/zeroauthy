# Plan 33b — Passkeys as a first factor and WebAuthn MFA

**Date:** 2026-11-05. **Status:** design; not implemented.

**Predecessors:** [Plan 33 MFA](2026-11-02-zeroauthy-mfa-design.md) (its §6 is
the starting design refined here) and [Plan 34 passwordless and
phone](2026-11-03-zeroauthy-passwordless-phone-design.md). Roadmap entry:
[v1 release scope §4 item 2](2026-11-02-zeroauthy-v1-release-scope.md) and
[management roadmap, Plan 33](2026-10-19-zeroauthy-management-roadmap-design.md).
Read the [clean-room policy](../../../CLEAN_ROOM.md), `AGENTS.md`, the
[MFA guide](../../mfa.md), the [custom domains guide](../../custom-domains.md),
the [Actions guide](../../actions.md) and the [logs guide](../../logs.md).

## 1. Outcome and scope

An operator turns on passkeys for a database connection, and users sign up
and log in with a passkey on the hosted login pages, using the browser's
autofill, a "continue with a passkey" button, or both. Users who log in with
a password are offered a passkey after login. A user who logs in on a new
device with a passkey from their phone is offered a passkey on the new
device. Native and embedded apps sign users up and in through Auth0's
Passkey APIs (`/passkey/register`, `/passkey/challenge` and the
`urn:okta:params:oauth:grant-type:webauthn` grant). Operators turn on the
Guardian factors `webauthn-roaming` (security keys) and
`webauthn-platform` (device biometrics), and users enrol and are challenged
on the hosted MFA pages. Operators see and remove passkeys and WebAuthn
authenticators through the Management API and the console.

**Rule:** strict 1:1 with Auth0's documented behaviour. The maintainer has
not used passkeys and ruled "go by the documentation": every behaviour below
traces to an Auth0 page, the W3C WebAuthn recommendation, the Management API
OpenAPI, the logs schema, or a numbered local ruling (**LR33b-n**, §13). Local
rulings are recorded in **D-0062**. Tenant observation is optional, as for
Plans 32–34: each undocumented point has a local answer now and an
"observe later" entry (**W1–Wn**, §13).

### In scope

1. **Connection passkey policy.** `options.authentication_methods.passkey.enabled`
   and `options.passkey_options` (`challenge_ui`, `progressive_enrollment_enabled`,
   `local_enrollment_enabled`) on `auth0` database connections stop being
   stored-only (D-0042) and drive hosted login, subject to Auth0's documented
   prerequisites (§3.1).
2. **Hosted passkey login** on the `login-id` screen: autofill (conditional
   mediation), the passkey button, or both.
3. **Hosted passkey signup**: identifier first (`signup-id`), then the
   `passkey-enrollment` screen, with "create a password instead".
4. **Progressive enrollment** (`passkey-enrollment` after a password login)
   and **local enrollment** (`passkey-enrollment-local` after a cross-device
   passkey login), with their skip and "don't show again" choices.
5. **Relying party IDs** per host: canonical host, each verified custom
   domain, and the custom domain's `relying_party_identifier` (stored since
   Plan 23, now enforced).
6. **WebAuthn MFA:** `webauthn-roaming` with the user-verification setting
   (never / if supported / required); `webauthn-platform` with progressive
   device enrollment and device recognition; hosted enrollment, challenge,
   nickname, success and error screens; remember browser; recovery;
   enrollment tickets; the reset-password MFA challenge screens; Actions
   `challengeWith*`/`enrollWith*` with WebAuthn factors.
7. **MFA API:** WebAuthn authenticators are listed and removable, never
   enrolled or challenged (documented limitation).
8. **Native Passkey APIs:** `POST /passkey/register`, `POST /passkey/challenge`,
   the passkey grant on `/oauth/token` (including `mfa_required`), client
   `grant_types` and `mobile` settings, and the hosted
   `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json`
   files on custom domains.
9. **Management API:** `passkey` authentication methods on
   `/users/{id}/authentication-methods` (list, get, rename, delete, create per
   the current OpenAPI), exclusion of passkeys from the MFA-only operations,
   client `mobile` and the passkey grant type, and the WebAuthn rows of the
   existing Guardian routes.
10. **Actions:** `passkey` in `event.authentication.methods`, the WebAuthn
    factors in `event.user.enrolledFactors`, `api.authentication.*` and
    `api.multifactor.enable` with WebAuthn factors, `oauth2-webauthn` as
    `event.transaction.protocol`.
11. **Logs and events:** `gd_webauthn_enrollment_failed`,
    `gd_webauthn_challenge_failed`, `passkey_challenge_started`,
    `passkey_challenge_failed`, `sepkotpft`, `sepkoobft`, `sepkrcft`, the
    documented passkey details on `s`, `ss` and `gd_enrollment_complete`,
    plus the Plan 33 success codes `seotpft`, `seoobft`, `sercft` that share
    the same grant dispatch; `user.updated` when `multifactor` changes.
12. **Storage, `webauthn.v1` plugin capability, console, seed, Deploy CLI,
    docs, E2E.**

### Not in scope

- **My Account API** passkey enrollment, listing and deletion
  (`/me/v1/authentication-methods`, `type: "passkey"`) and consumer portals:
  Plan 42. The native "enrollment flow" in Auth0's Passkey API page is a My
  Account call, so it moves with Plan 42. The verifier and storage built here
  are what Plan 42 reuses; nothing here is designed for it beyond that.
- **ACUL** WebAuthn and passkey screens: Plan 44.
- **`webauthn_platform_first_factor`** ("Identifier First + Biometrics"):
  stored only, Plan 44 (roadmap: "WebAuthn-first … on hosted pages"). Its
  `login-password` key `useBiometricsText` is not rendered.
- **Passkeys on custom databases without import mode** (Auth0 Early Access,
  needs the custom-database `context` argument, Plan 40). Custom databases
  *with* import mode are in scope (users live in zeroauthy after the first
  login).
- **EA connection methods** `email_otp` and `phone_otp` in
  `authentication_methods`: stay stored-only.
- **Passkey prompt partials** (`passkeys` partial group): stored only, as the
  four Plan 22 slots do not include passkey screens.
- **Dashboard and operator console sign-in with WebAuthn** (Auth0 has it for
  its own dashboard; zeroauthy operators are out of scope).
- **Attestation verification and authenticator allow lists** (FIDO Metadata
  Service): Auth0 documents none.
- **Experiments** targeting `passkey_enrollment` (`AuthenticationFlowEnum`).

### Anti-goals

- An assertion accepted for the wrong origin, RP ID, tenant, transaction or
  user. There is no fallback path that relaxes an origin or RP ID check.
- A passkey or WebAuthn path that bypasses MFA policy, Actions, blocked
  users, organization rules, attack protection on password steps, or the
  hosted CSRF/transaction binding that password logins obey.
- Enrollment of a new credential by someone who has not completed every
  factor the login required (account takeover via enrollment).
- Any `clientDataJSON`, attestation object, signature, `auth_session`,
  challenge or user handle in a log line, event body, Action event or console
  response. Public keys and credential IDs appear only where the Management
  API documents them.
- A new Go module. CBOR, COSE and signature checks use the standard library.

## 2. Evidence

Fetched on 2026-11-04 as Markdown from the published docs (`<url>.md`). Task 1
re-fetches, freezes the contract in `internal/webauthnrules/inventory.json`
(every rule with its URL) and records D-0062.

| Contract | Primary source | Stage |
| --- | --- | --- |
| Passkeys overview: sync, 20 per user, coexistence with passwords, autofill vs button, MFA after passkey, MCD, RP ID | [Passkey Authentication for Database Connections](https://auth0.com/docs/authenticate/database-connections/passkeys) | GA (2024-01-31) |
| Prerequisites, `challenge_ui`, progressive (30-day delay) and local enrollment, RP ID customization, MFA bypass via Action | [Enable and Configure Passkey Authentication](https://auth0.com/docs/authenticate/database-connections/passkeys/configure-passkey-policy) | GA; custom DB without import EA |
| Passkey log codes and details | [Monitor Passkey Events in Tenant Logs](https://auth0.com/docs/authenticate/database-connections/passkeys/monitor-passkey-events-in-tenant-logs) | GA |
| Native/embedded flows, request/response bodies, `authn_params_public_key`, `auth_session`, grant, device settings, `.well-known` files, origins | [Passkey APIs for Embedded Applications](https://auth0.com/docs/authenticate/database-connections/passkeys/passkey-apis) (same content at `…/native-passkeys-for-mobile-applications`) | no stage banner; see K9 |
| `/passkey/register` | [Register a New User With a Passkey](https://auth0.com/docs/api/authentication/passkey/register) | as above |
| `/passkey/challenge` | [Start a Passkey Challenge](https://auth0.com/docs/api/authentication/passkey/challenge) | as above |
| Passkeys with multiple custom domains | [Passkeys with Multiple Custom Domains](https://auth0.com/docs/customize/custom-domains/multiple-custom-domains/passkeys), [Multiple Custom Domains § Limitations](https://auth0.com/docs/customize/custom-domains/multiple-custom-domains) | MCD GA (2026-04-08) |
| WebAuthn MFA overview, roaming vs platform, progressive device enrollment | [FIDO Authentication with WebAuthn](https://auth0.com/docs/secure/multi-factor-authentication/fido-authentication-with-webauthn) | GA (2021) |
| Security keys: UV setting, RP ID, device support, MFA API limitation | [Configure WebAuthn with Security Keys for MFA](https://auth0.com/docs/secure/multi-factor-authentication/fido-authentication-with-webauthn/configure-webauthn-security-keys-for-mfa) | GA |
| Device biometrics: not the only factor, device recognition, one device per type, progressive-only | [Configure WebAuthn with Device Biometrics for MFA](https://auth0.com/docs/secure/multi-factor-authentication/fido-authentication-with-webauthn/configure-webauthn-device-biometrics-for-mfa) | GA |
| Biometrics snooze durations (borrowed, LR33b-18) and enumeration stance | [WebAuthn with Device Biometrics for Passwordless](https://auth0.com/docs/authenticate/login/auth0-universal-login/passwordless-login/webauthn-device-biometrics) | GA; first-factor use is Plan 44 |
| Factor list | [MFA factors](https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors) | GA |
| Actions: skip MFA after passkey | [post-login trigger § Reduce friction with passkeys](https://auth0.com/docs/customize/actions/explore-triggers/post-login) | GA |
| Actions members and allowed factor values | [post-login API object](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-api-object), [post-login event object](https://auth0.com/docs/customize/actions/explore-triggers/signup-and-login-triggers/login-trigger/post-login-event-object) (`oauth2-webauthn` protocol) | GA |
| Prompt, screen and text key names | [Customize Universal Login text](https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements) (`login-id`, `passkeys`, `mfa-webauthn`, `reset-password` accordions) | GA |
| Identifier First | [Identifier First Authentication](https://auth0.com/docs/authenticate/login/auth0-universal-login/identifier-first) | GA |
| Management API | [Management API OpenAPI](https://auth0.com/docs/oas/management/v2/management-api-oas.json): `ConnectionAuthenticationMethods`, `ConnectionPasskeyOptions`, `ConnectionPasskeyChallengeUIEnum`, `UserAuthenticationMethod`, `CreateUserAuthenticationMethodRequestContent`, `CreatedUserAuthenticationMethodTypeEnum` (includes `passkey`), `CredentialDeviceTypeEnum`, `AuthenticationMethodTypeEnum`, `GuardianFactorNameEnum`, `UserEnrollmentAuthMethodEnum`, `GuardianEnrollmentFactorEnum`, `CustomDomain.relying_party_identifier`, `ClientMobile*`, `SessionAuthenticationSignal`, prompt/screen enums | GA (route lifecycle) |
| Management API usage | [Manage Authentication Methods with Management API](https://auth0.com/docs/secure/multi-factor-authentication/manage-mfa-auth0-apis/manage-authentication-methods-with-management-api) | GA |
| MFA API authenticator list | [Authentication API OpenAPI](https://auth0.com/docs/oas/authentication/authentication-api-oas.json) `/mfa/authenticators` | GA |
| Logs | [logs schema](https://auth0.com/docs/oas/tenant-logs/logs-schema.json): `gd_webauthn_challenge_failed`, `gd_webauthn_enrollment_failed` (`details.first_factor`, `failure_details`), `passkey_challenge_started`/`_failed` (`details.purpose`: `register`/`login`), `sepkotpft`, `sepkoobft`, `sepkrcft` | GA |
| Events | `internal/eventrules/catalog.json` (Plan 32 frozen catalog: `oauth2-webauthn` protocol, `multifactor`) | — |
| Request shapes | MIT [`@auth0/auth0-auth-js`](https://github.com/auth0/auth0-auth-js) 1.16.1 (pinned in `tests/e2e`): `PasskeyClient.register`, `.challenge`, `.getTokenByPasskey` (sends `authn_response` as a JSON **string** in a form body) | — |
| WebAuthn | [W3C WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/) §§5, 6, 7 and [Level 3](https://www.w3.org/TR/webauthn-3/) (BE/BS flags, `authenticatorAttachment`, conditional mediation, `topOrigin`) | REC / CR |
| Encodings | RFC 8949 (CBOR), RFC 9052/9053 (COSE), RFC 8230 (COSE RSA), RFC 8032 (Ed25519), FIPS 186-4 (ECDSA) | — |
| Apple/Google association files | Apple "Supporting associated domains" (`webcredentials`), Google Digital Asset Links (`delegate_permission/common.get_login_creds`) | — |

**Changelog.** `docs/compat/changelog-review.md` records coverage through
2026-10-27 (Plan 29). For this spec the full
[changelog text](https://auth0.com/changelog/llms-full.txt) was read on
2026-11-04 (newest entry 2026-10-30). Passkey and WebAuthn entries, in our
words:

| Date | Entry | Effect |
| --- | --- | --- |
| 2020-11-09 / 2021-02-10 / 2021-03-31 | WebAuthn security keys and device biometrics for MFA, beta then GA | §6 |
| 2021-05-28 | WebAuthn device biometrics as a first factor GA | Plan 44 (`webauthn_platform_first_factor`) |
| 2023-09-07 / 2024-01-31 | Passkeys EA, then GA, with progressive enrollment and custom-DB lazy migration | §§3–5 |
| 2025-02-06 (v202505) | ACUL screens `passkey-enrollment`, `passkey-enrollment-local`; identifier-first with passkeys | names only; ACUL is Plan 44 |
| 2025-05-27 (v202521) | ACUL WebAuthn MFA and reset-password WebAuthn challenge screens | screen names in §6.4 |
| 2025-06-05, 2025-10-01 (v202523, v202538) | My Account passkey enrollment and management (Limited EA); Organizations with native passkeys (Limited EA) | Plan 42; `organization` on native endpoints (§7) |
| 2025-07-21 (v202526) | Passkeys on custom databases without import mode (EA) | not in scope |
| 2026-03-10 / 2026-06-01 | Custom RP ID for passkeys EA, then GA | §3.2 |
| 2026-04-02 (v202609) | Passkey screens in customized prompts | partials stored only |
| 2026-04-08 (v202614) | MCD GA, including passkey enrollment on custom domains | §3.2, K1 |
| 2026-10-27 (v202644) | Consumer portals with passkey enrollment | Plan 42 |

Task 1 writes the review row (coverage 2026-10-30) to the changelog review.

**General rules hold** (Plan 33 §2): tenant-scoped IDs, cross-tenant
references behave as missing, live operator grant checks, strict body
parsing, pagination conventions, `x-source` entries, regenerated
API/protobuf/console outputs, current Go toolchain and Node pins. **No new Go
module.**

## 3. Documented behaviour and rules

### 3.1 Connection passkey policy

| Documented behaviour | Rule |
| --- | --- |
| Passkeys are an authentication method of **database** connections; enabled by `authentication_methods.passkey.enabled`; options `challenge_ui` (`both`, `autofill`, `button`), `progressive_enrollment_enabled`, `local_enrollment_enabled` (OpenAPI; defaults from D-0042: disabled, `both`, true, true) | Only `strategy: auth0`. Values already stored and returned since D-0042; shapes unchanged. |
| Tenant prerequisites: Universal Login, Identifier First, no custom (classic) login page | **Effective** only when the tenant prompt settings are `universal_login_experience: new` and `identifier_first: true`. zeroauthy has no classic custom login page (D-0039 ignores `custom_login_page_on`), so that prerequisite always holds. |
| Connection prerequisites: `requires_username` off **or** flexible identifiers on; custom database off **or** import mode on; passwords still enabled | Effective only when `!requires_username \|\| attributes` present (Plan 34 flexible identifiers); `!enabledDatabaseCustomization \|\| import_mode`; `authentication_methods.password.enabled != false`. |
| Dashboard disables Save until prerequisites hold | **LR33b-1:** the Management API accepts and stores any combination (API behaviour undocumented; D-0042 stores these keys verbatim). The server computes `connrules.PasskeyPolicy(conn, prompts) (Policy, []Unmet)`; passkeys are offered only when effective. The console shows the prerequisite list and blocks enabling while any is unmet. |
| Passkeys do not replace or invalidate existing credentials | A passkey enrollment never touches the password hash or other methods. |
| Limit of 20 passkeys per user | Enforced atomically in the store on every passkey create (hosted, native, Management API). Error key `passkey-enrollment-max-allowed-reached`. |
| `password.api_behavior` (`required`/`optional`, GA in OAS) and `signup_behavior` (EA) | **LR33b-3:** stored only; semantics undocumented. `/dbconnections/signup` keeps requiring a password. |
| Organization invitation signups cannot choose passkeys; progressive enrollment covers them | The invitation signup page never shows the passkey choice. |

A passkey belongs to one user and records the identity it was created for
(`identity_user_id`, the database identity's `user_id`). It is usable only
through a connection on which passkeys are effective at login time; turning
passkeys off hides passkeys without deleting them (existing data untouched).

### 3.2 Relying party ID and origins

| Documented behaviour | Rule |
| --- | --- |
| A passkey is bound to the RP ID; changing domain or RP ID makes old passkeys unusable and users re-enroll | Every credential stores its RP ID. Ceremonies list and accept only credentials whose stored RP ID equals the request's **effective RP ID**. Rows with another RP ID are kept, shown in the API and console, and never deleted automatically. |
| Default RP ID is the custom domain; `CustomDomain.relying_party_identifier` sets another (any registrable suffix of the origin; `null` falls back to the full domain); max 255; `format: hostname` | `rpid.For(resolved) string`: canonical host → the canonical host; verified custom domain → its `relying_party_identifier`, else the domain itself. Validation at write (Plan 23 already): normalized DNS name, equal to or an ancestor of the domain, not a public suffix (pinned PSL). **LR33b-4 (added):** also refuse an RP ID that equals or is an ancestor of the deployment's system host, base domain or origin suffix (`400 invalid_body`). |
| Dashboard "Tenant Settings → Relying Party IDs", including "default for your tenant" | **LR33b-4:** no Management API documents a tenant-level RP ID, so there is none. The console's Relying Party IDs view lists every host and its effective RP ID and edits the documented custom-domain field. K5. |
| Security keys/biometrics: RP ID can be set only with a custom domain; if the custom domain changes, update the RP ID | Same resolver for MFA and passkeys; one source of truth. |
| MCD: each custom domain has its own RP ID and its own passkeys; a roaming key enrolled on domain A, used on domain B, leads to a new enrollment screen | **LR33b-5:** per-RP-ID enrollment for passkeys and WebAuthn MFA. Another statement ("only the first domain") conflicts: K1. |
| The application's origin must be in Allowed Origins (CORS)/Allowed Web Origins for an RP ID to work (embedded/native) | Native and embedded origins: §7.3. Hosted pages accept exactly `https://<request host>`. |

Origin checks are exact string comparisons of the serialized origin
(scheme, host, port). `crossOrigin: true` and any `topOrigin` are refused on
every ceremony (hosted pages are never meant to run WebAuthn in a frame).

### 3.3 Hosted passkey login

| Documented behaviour | Rule |
| --- | --- |
| Login UI asks for the identifier and/or a passkey; `challenge_ui` picks autofill, button, or both | The `login-id` page gains, when passkeys are effective for the transaction's database connection: `autocomplete="username webauthn"` on the identifier input and a conditional `get` (autofill) when `challenge_ui` is `both`/`autofill`; a button (text key `passkeyButtonText`) when `both`/`button`. |
| If autofill is unavailable, the user uses the button (if enabled) or the password | Feature detection in the page script; with `autofill` only and no conditional support the page is a plain identifier page. Without JavaScript nothing changes. |
| After passkey authentication, MFA still applies by default; an Action may skip it | The login continues exactly as after a password: Actions, `mfa.Decide`, consent, organizations. |
| Errors: `passkey-not-allowed`, `no-passkey`, `passkey-authentication-failed`, `invalid-passkey`, `conflict-password-passkey`, `password-not-allowed` | Rendered on `login-id` from the i18n catalog (our own English text). |

Identity resolution (**LR33b-16**): the assertion's credential ID is looked
up in the tenant; the credential's user is the user, whatever identifier was
typed. The user must belong to a database connection enabled for the client
with passkeys effective and `rp_id` must match; blocked users get
`user-blocked` (the passkey already proved possession). Every other failure
is the generic `passkey-authentication-failed`, so no answer reveals whether
an account or credential exists.

### 3.4 Hosted passkey signup

| Documented behaviour | Rule |
| --- | --- |
| Signup asks for the email first, then offers to create a passkey; the credential manager may offer a QR code for another device | Identifier-first signup: `signup-id` → `passkey-enrollment` (prompt `passkeys`). Keys `createButtonText`, `usePasswordButtonText` ("create a password"), `backButtonText`, errors `email-in-use`, `auth0-users-validation`, `passkey-enrollment-failure`, … |
| "Create a password" | Leads to `signup-password`, then the existing Plan 22/34 signup rules. |
| Signup with a passkey registers the passkey as the primary method; `ss` carries `details.authentication_methods: ["passkey"]` | The user is created **without a password** (empty hash), with the passkey, in one store transaction after `pre-user-registration` succeeds. Email verification, `post-user-registration`, `ss` and `user.created` as for any signup. |

**LR33b-15:** the split `signup-id`/`passkey-enrollment`/`signup-password`
flow is used only when passkeys are effective; otherwise the existing single
signup page stays (Auth0's split for identifier-first without passkeys is not
built here). A passkey-only user's password login fails with the normal
wrong-credentials answer; they may set a password through reset.

### 3.5 Progressive and local enrollment

| Documented behaviour | Rule |
| --- | --- |
| Progressive: after an identifier-and-password login, offer a passkey if the user has none; skippable; the user can delay it every 30 days; default on | Offered after the login's MFA is satisfied (or not required), before consent and the redirect, when `progressive_enrollment_enabled`, the login's first factor was `pwd`, the user has no passkey for the effective RP ID, has fewer than 20 passkeys, and is not snoozed. `continueButtonText` skips for this login; `checkboxText` ("don't show again") snoozes for **30 days per user per RP ID** (LR33b-13). |
| Local: after a login with a **cross-device** passkey, offer a passkey on this device; skippable; default on | Offered after MFA when `local_enrollment_enabled`, the assertion's `authenticatorAttachment` was `cross-platform` (WebAuthn L3), and the page script reports a user-verifying platform authenticator. `excludeCredentials` lists the user's credentials for the RP ID; `authenticatorAttachment: "platform"`. "Don't show again" snoozes 30 days per user per browser (LR33b-14). |
| Both screens show only where WebAuthn works | The page script auto-continues (skip, no snooze) when `PublicKeyCredential` or the platform check is missing. |
| Successful enrollment logs `gd_enrollment_complete` with `details.authenticator.type: "passkey"`; failure logs `gd_webauthn_enrollment_failed` with `details.authentication_methods: ["passkey"]` | As documented. |

Enrollment is bound to the hosted transaction, its browser cookie and CSRF
token, and is reachable only after every factor the login required. Back or
refresh after completion shows the session-expired page (Plan 33 rule).

## 4. WebAuthn verification design (`internal/webauthn`)

Refines Plan 33 §6. Pure functions, no storage, no HTTP. Callers pass the
expected values; the package returns typed results or an error with a
bounded **reason code** (used in logs and tests, never shown verbatim).

### 4.1 API

```go
type CreationOptions struct { // rendered as PublicKeyCredentialCreationOptionsJSON
    Challenge []byte; RPID, RPName string; UserID []byte; UserName, DisplayName string
    Algs []int64 // default -8, -7, -257 in that order
    Attachment string // "", "platform", "cross-platform"
    ResidentKey, UserVerification string; Exclude []Descriptor; Timeout time.Duration
}
type RequestOptions struct { Challenge []byte; RPID, UserVerification string; Allow []Descriptor; Timeout time.Duration }

type Expect struct {
    Challenge []byte; RPID string; Origins []string // exact allowed origins
    RequireUV bool; Algs []int64 // registration only
}
type Registration struct {
    CredentialID, PublicKeyCOSE []byte; Alg int64; AAGUID [16]byte
    SignCount uint32; UV, BE, BS bool; Format string; Transports []string
    Attachment string
}
type Assertion struct { CredentialID, UserHandle []byte; SignCount uint32; UV, BE, BS bool; Attachment string }
type Stored struct { PublicKeyCOSE []byte; SignCount uint32; BE bool; UserHandle []byte }

func ParseCredentialJSON(raw []byte) (*Credential, error) // PublicKeyCredential JSON (base64url fields)
func VerifyRegistration(c *Credential, e Expect) (*Registration, error)
func VerifyAssertion(c *Credential, e Expect, s Stored) (*Assertion, error)
```

`ParseCredentialJSON` accepts the documented `authn_response` shape
(`id`, `rawId`, `type: "public-key"`, `authenticatorAttachment`,
`response.{clientDataJSON, attestationObject | authenticatorData, signature,
userHandle}`, `response.transports`, `clientExtensionResults`). `id` must
equal `rawId`; base64url without padding (padding tolerated on input).

### 4.2 Bounded CBOR and COSE

- CBOR (RFC 8949 subset): unsigned/negative integers, byte and text strings,
  arrays, maps, simple values `false`/`true`/`null`. No tags, floats,
  indefinite lengths or undefined. Map keys are integers or text; duplicate
  keys rejected; trailing bytes rejected. Depth ≤ 16; item count ≤ 1024;
  attestation object ≤ 64 KiB; `clientDataJSON` ≤ 16 KiB; credential ID ≤ 1023
  bytes (L3); COSE key ≤ 16 KiB. Fuzzed (`go test -fuzz`) with a seed corpus.
  The existing `internal/mgmt/mfa_cose.go` reader moves into this package and
  `validStoredCOSE` calls it, so stored and verified keys share one parser.
- COSE keys: OKP Ed25519 (`kty 1`, `crv 6`, `alg -8`); EC2 P-256 (`-7`),
  P-384 (`-35`), P-521 (`-36`), uncompressed points checked on curve; RSA
  (`kty 3`) `-257` (PKCS#1 v1.5 SHA-256) and `-37` (PSS SHA-256), modulus
  2048–8192 bits, public exponent odd and > 1. Private-key labels rejected.
  Registration accepts only the algorithms offered (`-8`, `-7`, `-257`);
  assertions also verify `-35`, `-36`, `-37` keys created through the
  Management API (**LR33b-11**).

### 4.3 Registration checks (L2 §7.1, L3 additions)

1. `type == "public-key"`; client data JSON is UTF-8 JSON with
   `type == "webauthn.create"`, `challenge` equal (constant time) to the
   expected challenge, `origin` in `Expect.Origins`, `crossOrigin` absent or
   false, `topOrigin` absent. `tokenBinding` ignored.
2. Attestation object `{fmt, attStmt, authData}`; `authData` ≥ 37 bytes:
   `rpIdHash == SHA-256(RPID)`; UP set; UV set when `RequireUV`; AT set;
   BS set without BE rejected; ED extensions parsed with the bounded CBOR
   decoder and ignored; attested credential data parsed exactly (AAGUID,
   length, ID, COSE key) with no unparsed tail.
3. Algorithm in `Expect.Algs`; key parses (§4.2).
4. **Attestation (LR33b-9):** conveyance `none` is requested. Format `none`
   needs an empty `attStmt`. `packed`, `tpm`, `android-key`,
   `android-safetynet`, `fido-u2f` and `apple` are accepted **without**
   verifying the statement and recorded as `none`; unknown formats are
   rejected. AAGUID is stored as a UUID string (all-zero allowed).
5. Credential ID uniqueness per tenant is the store's job (`ErrConflict`).

### 4.4 Assertion checks (L2 §7.2)

Client data `type == "webauthn.get"`, challenge, origin, `crossOrigin`,
`topOrigin` as above; `rpIdHash`; UP set; UV when required; signature over
`authenticatorData || SHA-256(clientDataJSON)` (ECDSA as ASN.1 DER via
`ecdsa.VerifyASN1`, Ed25519 raw, RSA per alg). Then:

- **User handle:** required for discoverable (passkey first-factor) logins
  and must equal the stored handle; for MFA (`Allow` list given) it is
  optional and, if present, must match.
- **Sign counter (LR33b-10):** if the stored or received count is non-zero,
  the received count must be greater, else reject with reason `sign_count`
  (possible cloned authenticator). Synced passkeys report 0 and pass. The
  store applies the update with a conditional write (`sign_count < n` or both
  zero), so two concurrent assertions cannot both succeed with one count.
- **Backup flags (L3):** BE must equal the stored BE (BE is fixed for a
  credential; a change is rejected, reason `backup_eligibility`). BS may
  change and is written back (`credential_backed_up`).
- Unknown flags bits RFU ignored.

### 4.5 Ceremony parameters

| Ceremony | `userVerification` | `residentKey` | `authenticatorAttachment` | `excludeCredentials`/`allowCredentials` | UV enforced |
| --- | --- | --- | --- | --- | --- |
| Passkey signup / progressive (hosted, native) | `preferred` (documented) | `required` (documented) | none | user's credentials for RP ID (none on signup) | no (LR33b-8) |
| Local enrollment | `preferred` | `required` | `platform` | user's credentials for RP ID | no |
| Passkey login (hosted, native) | `preferred` (documented) | — | — | empty (discoverable) | no |
| `webauthn-roaming` enroll/challenge | from setting: never → `discouraged` (default), if supported → `preferred`, required → `required` | `discouraged` | `cross-platform` | user's roaming credentials for RP ID | only when `required` |
| `webauthn-platform` enroll/challenge | `required` ("always performed") | `discouraged` | `platform` | user's platform credentials for RP ID | yes |

`pubKeyCredParams`: `-8`, `-7`, `-257` (documented order). `rp.name` equals
`rp.id` (documented for native; LR33b-6 for hosted). `attestation: "none"`.
User handle (**LR33b-7**): 32 random bytes generated at a user's first
passkey and reused for the user's later passkeys (stored on each row as
`user_handle`, base64url); it contains no PII. `user.name` is the
highest-precedence identifier (email, phone number, username per the
connection); `user.displayName` is `name` if set, else that identifier
(documented for native).

**Challenges (LR33b-6):** 32 random bytes, single use. The verifier must
compare the raw value, so the row stores the raw challenge (it is not a
credential once consumed or expired) and is consumed by a conditional
update. Hosted: lifetime 5 minutes (`timeout` 300000), bound to tenant,
transaction ID, transaction cookie hash, purpose, RP ID, origin and (for
enrollment and MFA) user. Native: `timeout` 60000 (the documented value) and
the row expires 10 s after it to absorb transport delay; bound to tenant,
client, realm, organization, purpose, RP ID and the allowed origins, and
addressed by an opaque `auth_session` (32 random bytes, stored hashed). A
failed verification consumes the challenge; the next attempt gets a new one.

## 5. Hosted pages

### 5.1 Routes and screens

| Path | Prompt / screen | Purpose |
| --- | --- | --- |
| `GET /u/login` (identifier step, existing) | `login-id` / `login-id` | adds the passkey button, autofill and a challenge |
| `POST /u/login/passkey` | `login-id` | assertion submit (button and autofill) |
| `GET`/`POST /u/signup/identifier` | `signup-id` / `signup-id` | identifier and profile fields (Plan 34 attributes) |
| `GET`/`POST /u/signup/passkey` | `passkeys` / `passkey-enrollment` | create a passkey or choose a password |
| `GET`/`POST /u/signup/password` | `signup-password` / `signup-password` | password signup after the split |
| `GET`/`POST /u/passkey-enrollment` | `passkeys` / `passkey-enrollment` | progressive enrollment |
| `GET`/`POST /u/passkey-enrollment-local` | `passkeys` / `passkey-enrollment-local` | local enrollment |
| `GET`/`POST /u/mfa-detect-browser-capabilities` | `mfa` / `mfa-detect-browser-capabilities` | WebAuthn capability detection before factor choice |
| `/u/mfa-webauthn-roaming-enrollment`, `/u/mfa-webauthn-platform-enrollment` | `mfa-webauthn` / same names | MFA enrollment |
| `/u/mfa-webauthn-roaming-challenge`, `/u/mfa-webauthn-platform-challenge` | `mfa-webauthn` / same names | MFA challenge |
| `/u/mfa-webauthn-change-key-nickname`, `/u/mfa-webauthn-enrollment-success` | `mfa-webauthn` / same names | naming and success |
| (rendered in place) | `mfa-webauthn` / `mfa-webauthn-error`, `mfa-webauthn-not-available-error` | errors |

Auth0's `/u/` paths for these screens are not documented; the paths are
local (**LR33b-37**), the prompt and screen names are Auth0's, so Plan 22
custom text applies. `internal/brandingrules/inventory.json` already lists
the `passkeys` and `mfa-webauthn` prompts and these screens; Task 1 adds the
`reset-password-mfa-webauthn-platform-challenge` and
`reset-password-mfa-webauthn-roaming-challenge` screens from the OpenAPI
`ScreenGroupNameEnum`. Every text key listed in the customize-text page for
these screens gets an English catalog entry written in our own words and the
existing translation path; no Auth0 sentence is copied.

### 5.2 Page script and CSP

One in-tree script, served inline with the page's existing CSP nonce, reads
its options from `<script type="application/json" id="za-webauthn">` (emitted
by `html/template`, so JSON-escaped) and:

- converts base64url ↔ `ArrayBuffer` (uses `parseCreationOptionsFromJSON`/
  `parseRequestOptionsFromJSON` where present);
- for autofill, checks `PublicKeyCredential.isConditionalMediationAvailable()`
  and calls `navigator.credentials.get({mediation: "conditional", signal})`,
  aborting it before any other form submit or button ceremony;
- serializes the result as the §4.1 JSON into a hidden `credential` field and
  POSTs the normal form (with `state`, `csrf`, `hosted_revision`,
  `challenge_id`); no `fetch`, so `connect-src` stays `'none'`;
- on a `DOMException` posts `webauthn_error` with the exception **name**
  only; the server accepts only `NotAllowedError`, `InvalidStateError`,
  `NotSupportedError`, `SecurityError`, `AbortError`, `ConstraintError`,
  `UnknownError`, maps anything else to `UnknownError`, and never echoes it.

No CSP relaxation and no `Permissions-Policy` change: WebAuthn runs in the
top-level hosted document of the same origin.

### 5.3 State

The hosted transaction state (`HostedLoginState`) does not change shape. A
WebAuthn challenge row carries the transaction ID and cookie hash; the page
posts its `challenge_id`; the server rejects a challenge bound to another
transaction, browser, purpose or RP ID. Post-login prompts (progressive and
local enrollment) are decided by `authz` after MFA and recorded in the
transaction's internal params (`za_pk_prompt`: kind and decision time), so the
redirect can only proceed once the prompt is answered or skipped.

### 5.4 Session record

`store.LoginSession` gains `AuthMethods []AuthMethod{Name, Type string; At
time.Time}`. Hosted logins record the first factor (`pwd`, `passkey`,
`federated`, `email`, `sms`) and MFA (`mfa` with the factor `type`), using
`SessionAuthenticationSignal` names from the OpenAPI. The Management API
session view returns them (legacy sessions without a record keep today's
`pwd` output). Actions use them as in §8.1.

## 6. WebAuthn MFA

Builds on `internal/mfa` (Plan 33): factor flags, `mfa.Decide`, throttles,
remember browser, recovery codes, tickets, proof commits.

### 6.1 Factor rules

| Documented behaviour | Rule |
| --- | --- |
| Security keys: UV Never (default) / If supported / Required; FIDO-1 keys fail when Required | Setting stored in Guardian settings (§9.2); maps to §4.5. |
| Device biometrics cannot be the only factor enabled; the user must have another enrollment first | **LR33b-20:** `PUT /guardian/factors/webauthn-platform` accepts `enabled: true` alone (API behaviour undocumented); the factor is offered only to a user who already has another confirmed enforced factor. The console warns when it is the only enabled factor. |
| Biometrics are enrolled only via progressive enrollment; one device per type (phone, tablet, desktop); progressive per device | After a successful MFA challenge or enrollment with another factor, on a browser that reported a user-verifying platform authenticator, with no platform enrollment of this device's class, show `mfa-webauthn-platform-enrollment` with Continue, "Remind me later", "Not on this device", "Not now" (keys `continueButtonText`, `snoozeEnrollmentButtonText`, `refuseAddingDeviceText`, `skipAddingDeviceText`). |
| Device recognition is by user agent; macOS per browser; Windows/iOS 14.5+ per OS; Android Chrome only | **LR33b-19:** `webauthn.DeviceOf(userAgent) Device{OS, Browser, Class}`: OS ∈ windows, ios, macos, android, other; browser counts only on macOS; class phone/tablet/desktop. A platform authenticator is offered for challenge only when its stored `user_agent` maps to the same device key as the request; enrollment refused when one of the same class exists. |
| Browsers without JavaScript or WebAuthn are not offered WebAuthn; the user gets another factor or the recovery code | `mfa-detect-browser-capabilities` runs before the factor list, challenge or enrollment whenever a WebAuthn factor could be offered; its result (`webauthn`, `platform`) is kept in the MFA page state. No result (no script) means unavailable. |
| A roaming key enrolled under another RP ID leads to a new enrollment | Usable authenticators are filtered by RP ID before `mfa.Decide`; a user whose only factors are WebAuthn credentials for another RP ID is sent to enrollment. |
| Challenge screens carry `rememberMeText` | Remember browser works as for OTP (Plan 33 §5). |
| `too-many-webauthn-challenge-attempts-error` | WebAuthn failures count in Plan 33's per-user, per-factor throttle (10 per 15 minutes). |
| Roaming enrollment names the key; nickname screen | After roaming registration, `mfa-webauthn-change-key-nickname`; 1–20 characters (OpenAPI `name` maxLength 20; **LR33b-31**: minimum 1). Platform enrollments get a default name "<browser> on <OS>" and the same screen with the platform texts. |
| Recovery | "Try another method" lists the user's other factors and the recovery code. First roaming enrollment as the user's first factor shows the recovery code (Plan 33). |

Snoozes for platform enrollment (**LR33b-18**, borrowed from the documented
biometrics first-factor dialog): "Remind me later" 14 days per user per
device key; "Not on this device" 365 days in a browser cookie and the
snooze table; "Not now" this login only.

### 6.2 Actions and tickets

`challengeWith`/`challengeWithAny` accept `webauthn-roaming` and
`webauthn-platform` (documented allowed values); `enrollWith`/`enrollWithAny`
too. Enrollment tickets accept `factor: webauthn-roaming|webauthn-platform`
(`GuardianEnrollmentFactorEnum`). **LR33b-20:** an explicit request to enroll
`webauthn-platform` (Action or ticket) shows the platform enrollment screen
but still requires another confirmed factor first; K4 records the conflict
with "only through progressive enrollment". `api.multifactor.enable("any")`
and `("guardian")` include enabled WebAuthn factors.

### 6.3 MFA API (Authentication API)

| Documented | Rule |
| --- | --- |
| You can list and remove WebAuthn enrollments but not enroll them | `GET /mfa/authenticators` lists confirmed WebAuthn authenticators; `DELETE /mfa/authenticators/{id}` removes them. **LR33b-21:** their `authenticator_type` is the factor name (`webauthn-roaming`/`webauthn-platform`) because the OpenAPI enum has no WebAuthn value. `/mfa/associate` with those types and `/mfa/challenge` for those IDs answer the existing unsupported-type error. Passkeys never appear in the MFA API. |

### 6.4 Reset password

`password-reset-post-challenge` with `challengeWith` a WebAuthn factor uses
the same pages, rendered with the screen names
`reset-password-mfa-webauthn-platform-challenge` and
`reset-password-mfa-webauthn-roaming-challenge`.

## 7. Native Passkey APIs

### 7.1 Endpoints

| Documented | Rule |
| --- | --- |
| Client must list `urn:okta:params:oauth:grant-type:webauthn` in `grant_types`; be first party; be OIDC conformant | `clientrules.GrantPasskey` added to `GrantTypes`; zeroauthy clients are always OIDC conformant (D-0039). Third-party client or missing grant: `400 invalid_request` on `/passkey/*` (documented 400), `unauthorized_client` on `/oauth/token` (existing pattern). |
| Requests must be on a custom domain; the default domain is rejected | `400 invalid_request` on the canonical host (**LR33b-25**: canonical host = Auth0's default domain). |
| Body: `client_id`, `client_secret` (confidential, `client_secret_post`), `realm`, `organization`; `/passkey/register` adds `user_profile` (`email`, `phone_number`, `username`, `name` 1–300, `given_name` 1–150, `family_name` 1–150, `nickname` 1–300, `picture`) and `user_metadata` (≤ 10 string fields) | JSON (and form) bodies; client authentication through the existing client authenticator (Basic also accepted where the client is configured for it). Unknown `user_profile` keys → `400 invalid_request`. |
| `realm` omitted → tenant default directory / default DB connection for the app | The tenant's `default_directory` when it is a database connection enabled for the client; else the client's only enabled database connection with passkeys effective; else `400 invalid_request`. |
| `organization` required when `organization_usage: require`; ID or name (SDK) | Plan 29 organization rules of the password-realm grant, including auto-membership. |
| `user_profile` must hold every identifier required at signup; an existing user under any identifier fails with `invalid_request` | Plan 34 attribute rules. The existence answer is documented, so it stays; it is rate limited (§12). |
| Native registration is unsupported when SMS/email OTP verification is required at signup on the connection | `400 invalid_request` when the connection requires email or phone verification at signup (Plan 34 `signup.verification`). |
| Responses: `{auth_session, authn_params_public_key}` with the documented members | Exactly the documented members (§4.5 values). `/passkey/challenge` returns `{challenge, timeout, rpId, userVerification: "preferred"}`. |
| Status 400/401/404/429 | 401 `invalid_client`; **LR33b-25:** 404 `{"error":"not_found"}` when the store lacks `webauthn.v1` or no database connection of the tenant has passkeys effective; 429 from the general Authentication API limiter (`too_many_requests`). |
| Logs `passkey_challenge_started` (`details.purpose`) and `passkey_challenge_failed` | Logged on each challenge issued or refused. |

### 7.2 The passkey grant

`POST /oauth/token` with `grant_type=urn:okta:params:oauth:grant-type:webauthn`,
`client_id`, client authentication, `auth_session`, `authn_response`,
optional `realm`, `scope`, `audience`, `organization`. `authn_response` is
accepted as a JSON object (documented JSON body) **or** a JSON string (form
body, as the pinned auth0-auth-js sends). The `auth_session` is consumed
first (single use, same client, realm and organization), then:

- **register:** `VerifyRegistration`; run `pre-user-registration`; create the
  user without a password plus the passkey in one transaction; logs `ss`
  (`details.authentication_methods: ["passkey"]`); `post-user-registration`.
- **login:** `VerifyAssertion` against the credential found by ID in the
  tenant (user handle required); blocked user → `invalid_grant` "user is
  blocked" (Plan 34 wording).
- Then the normal token path: post-login Actions (`event.transaction.protocol
  = "oauth2-webauthn"`, `passkey` in `event.authentication.methods`),
  `mfa.Decide` (an unsatisfied requirement returns Plan 33's `mfa_required`
  with an `mfa_token` bound to this grant), refresh tokens by the normal
  rules, logs `s` with `details.prompts[0].performed_amr: ["phr"]`. The MFA
  grants that follow a passkey `mfa_token` log `sepkotpft`, `sepkoobft`,
  `sepkrcft` (and after a password `mfa_token`, `seotpft`, `seoobft`,
  `sercft`, closing a Plan 33 gap, **LR33b-28**).
- Errors: missing parameters `400 invalid_request`; expired, consumed or
  mismatched `auth_session` and every verification failure `400 invalid_grant`
  with a fixed description (**LR33b-25**, consistent with D-0061 keeping
  unobserved grants at 400); each failure logs `passkey_challenge_failed`
  with the purpose and a bounded reason.
- Not advertised in discovery `grant_types_supported` (D-0059 rule).

### 7.3 Origins and association files

**LR33b-26:** a native/embedded ceremony accepts these `clientDataJSON`
origins: `https://<request host>`; any `https` origin whose host equals the
RP ID or is a subdomain of it **and** is listed in the client's
`web_origins`; `android:apk-key-hash:<base64url SHA-256>` for each of the
client's `mobile.android.sha256_cert_fingerprints` (hex with colons,
converted). iOS apps report `https://<rp id>`, which the second rule covers
when the RP ID host itself is the request host or in `web_origins`.

Client `mobile` (`ios.team_id`, `ios.app_bundle_identifier`,
`android.app_package_name`, `android.sha256_cert_fingerprints`) moves from
ignored (D-0039) to stored and returned, validated against `ClientMobile*`.
**LR33b-27:** each verified custom domain serves
`/.well-known/apple-app-site-association`
(`{"webcredentials":{"apps":["<team_id>.<bundle_id>", …]}}`) and
`/.well-known/assetlinks.json` (one statement per Android client with
relation `delegate_permission/common.get_login_creds`) built from the
tenant's first-party clients that have the passkey grant and the matching
`mobile` fields; `404` when there are none; `application/json`, no redirect,
cached 5 minutes. Not served on the canonical host (documented: custom
domain). Customers whose RP ID is a parent domain host these files
themselves, as with Auth0.

## 8. Actions, logs and events

### 8.1 Actions

- `event.authentication.methods` includes `{name: "passkey", timestamp}` when
  the session's first factor was a passkey (documented example). The other
  first-factor names stay Plan 40's (roadmap); **LR33b-12** keeps that
  boundary although the session now records them (K11).
- `event.user.enrolledFactors` includes `{type: "webauthn-roaming"}` and
  `{type: "webauthn-platform"}`; passkeys are not MFA factors and are not
  listed (**LR33b-12**).
- `api.authentication.challengeWith*`/`enrollWith*` and
  `api.multifactor.enable`: §6.2. `internal/actionsrules/inventory.json`
  moves the WebAuthn factor values from unavailable to supported.
- `event.transaction.protocol` is `oauth2-webauthn` for the passkey grant.
- `pre-user-registration` and `post-user-registration` run for passkey
  signups (hosted and native) as for password signups.
- ID token `amr`: unchanged by a passkey alone; `["mfa"]` after MFA as in
  Plan 33 (**LR33b-12**; K7).

### 8.2 Logs

Moving from deferred to emitted in the frozen log inventory (with owner
Plan 33b): `gd_webauthn_enrollment_failed`, `gd_webauthn_challenge_failed`,
`passkey_challenge_started`, `passkey_challenge_failed`, `sepkotpft`,
`sepkoobft`, `sepkrcft`, `seotpft`, `seoobft`, `sercft`. `gd_auth_rejected`
(push decline) moves from owner Plan 33b to `not_planned` with push.

| Event | Code | Details (schema fields) |
| --- | --- | --- |
| Hosted passkey login succeeds | `s` | `details.prompts[{name: "login-id", performed_amr: ["phr"]}]` (documented) |
| Hosted or native passkey signup | `ss` | `details.authentication_methods: ["passkey"]` (password signups: `["pwd"]`, documented) |
| Progressive/local passkey enrollment succeeds | `gd_enrollment_complete` | `details.authenticator.type: "passkey"` |
| WebAuthn MFA enrollment succeeds | `gd_enrollment_complete` | `authenticator.type` = factor |
| Passkey enrollment fails | `gd_webauthn_enrollment_failed` | `details.authentication_methods: ["passkey"]`, `failure_details.errorCode` (DOMException name or reason code) |
| WebAuthn MFA enrollment fails | `gd_webauthn_enrollment_failed` | `authenticator.type`, `failure_details` |
| Hosted passkey login assertion fails | `gd_webauthn_challenge_failed` | `first_factor: true`, `failure_details` (**LR33b-17**) |
| WebAuthn MFA challenge fails | `gd_webauthn_challenge_failed` | `first_factor: false`, `authenticator`, `failure_details`; `gd_auth_failed` as Plan 33 |
| Native challenge issued / refused; grant verification fails | `passkey_challenge_started` / `passkey_challenge_failed` | `purpose`, `error.message` (bounded reason) |

The log inventory allowlists gain exactly these detail fields. The
key-name scrubber gains `authn_response`, `auth_session`, `attestationObject`,
`authenticatorData`, `clientDataJSON`, `signature`, `userHandle`,
`user_handle` and `challenge_id`. A representative-value scan covers all of
them.

### 8.3 Events

`user.updated` fires when the derived `multifactor` changes (Plan 33 rule),
so enrolling or removing a WebAuthn MFA authenticator can fire it.
**LR33b-33:** passkey create/delete, sign-count, BS and `last_auth_at`
updates do not change the user object and fire nothing. Passkey signups
emit `user.created` as other signups do.

## 9. Management API and configuration

### 9.1 User authentication methods

| Route | Passkeys | WebAuthn MFA |
| --- | --- | --- |
| `GET /users/{id}/authentication-methods` (+ by ID) | listed: `id`, `type: "passkey"`, `name`, `created_at`, `last_auth_at`, `key_id`, `public_key`, `relying_party_identifier`, `credential_device_type` (`multi_device` iff BE), `credential_backed_up` (BS), `aaguid`, `identity_user_id`, `user_agent`, `user_handle`, `transports` | listed with `key_id`, `public_key`, `relying_party_identifier` |
| `PATCH …/{authentication_method_id}` | `name` | `name` (and `preferred_authentication_method` per Plan 33) |
| `DELETE …/{authentication_method_id}` | deletes | deletes |
| `POST /users/{id}/authentication-methods` | `type: "passkey"` (current `CreatedUserAuthenticationMethodTypeEnum`): **LR33b-23** requires `key_id`, `public_key` (valid COSE, §4.2); `relying_party_identifier` defaults to the tenant's default custom domain's effective RP ID, else the canonical host; `identity_user_id` defaults to the user's database identity (must be one of the user's database identities); `user_handle` defaults to the user's existing handle, else a new one; `aaguid`, `credential_device_type`, `credential_backed_up`, `user_agent`, `transports` stored as given; 20-passkey limit → `400 invalid_body` (**LR33b-29**); duplicate `key_id` in the tenant → `409` | `webauthn-roaming` as Plan 33; RP ID stored and now enforced |
| `DELETE /users/{id}/authentication-methods` | **kept** (documented: "enrolled MFA factors") | deleted |
| `PUT /users/{id}/authentication-methods` | kept (types `phone`, `email`, `totp` only) | replaced (deleted) |
| `DELETE /users/{id}/authenticators`, `GET /users/{id}/enrollments`, `multifactor` | excluded | included (`auth_method` `webauthn-roaming`/`webauthn-platform`) |

Passkey method IDs: `passkey|dev_<20 alphanumerics>` (D-0059 format; W1).
`store.AuthenticatorTypes` gains `passkey`. Creating a `passkey` method
needs `webauthn.v1` (§10); without it `501 webauthn_unavailable`.

**Linking (LR33b-24):** linking moves the secondary user's passkeys to the
primary user unchanged (`identity_user_id` still names the secondary
identity), so a passkey login resolves to the primary user as a linked login
does. Unlinking moves passkeys whose `identity_user_id` is the unlinked
identity back. User deletion deletes passkeys (Plan 33 `DeleteUserMFA`).

### 9.2 Guardian and other configuration

- `GET/PUT /guardian/factors`: `webauthn-roaming` and `webauthn-platform`
  move from `stored` to `enforced` in `internal/mfarules/inventory.json`.
- **WebAuthn security-key user verification (LR33b-22):** Auth0 documents
  the setting only in the Dashboard. zeroauthy stores it in
  `GuardianSettings.Stored["webauthn-roaming/settings"]` as
  `{"user_verification": "discouraged"|"preferred"|"required"}` (default
  `discouraged` = "Never") and exposes it through a marked extension route
  `GET/PUT /api/system/tenants/{tenant}/guardian/factors/webauthn-roaming/settings`
  (operators, `update:guardian_factors`-equivalent operator permission), used
  by the console and seed. No `/api/v2` route is invented.
- `relying_party_identifier` on `/custom-domains`: enforced (§3.2) with the
  extra reserved-name check.
- Clients: `mobile` stored and returned; the passkey grant type accepted.
- Connections: no wire change; the response is unchanged. The console reads
  the prerequisites from a new read-only field on the operator system API
  `GET /api/system/tenants/{tenant}/connections/{id}/passkey-prerequisites`
  (`{effective, unmet: ["identifier_first", …]}`), marked extension.

## 10. Storage, migration and plugin capability

**Migration `0035_webauthn.sql`** (SQLite, PostgreSQL, MySQL), forward only;
no existing row is rewritten:

| Change | Holds |
| --- | --- |
| `sessions.auth_methods TEXT NULL` | JSON `[{name, type?, at}]` (§5.4); NULL for old sessions |
| `clients.mobile TEXT NULL` | `ClientMobile` JSON |
| `webauthn_snoozes (tenant_id, user_id, kind, scope_key, until, PRIMARY KEY (tenant_id,user_id,kind,scope_key))` + index on `until` | `kind` ∈ `passkey-progressive` (scope = RP ID), `passkey-local` (scope = hashed device cookie), `platform-remind`, `platform-refuse` (scope = device key) |

Passkeys and WebAuthn MFA credentials live in the existing
`mfa_authenticators` rows (`type`, `credential_id` with the existing
`UNIQUE (tenant_id, credential_id)`, `public_key` COSE, `rp_id`,
`sign_count`, `public_data` JSON with the allowlisted public fields — now
also `backup_eligible`). Challenges use `mfa_challenges` with new kinds
`webauthn-register`, `webauthn-assert`, `passkey-register`, `passkey-login`
and the binding JSON in `data`. The UV setting uses `mfa_guardian.data`.
Expiring challenges and snoozes join the periodic purge sweep.

**Store contract** (`internal/store/webauthn.go`), memory, SQL, gRPC and
`pkg/storetest` cases:

```go
var ErrWebAuthnUnavailable = errors.New("store: WebAuthn unavailable")
type WebAuthnSupporter interface { CheckWebAuthnSupport(context.Context) error; WebAuthnSupported() bool }
type WebAuthn interface {
    GetAuthenticatorByCredentialID(ctx context.Context, tid string, credID []byte) (*Authenticator, error)
    // CreatePasskey enforces the per-user limit and tenant credential uniqueness atomically.
    CreatePasskey(ctx context.Context, a *Authenticator, limit int) error // ErrConflict (dup), ErrPrecondition (limit)
    // AcceptAssertion applies the sign-count rule and writes BS and last_auth_at.
    AcceptAssertion(ctx context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error
    MovePasskeys(ctx context.Context, tid, fromUID, toUID, identityUserID string) error // "" = all
    PutSnooze(ctx context.Context, s *WebAuthnSnooze) error
    GetSnooze(ctx context.Context, tid, uid, kind, scope string, now time.Time) (*WebAuthnSnooze, error)
    PurgeWebAuthn(ctx context.Context, before time.Time, limit int) (int, error)
}
```

`DeleteUserAuthenticators(..., nil)` changes meaning to "every MFA type"
(all types except `passkey`); `DeleteUserMFA` and tenant deletion still
remove everything. Old plugins cannot hold passkeys (creation needs the new
capability), so the changed meaning is safe for them.

**`webauthn.v1` gRPC capability**, negotiated by `WebAuthnCapabilities`
separately from every earlier capability, latched like `phone.v1`. It also
covers the new session and client fields. Without it: passkey options stay
stored-only (as before), WebAuthn factors are not offered (as before), the
native endpoints answer 404, Management API passkey create answers 501,
`mobile` stays ignored, and the old plugin keeps working.

## 11. Console, seed, Deploy CLI and docs

**Console.**

- *Database connection → Authentication Methods:* Password (stored fields
  shown) and a Passkey panel: enable; "Passkey authentication UI" with the
  three `challenge_ui` choices; progressive and local enrollment checkboxes;
  a prerequisites list with each item's status and a link to where it is
  fixed (prompt settings, `requires_username`, flexible identifiers, import
  mode, password). Enabling is blocked while any is unmet (LR33b-1).
- *Security → Multi-factor auth:* the WebAuthn rows lose their "stored for
  Plan 33b" labels; security keys get the user-verification select (Never,
  If supported, Required); device biometrics warns when it is the only
  enabled factor.
- *Settings → Relying party IDs:* every host (canonical and custom domains)
  with its effective RP ID; edit a custom domain's RP ID with the warning
  that existing passkeys and WebAuthn keys for the old RP ID stop working.
- *User → MFA tab:* WebAuthn authenticators with type, name, RP ID, enrolled,
  last used; a **Passkeys** section with name, RP ID, synced
  (`credential_device_type`), backed up, AAGUID, created, last used; delete
  one; rename.
- *Application → Settings:* the "Passkey" grant checkbox and the Device
  Settings (iOS team ID and bundle ID, Android package name and fingerprints).
- Requests capture the tenant and drop stale replies; all strings through the
  catalog.

**Seed.** `guardian.factors` already accepts the WebAuthn flags; seed adds
`guardian.webauthn_roaming.user_verification` (extension key), client
`mobile` and the passkey grant. Connection passkey options already seed.

**Deploy CLI** (pinned 9.1.0). Clients round-trip `mobile` and the grant;
connections round-trip passkey options (already stored); `customDomains`
round-trips `relying_party_identifier`; `guardianFactors` round-trips the
WebAuthn flags. The UV setting has no Auth0 API and no handler. Task 1
updates `tests/e2e/deploy-cli/manifest.json` reasons for those handlers.

**Docs.** New `docs/passkeys.md` (operator guide: prerequisites, RP IDs and
custom domains, UI choices, enrollment prompts, native setup, limits,
differences); updates to `docs/mfa.md`, `docs/custom-domains.md` (RP ID now
enforced), `docs/logs.md`, `docs/actions.md`, `docs/compat/matrix.md`,
`docs/compat/changelog-review.md`, D-0062, the follow-ups file (W-items, the
custom-database-without-import passkey item stays open).

## 12. Security review focus

1. **Phishing resistance.** Exact origin per ceremony; RP ID hash; no
   `crossOrigin`/`topOrigin`; hosted pages accept only their own origin;
   native origins only from the client's own configuration (§7.3). Tests
   prove a correct assertion is refused from another custom domain of the
   same tenant, from another tenant's host, and with a forged origin.
2. **Challenge binding and replay.** Challenge rows are tenant-, purpose-,
   RP-ID- and transaction/`auth_session`-bound, single use by conditional
   update, short lived. A captured assertion cannot be replayed into another
   transaction, client or tenant.
3. **Credential uniqueness and tenant isolation.** Lookup is always by
   `(tenant_id, credential_id)`; a duplicate credential ID inside a tenant is
   refused. Two tenants may share an RP ID (e.g. prod and staging under one
   parent domain); that is safe only because origins are checked per tenant
   and credentials are tenant-scoped — tests cover it. RP IDs covering the
   deployment's own hosts are refused only with `security.webauthn.restrict_shared_rp_ids` (LR33b-4 as amended by §14a R1).
4. **User enumeration.** Hosted login uses discoverable credentials with an
   empty `allowCredentials`; no endpoint maps an identifier to credential
   IDs before the first factor; all hosted passkey failures share one
   answer. The native `/passkey/register` existence answer is documented; it
   is covered by the per-IP limiter and logged.
5. **Account takeover via enrollment.** Progressive, local and WebAuthn MFA
   enrollment happen only after every factor the login required, inside the
   bound transaction. Enrollment tickets keep Plan 33's single-use rules. The
   Management API is operator-trusted. A passkey-only signup is still a
   signup: bot detection, signup disabling, organization rules and
   `pre-user-registration` apply.
6. **MFA interplay.** A passkey alone never sets `mfa_at` or `amr: ["mfa"]`;
   MFA after a passkey is the default; only an Action skips it.
   Remember-browser cannot satisfy `challengeWith*`.
7. **Cloned authenticators.** Sign-count regression is refused and logged;
   BE changes are refused.
8. **Parser safety.** Bounded CBOR with fuzzing; size limits before parsing;
   no reflection of attestation contents; COSE private labels refused.
9. **Secrets in logs.** §8.2 scrubber keys and a representative scan of every
   sink, event body, Action log and console response.
10. **Linked accounts.** Passkeys move with identities; unlinking returns
    them, so an unlinked identity never keeps a way into the primary user.

## 13. Local rulings and observe-later list

| # | Ruling | Cost if wrong |
| --- | --- | --- |
| LR33b-1 | API stores any passkey option combination; passkeys are offered only when the documented prerequisites hold; console blocks enabling | A tool expecting a 400 from Auth0 gets 200 and silently no passkeys |
| LR33b-2 | Passkeys effective only with password enabled (documented "must still have passwords") | None known |
| LR33b-3 | `api_behavior`/`signup_behavior` stored only; `/dbconnections/signup` requires a password | Apps relying on passwordless DB signup via API fail |
| LR33b-4 | **Amended by §14a R1.** RP ID per host (canonical = itself; custom = field or domain); no tenant-level default RP ID; RP IDs covering the deployment's hosts refused | A tenant expecting a dashboard default RP ID must set it per custom domain |
| LR33b-5 | Per-RP-ID enrollment across multiple custom domains (not "first domain only") | Users may hold passkeys on several domains where Auth0 allows one |
| LR33b-6 | Challenges: hosted 5 min; native `timeout` 60000 + 10 s grace; single use; raw challenge stored until consumed; `rp.name = rp.id` on hosted too | Slow users see an expired-challenge retry |
| LR33b-7 | User handle: 32 random bytes per user, reused across that user's passkeys | Clients that infer Auth0's handle format break (none known) |
| LR33b-8 | Passkey ceremonies send `preferred` and do not require the UV flag | Weaker than "required"; matches the documented option |
| LR33b-9 | Attestation `none` requested; other known formats accepted unverified; no AAGUID policy | An operator wanting attestation-based restrictions cannot have them |
| LR33b-10 | Sign-count regression rejected (reason `sign_count`); BE change rejected; BS written back | A buggy authenticator with a resetting counter is locked out (other factors/recovery remain) |
| LR33b-11 | Register offers -8, -7, -257; assertions also verify -35, -36, -37 keys imported by API | None known |
| LR33b-12 | Actions get `passkey` only among first-factor methods (Plan 40 owns the rest); passkeys not in `enrolledFactors`; ID token `amr` unchanged by a passkey alone | Actions or RPs checking `pwd` or `amr` see Plan 33 behaviour |
| LR33b-13 | Progressive enrollment after MFA; "don't show again" = 30 days per user per RP ID; only when the user has no passkey for that RP ID | Prompt frequency differs from Auth0 |
| LR33b-14 | Local enrollment when the assertion's attachment is `cross-platform` and a platform authenticator is available; snooze 30 days per user per browser | Prompt shown more or less often than Auth0 |
| LR33b-15 | Split signup screens only when passkeys are effective | Identifier-first tenants without passkeys keep the single signup page |
| LR33b-16 | Passkey login: credential's user wins over the typed identifier; generic failure for every non-blocked error | None known |
| LR33b-17 | Hosted passkey login failure logs `gd_webauthn_challenge_failed` with `first_factor: true`; native failures `passkey_challenge_failed` | Log consumers filtering on another code miss failures |
| LR33b-18 | Platform enrollment snoozes 14 days ("remind me later") and 365 days ("not on this device"), borrowed from the biometrics first-factor page | Prompt frequency differs |
| LR33b-19 | Device recognition by user-agent classification (OS; browser on macOS; class phone/tablet/desktop) | Some users not offered their enrolled device, or refused a second same-class device |
| LR33b-20 | `webauthn-platform` may be enabled alone via API; offered only after another confirmed factor; explicit enroll requests honoured after another factor | Differs if Auth0's API refuses or Actions bypass the rule |
| LR33b-21 | MFA API lists WebAuthn with `authenticator_type` = factor name; associate/challenge refuse | SDKs expecting only `otp`/`oob`/`recovery-code` may ignore them |
| LR33b-22 | Security-key UV setting in Guardian stored JSON plus an extension system route; default Never | Deploy CLI cannot carry it (Auth0 has no API either) |
| LR33b-23 | Management API `passkey` create: required `key_id`/`public_key`; defaults for RP ID, identity, user handle | Imported passkeys bound to an unexpected RP ID are unusable until fixed |
| LR33b-24 | Linking moves passkeys to the primary; unlinking moves them back | Differs if Auth0 drops or keeps them |
| LR33b-25 | **Amended by §14a R2 (aliases).** Native: canonical host refused 400; 404 when unavailable or no effective connection; realm defaulting; grant failures 400 `invalid_grant` | Status/error codes differ from Auth0 |
| LR33b-26 | Native origins: request host, RP-ID hosts listed in `web_origins`, Android key hashes | An app whose origin Auth0 would accept is refused (configuration fixable) |
| LR33b-27 | **Amended by §14a R2 (aliases).** `.well-known` association files on verified custom domains from first-party passkey clients; 404 if none | Apps needing other AASA sections (applinks) don't get them |
| LR33b-28 | Emit `seotpft`, `seoobft`, `sercft` with the `sepk*` codes (shared dispatch) | None (closes a Plan 33 gap) |
| LR33b-29 | 21st passkey via Management API → 400 `invalid_body` | Status differs |
| LR33b-30 | **Amended by §14a R3.** WebAuthn MFA failures count in Plan 33's throttle; passkey login failures only in the general per-IP limiter | Lockout thresholds differ |
| LR33b-31 | Key nickname 1–20 characters; default names from `authenticatorNames*` / "<browser> on <OS>" | Cosmetic |
| LR33b-32 | Invitation signups hide the passkey choice | None (documented) |
| LR33b-33 | No `user.updated` for passkey changes | Consumers expecting one miss it |
| LR33b-34 | Parser bounds (§4.2) | Exotic authenticators with huge data refused |
| LR33b-35 | `passkeys` partials stored only | Customized passkey screens look default |
| LR33b-36 | Passkey-only users have no password; password login gives the normal wrong-credentials answer | None known |
| LR33b-37 | `/u/` paths for the new screens are local | Bookmarks/tests pinned to Auth0 paths differ |

**Observe later** (separate observer session, optional; recorded in D-0062
and the follow-ups file): **W1** passkey and WebAuthn method ID formats and
the exact `GET /users/{id}/authentication-methods` passkey object; **W2**
whether the Management API refuses passkey enablement with unmet
prerequisites; **W3** `POST` passkey create defaults and errors (limit,
duplicate, RP ID); **W4** native endpoint error bodies, the 404 condition and
grant error status; **W5** progressive/local snooze semantics (per user, per
browser, per RP ID); **W6** when local enrollment is offered; **W7**
`/mfa/authenticators` output for WebAuthn; **W8** exact log `details` for
`s`, `ss`, `gd_webauthn_*`, `passkey_challenge_*`; **W9** behaviour of
`DELETE`/`PUT` authentication methods on passkeys; **W10** `amr` and
`event.authentication.methods` after a passkey login; **W11** linking and
unlinking effects on passkeys; **W12** challenge lifetime on hosted pages.

## 14. Documentation conflicts and thin points (resolved in §14a)

- **K1 MCD enrollment scope.** The passkeys overview and configure pages say
  a user can enroll a passkey for only one of the tenant's custom domains
  (the first). The MCD passkeys page and the MCD limitations section say each
  domain has its own RP ID and users enroll per domain; the 2026-04-08
  changelog lists passkey enrollment on custom domains. This spec follows
  per-domain (LR33b-5).
- **K2 MCD passkeys page setup steps** tell users to enable "WebAuthn with
  FIDO Security Keys" under MFA to enable passkeys, which contradicts the
  database-connection configuration everywhere else. Ignored.
- **K3 Field casing.** The Management API usage page shows a `webauthn-roaming`
  response with `relyingPartyIdentifier`, `keyId`, `publicKey`; the OpenAPI
  uses snake case. Snake case kept (Plan 33).
- **K4 Biometrics enrollment.** "No way to enroll device biometrics beyond the
  progressive prompt" versus `enrollWith`/tickets accepting
  `webauthn-platform`. LR33b-20 honours explicit requests after another
  factor.
- **K5 Tenant default RP ID** exists in the Dashboard only; no API. Not built.
- **K6 Dashboard-only settings:** security-key UV and MFA RP ID. UV gets an
  extension route; MFA RP ID reuses the custom-domain field.
- **K7 `amr` for passkeys.** Logs record `performed_amr: ["phr"]`; nothing
  documents an ID token `amr` for passkeys. Unchanged (LR33b-12).
- **K8 `password.api_behavior`** semantics are undocumented (LR33b-3).
- **K9 Native Passkey API stage.** The API pages carry no Early Access banner,
  but the changelog called related pieces Limited EA and the API documents a
  per-tenant "not enabled" 404 without saying how to enable it. Built as GA
  with LR33b-25. Decide whether to gate it behind a tenant flag.
- **K10 MFA RP ID and MCD.** The WebAuthn MFA overview says the RP ID is
  limited to one domain and incompatible with MCD; the MCD page describes
  per-domain re-enrollment. Per-domain chosen.
- **K11 Plan 40 boundary.** The session now records `pwd`, `federated`,
  `email`, `sms`; emitting them in `event.authentication.methods` is a
  one-line change. Pull forward into 33b or keep in Plan 40?
- **K12 `webauthn_platform_first_factor`** stays Plan 44, although it uses
  this plan's platform authenticators. Confirm.
- **K13** The MCD page's sample Action checks `method.name === "webauthn"`,
  a name documented nowhere else. Not emitted.
- **K14 Sign-count policy** (reject vs. log only) is an RP choice in WebAuthn;
  rejecting is stricter. Confirm.

## 14a. Resolutions (controller calls, 2026-11-05)

The maintainer has not used passkeys and asked for the documentation to
decide ("go by the documentation"). The controller settled the conflicts and
the builder check's open questions as follows. These supersede any earlier
wording in this document; each is recorded in D-0062 as a controller call,
not a maintainer ruling.

**Conflicts.** K1 per domain (LR33b-5). K2 ignored. K3 snake case. K4
LR33b-20. K5 not built. K6 as stated. K7 `amr` unchanged. K8 stored only
(LR33b-3). **K9:** built as generally available with no tenant flag;
zeroauthy has no Early Access tiers, and LR33b-25's 404 covers stores without
`webauthn.v1` or tenants with no effective passkey connection. **K10** per
domain. **K11:** pulled forward: `event.authentication.methods` also lists
`pwd`, `federated`, `email` and `sms` from the session record (closes the
pre-1.0 review finding actions-extensibility F5; remove it from Plan 40).
K12 stays Plan 44. K13 not emitted. **K14:** reject a sign-count regression
(stricter of the two RP choices the WebAuthn spec allows).

**R1. RP IDs that cover the deployment's own hosts (amends LR33b-4).** A
custom domain or operator alias may set its RP ID to any registrable suffix
of its own host (WebAuthn's rule), including a parent of `server.base_domain`
such as `example.com`; this is Auth0's documented customisation for sharing
passkeys with the customer's own sites and apps, and single-organisation
self-hosting is the common case. A new deployment setting
`security.webauthn.restrict_shared_rp_ids` (default `false`) restores the
strict rule (refuse RP IDs that are a suffix of `server.base_domain` or of
another tenant's host) for shared multi-tenant hosting; Plan 47 turns it on.
A stored `relying_party_identifier` that is not a registrable suffix of its
host, or that the strict rule refuses, is never silently replaced: ceremonies
on that host fail closed with the hosted error page (native: 400
`invalid_request`), a WARN is logged, and the console marks the domain. The
canonical host's RP ID stays its own host.

**R2. Operator alias hosts (`store.HostOperator`, seed `domains`).** They are
operator-controlled hosted-login hosts and are treated like verified custom
domains: RP ID defaults to the host itself and may be set per alias with a
new optional seed field `relying_party_identifier` (same validation as R1).
They serve the native Passkey APIs (LR33b-25 refuses only the canonical
host) and the `.well-known` association files (LR33b-27). `rpid.For` takes
the host kind (canonical, custom domain, operator alias) and the stored
override.

**R3. Attack protection (amends LR33b-30).**
- A brute-force block on (identity, connection, IP) refuses every first-factor
  login for that identity from that IP, passkey included ("the user can't log
  in"), with the same `user-blocked`-style answer and log as a password
  attempt. The check runs after the assertion identifies the user and before
  any session is created, so a valid passkey never bypasses it.
- A successful passkey login resets that identity's brute-force failure
  counter, as a successful password login does.
- Suspicious-IP throttling: passkey login failures spend the login budget
  (after a failed assertion, keyed by IP since the user may be unknown);
  hosted passkey signup and native `/passkey/register` spend the
  registration budget before the "user exists" answer is revealed. All
  calls go through `internal/protection`, so limits are store-backed and
  shared across processes like the password paths, not only the per-process
  rate limiter.

## 15. Acceptance

A fresh tenant run by `make e2e-passkeys` (`tests/e2e/run-m33b-passkeys.sh`;
production app; SQLite and memory, PostgreSQL/MySQL through the runner's
backend switch; Chromium) with the Plan 23 custom-domain fixtures.

**Virtual authenticators.** Playwright CDP session:
`WebAuthn.enable`, `WebAuthn.addVirtualAuthenticator` with
`{protocol: "ctap2", transport: "internal", hasResidentKey: true,
hasUserVerification: true, isUserVerified: true,
automaticPresenceSimulation: true, defaultBackupEligibility: true,
defaultBackupState: true}` for synced platform passkeys; `transport: "cable"`
for a cross-device (hybrid) passkey; `transport: "usb"` with and without UV
for security keys; `protocol: "u2f"` for a FIDO-1 key;
`WebAuthn.getCredentials`/`addCredential` to clone a credential with a lower
sign count. **Task 1 spike:** WebAuthn needs a secure context without
certificate errors; confirm it runs on the `*.e2e.test` hosts under
`ignoreHTTPSErrors`, otherwise launch Chromium with
`--ignore-certificate-errors-spki-list=<test CA SPKI hash>`; confirm whether
conditional mediation resolves with a virtual authenticator, otherwise the
autofill path is covered by markup and server tests and the button path by
the browser (record which).

Journeys:

1. Operator meets the prerequisites in the console, enables passkeys with
   `both`; a new user signs up with a passkey (no password), logs out, logs
   in through the button; ID token has no `amr`; `ss` and `s` carry the
   documented details; the Management API lists the passkey with
   `credential_device_type: "multi_device"`, `credential_backed_up: true`.
2. With `all-applications` MFA and OTP enrolled, the passkey login is
   challenged; an Action using `api.multifactor.enable("none")` when
   `passkey` is in `event.authentication.methods` skips MFA.
3. A password user is offered progressive enrollment after MFA; "don't show
   again" suppresses it on the next login; a second user enrolls; a hybrid
   (`cable`) login offers local enrollment and creating it adds a platform
   passkey.
4. Prerequisite unmet (identifier first off): no passkey UI, options still
   returned unchanged by the API.
5. RP ID: the same user on a second custom domain is not offered the first
   domain's passkey; setting that domain's `relying_party_identifier` to the
   shared parent makes it work; an assertion replayed from another host,
   another tenant or with a forged origin is refused; an RP ID equal to the
   base domain is refused.
6. Cloned credential with a lower sign count is refused and logged with
   reason `sign_count`; the 21st passkey is refused with
   `passkey-enrollment-max-allowed-reached`.
7. WebAuthn MFA: enable security keys; enroll a USB key with UV Never, name
   it, log in with it, tick remember browser; set UV Required and show the
   UV-less key fails and the FIDO-1 key cannot enroll; enable biometrics,
   enroll after OTP via the progressive prompt, challenge with it; "Remind me
   later" suppresses; recovery code still works; enrollment ticket with
   `factor: webauthn-roaming`; `challengeWith({type: "webauthn-roaming"})` in
   an Action and in `password-reset-post-challenge`.
8. MFA API with pinned `@auth0/auth0-auth-js` and raw HTTP: WebAuthn
   authenticators listed and deleted; associate/challenge refused.
9. Native: pinned `@auth0/auth0-auth-js` 1.16.1 `passkey.register`,
   `getTokenByPasskey` (form body with stringified `authn_response`),
   `passkey.challenge` against a custom domain, with the credential created
   by a browser page on an allowed web origin under the virtual
   authenticator; raw JSON-body requests; `mfa_required` then `mfa-otp`
   logs `sepkotpft`; canonical host refused; existing identifier refused;
   reused `auth_session` refused; `.well-known` files served and correct for
   a client with `mobile` settings; organization required and honoured.
10. Management API with pinned node-auth0 7.4.0 (raw HTTP where its types
    lack `passkey`): list, rename, delete passkeys; `POST type: passkey`;
    `DELETE /users/{id}/authentication-methods` keeps passkeys; linking moves
    them. auth0-cli raw `auth0 api` for the same. Deploy CLI round trip of
    clients (`mobile`, grant), connections, custom domains and Guardian
    factors on all four backends.
11. Representative-secret scan of every log sink, event body, Action log and
    console response finds no `auth_session`, challenge, client data,
    attestation, signature or user handle.
12. `webauthn.v1` capability matrix: an old plugin keeps working with
    passkeys unavailable and options stored-only.
13. Go unit tests: CBOR/authData/client-data fuzzers; W3C-shaped vectors from
    an in-tree software authenticator (`internal/webauthn/webauthntest`)
    covering every alg, every flag rule, every attestation format, every
    origin/RP/challenge mismatch; `pkg/storetest` WebAuthn cases on memory,
    SQLite, PostgreSQL, MySQL.

Final regression, following `AGENTS.md` for long suites (one monitored run,
logs kept, no polling): the full Go race suite, `./scripts/test-sql.sh` on
all three dialects, `make console`, `make check-sources`, `make
e2e-passkeys`, `make e2e-mfa`, `make e2e-passwordless`, `make e2e`, the
domains, Actions, logs, events and deploy E2E targets, and `make
conformance` (passkeys off by default). Then a whole-branch review with
fixes. Results are reported as they happened; skipped, unavailable or failed
checks are never called passing.

## 16. Decisions to record

**D-0062 — Passkeys and WebAuthn MFA contracts and local rulings** (next
number after D-0061). Contents: the evidence list (§2) and fetch date; the
frozen `internal/webauthnrules/inventory.json`; LR33b-1…37 with cost if wrong;
W1–W12 as open observation points; K1–K14 with the maintainer's answers;
D-0042 addendum (passkey options enforced when effective); D-0039 addendum
(`mobile` stored); D-0059 addenda (WebAuthn factors enforced; `passkey`
method type; `DELETE`/`PUT` exclusions; MFA success log codes); D-0061
addendum (passkey grant errors at 400). Matrix rows for passkeys, WebAuthn
MFA, native Passkey APIs and RP IDs.

## 17. Suggested task outline

1. Task 1: re-fetch sources; freeze `webauthnrules` inventory (rules, URLs,
   text keys, log fields, OpenAPI refresh adding `passkey` create and
   `ClientMobile`); changelog review row; D-0062 skeleton; virtual
   authenticator and TLS spike.
2. `internal/webauthn`: CBOR, COSE, authData, client data, registration,
   assertion, options rendering, `DeviceOf`, software authenticator, fuzzers.
3. Storage: migration 0035, store contract, memory, SQL, `webauthn.v1`
   protobuf/gRPC, storetest, purge.
4. RP ID resolver and origin policy; custom-domain reserved-name check;
   `connrules.PasskeyPolicy` and the prerequisites route.
5. Hosted passkey login (login-id button and autofill, POST, session
   methods).
6. Hosted passkey signup (split screens, user without password).
7. Progressive and local enrollment, snoozes, post-MFA prompt stage.
8. WebAuthn MFA roaming: capability detection, enrollment, nickname,
   challenge, errors, UV setting and extension route, tickets.
9. WebAuthn MFA platform: progressive device enrollment, device
   recognition, snoozes; reset-password screens; MFA API listing/refusal.
10. Management API: passkey methods and exclusions, linking, client
    `mobile` and grant type.
11. Native Passkey APIs, the grant, MFA from the grant, association files.
12. Actions, logs (inventory, allowlists, scrubber), events.
13. Console, seed, Deploy CLI manifest, docs.
14. Acceptance harness and final regression; whole-branch review.

Writing this spec and its plan does not mean anything is implemented or
passing.
