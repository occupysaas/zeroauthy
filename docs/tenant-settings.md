# Tenant settings

Manage settings in the console's **Tenant settings** page or with
`GET/PATCH /api/v2/tenants/settings`. Reads require `read:tenant_settings`;
writes require `update:tenant_settings`. Writes validate the whole patch,
merge nested objects transactionally, and replace supplied arrays. Omitted
values remain unchanged. The reserved system tenant rejects settings writes.
Unknown properties and an empty root patch are refused.
See the [complete field and flag inventory](compat/observations/management-tenant-settings.md)
for nullable, read-only and future-feature fields.

## Sessions and units

| Setting | API unit | Default |
|---|---|---|
| `session_lifetime` | hours | 168 |
| `idle_session_lifetime` | hours | 72 |
| `ephemeral_session_lifetime` | hours | 72 |
| `idle_ephemeral_session_lifetime` | hours | 24 |

Each also accepts its `_in_minutes` alias. Writes require positive integers;
do not send both aliases. Reads return hours, including fractions for values
set in minutes. Internally durations remain seconds. `session_cookie.mode`
is `persistent` (default) or `non-persistent`; the latter selects ephemeral
limits and omits cookie Expires/Max-Age. Server expiration still applies.
New absolute limits apply to new sessions. Existing absolute expiry never
extends; idle touches can shorten expiration under current policy. Extremely
large lifetimes saturate at the safely serializable year-9999 expiry. These
existing-session rules are local choices, not observed upstream parity.

## Seed precedence

Existing top-level seed durations remain **seconds** with their existing
validation. The new nested `settings` object uses public API **hours/minutes**.
Do not define the same setting in both shapes. For example:

```yaml
tenants:
  - name: example
    session_lifetime: 3600 # old seed interface: one hour
    settings:
      ephemeral_session_lifetime: 72 # public API hours
      session_cookie: {mode: non-persistent}
      support_email: help@example.test
    attack_protection:
      brute-force-protection: {max_attempts: 12}
```

`seed_mode: apply` overwrites seed-defined settings on startup; omitted fields
survive. `create_only` preserves API edits to existing tenants. CAPTCHA seed
credentials are operator secrets and are encrypted before persistence.

## Runtime and stored-only fields

Name, logo and escaped support links affect hosted pages. Audience/directory,
logout allowlist, hosted locales, device flow, PAR and callback-confirmation
settings use their existing runtime consumers. Explicit audience/realm wins
over tenant defaults. Hosted language choices are separate from console language.
An empty device mask uses the runtime default; a schema-valid but unusable
nonempty mask safely refuses device authorization.

All `flags` are stored-only except read-only `disable_impersonation`; none
silently enables a legacy endpoint. The linked inventory lists every nested
field and its owner. Stored-only families include error-page HTML/default
redirection, sandbox versions, token quotas, access-token claim mapping,
security headers, anonymous sessions/logout toggles, MFA/organization options,
mTLS/DPoP, resource indicators, dynamic registration, phone/country controls,
AI/vendor UI options and session-log metadata. These settings round-trip but
do not activate those features. The existing issuer response behavior is
unchanged by `authorization_response_iss_parameter_supported`.

See [attack protection](attack-protection.md) for shared limits, provider
configuration and operator recovery, and [D-0045](compat/decisions.md#d-0045-tenant-settings-and-protection-evidence-boundaries-plan-19)
for observation versus local-fallback boundaries.
