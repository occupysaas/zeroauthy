# Email Management API contract evidence

Date: 2026-10-25  
Evidence class: public documentation and pinned open-source SDK; no live tenant observation.

## Sources

- Provider API: <https://auth0.com/docs/api/management/v2/emails/post-provider>
- Template create: <https://auth0.com/docs/api/management/v2/email-templates/post-email-templates>
- Template update: <https://auth0.com/docs/api/management/v2/email-templates/patch-email-templates-by-template-name>
- Provider overview: <https://auth0.com/docs/customize/email/smtp-email-providers>
- Liquid syntax: <https://auth0.com/docs/customize/email/email-templates/supported-liquid-syntax>
- Template variables and workflows: <https://auth0.com/docs/customize/email/email-templates/customize-email-templates>
- SDK inspected: `auth0` npm 7.4.0, MIT. The generated ManagementClient surface exposes provider `get/create/update/delete`, template `create/get/set/update`, scopes, ten provider names and fourteen template names, including `auth_email_by_code`.

No credentials, tenant identifiers or personal data were used. A separate authorized observer report was unavailable, so live-only behavior remains unverified.

## Frozen API contract

`internal/emailrules/inventory.json` records eight methods: provider GET/POST/PATCH/DELETE at `/api/v2/emails/provider`; template POST at `/api/v2/email-templates`; and template GET/PUT/PATCH at `/api/v2/email-templates/{templateName}`. It records scopes, success statuses and SDK method names.

The SDK documents required credentials for SMTP, SendGrid, Mailgun, Mandrill, SparkPost and SES. Its generated union also identifies Azure Communication Services as `connectionString` and MS365 as `{tenantId, clientId, clientSecret}`. Mailgun and SparkPost accept `region: "eu"` or null. SMTP settings may carry `headers`; SES settings may carry `message.configuration_set_name`. Provider protocol sources and endpoints are listed in the inventory. This record does not claim adapters are implemented.

## Local fallbacks, not upstream observations

Unconfigured GET is 404; duplicate create conflicts; PATCH requires an existing record; PUT replaces or creates a template; absent provider DELETE is idempotent; unknown fields and names are rejected; credentials are write-only; null and omitted fields are interpreted per the inventory. `reset_email` alone drives reset-link delivery; `change_password` and `password_reset` remain separate. Zero/null lifetime uses the established flow default and positive values cap at 604800 seconds. `custom` is accepted only disabled. These choices are not described as observed Auth0 behavior.

The SDK models `settings` as an open record and does not settle all vendor protocol details. Implementations use official vendor protocol references and reject settings that are not implemented. No live Management API calls, sends, provider-account checks or tenant observations occurred.
