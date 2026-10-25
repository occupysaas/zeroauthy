# Tenant email

zeroauthy can send account and security email through a tenant's configured
provider. Existing installations with no enabled tenant provider continue to
use the server-wide email driver (`log`, `dir` or `smtp`). An enabled tenant
provider is used exclusively for that send. A provider failure does not fall
back to the server driver, so a configuration problem cannot silently route a
tenant's mail elsewhere.

## Configure the server fallback

The server fallback is useful for development and for tenants without an
enabled provider. The default is the `log` driver and sender
`zeroauthy@localhost`. For a local directory capture, set:

```yaml
email:
  driver: dir
  dir: ./var/email
  from: no-reply@example.test
```

SMTP uses verified TLS by default. The `email.smtp.insecure` option is for
local test servers only. Tenant SMTP destinations are checked against the
outbound address policy; explicitly allow a local relay only when you intend
to use it:

```yaml
email:
  allow_local_smtp:
    - 127.0.0.1:2525
```

The allowlist accepts explicit host and port entries. Keep it empty in
production unless private-address delivery is required. Do not enable
`log_links` in a production environment: the log driver can otherwise print
reset links that grant account access.

## Configure a tenant provider

Use the admin console's **Emails → Provider** page or the tenant Management
API. Provider credentials are write-only: responses, exports and the console
never return secret values. A same-provider PATCH that omits credentials
preserves them; a supplied credential replaces that field. To change provider
kind, submit the new provider's required credentials in the same create/update
operation. Deleting a provider returns that tenant to the server fallback.

Supported executable providers are `smtp`, `sendgrid`, `mailgun`, `mandrill`,
`sparkpost`, `ses`, `azure_cs`, `ms365` and `resend`. Each accepts only the
credential fields listed by its Management API schema. Mailgun and SparkPost
support the documented EU region option. SMTP uses TLS and the shared outbound
destination policy. HTTP adapters use fixed HTTPS vendor endpoints and do not
follow redirects. Configure the provider credentials and sender with the
provider's own service; zeroauthy does not validate live vendor account status
when saving a provider.

`custom` is accepted only as disabled stored configuration. It does not run
Actions. A configured provider's send failure is reported as a failed or
uncertain send; zeroauthy does not switch providers or automatically retry a
message whose remote acceptance is unknown.

For multi-instance deployments, use the same SQL database and master key on
every server. Provider records and notification claims are shared through the
store. gRPC store plugins must be rebuilt against the email repository
contract; older plugins fail closed for those operations.

## Templates and workflows

Templates are tenant-scoped Liquid source. The renderer has no filesystem,
network, environment or arbitrary Go-function access. It bounds source,
context, nesting, loops, evaluation, output, runtime and concurrent renders.
Use Liquid's `escape` filter for user-controlled text inserted into HTML, for
example `{{ user.email | escape }}`. The original built-in templates escape
untrusted values. Invalid or unsupported syntax is rejected when a template
is saved.

The console marks each template as active or stored-only. Verification and
reset templates (`verify_email`, `reset_email`) affect their corresponding
flows. `welcome_email` can send once after a user's email is verified (or after
a trusted signup that is already verified); it is disabled by default.
`blocked_account` and `stolen_credentials` notify the canonical local user
after the corresponding authoritative security event. Messages to unknown
identifiers are never sent. The remaining code, MFA, invitation and approval
templates are stored and can be previewed or test-sent, but their workflows
are not implemented. `custom` provider execution is also stored-only.

Template `resultUrl` values used for verification or reset must satisfy the
email-ticket redirect rules: HTTPS and, when an application is associated, an
exact registered callback match. Templates cannot change OIDC
`redirect_uri`, verification state or ticket single-use behavior. No record
keeps the existing localized verification/reset template behavior. An
explicitly disabled active template suppresses that email rather than
silently selecting a different template.

## Preview and test send

Preview renders the saved template (or the unsaved console edit) with
synthetic values and inert `.invalid` links. Its HTML is shown in an isolated
sandbox and is not inserted into the console DOM. Preview creates no ticket
and sends no email.

Test send uses the saved template and sends only to the authenticated,
verified operator's address. The request cannot select a recipient or a real
account URL. Stored-only templates may be tested; this does not activate
their workflow. Preview is limited to 30 attempts per operator and tenant per
fixed UTC minute. Test send is limited to three attempts per operator and
tenant per fixed UTC ten-minute window. A started send consumes an attempt,
including when the response is lost or the remote result is uncertain.

Email delivery is at-most-one attempt for these windows and for welcome and
security notification claims, not guaranteed delivery. A failed or uncertain
send keeps its claim to prevent duplicate security messages. There is no
automatic delivery retry queue. An accepted provider response means accepted
for processing; it does not prove inbox delivery.

## Deploy CLI migration

The pinned `auth0-deploy-cli` exports provider and template resources in YAML
and directory formats. Provider secrets are omitted from zeroauthy's public
Management responses. The CLI may add credential placeholder strings such as
`##SENDGRID_API_KEY##` to its export; those placeholders preserve an
already-configured destination credential and cannot configure a new
destination. Provision secrets separately through an operator-controlled
secret store or private Management API request. Never commit provider secrets
to migration fixtures or seeds. Re-export and compare after import to verify
public settings and templates; a public export cannot verify secret values.

The local deploy-cli 9.1.0 test lane covers YAML and directory imports with
generated and preserved client credentials. Its database, generic connection
and attack-protection handlers remain unsupported for the documented reasons
in the [compatibility record](compat/matrix.md). No live upstream tenant was
used for this work.

For source references, local choices and evidence limits, see the
[email contract observation](compat/observations/management-email.md) and
[decision D-0047](compat/decisions.md#d-0047-email-provider-and-template-contracts).
