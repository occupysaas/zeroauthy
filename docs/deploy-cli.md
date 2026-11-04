# Auth0 Deploy CLI migration

Plan 20 pins `auth0-deploy-cli` 9.1.0 and records its resource inventory and
field-specific comparison rules in
[`tests/e2e/deploy-cli/manifest.json`](../tests/e2e/deploy-cli/manifest.json).
The local CLI lane covers the nonempty resource families marked `included`
in that manifest, including organizations and federated connections. Database
connections remain excluded from this matrix; the pinned handler does not
establish their migration compatibility. `attackProtection` includes phone-provider protection (`default` and
`exponential`; `exponential` is stored but not enforced in 1.0, see
[attack protection](attack-protection.md#phone-provider-protection)). Focused tests run unmodified Deploy CLI 9.1.0 handlers and the
lockfile Auth0 SDK 7.4.0 against local Management handlers, including Guardian
phone settings, selected-provider and message-types. Full YAML/directory
migration acceptance remains a separate lane.
Rules, hooks and their configurations are finite empty compatibility
collections; they do not execute scripts.

The strict comparator is local:

```sh
go run ./tests/e2e/deploy-cli validate-manifest --registry FILE --manifest tests/e2e/deploy-cli/manifest.json
go run ./tests/e2e/deploy-cli compare --source SOURCE --target TARGET --format yaml --manifest tests/e2e/deploy-cli/manifest.json
go run ./tests/e2e/deploy-cli exclusions --manifest tests/e2e/deploy-cli/manifest.json
```

It compares included nonempty resource families, validates client/API/grant
references before mapping generated IDs, and compares referenced file bytes by
hash. Differences contain paths and reasons, never resource values. Script
files remain inert data. A local `make e2e-deploy` run invokes the pinned CLI in
YAML and directory modes. Each format runs against fresh destinations in
both generated-ID and credential-preserving modes. The local checks cover
repeat-import ID/secret stability, tenant-setting and grant updates, target-only
application survival with deletion disabled, an intentionally changed-scope
comparison, reserved API-name collision detection, and imported-client token
issuance. `make e2e-deploy` runs in CI. These local results do not establish
upstream Auth0 parity; the separate observer lane remains unavailable.

The runner uses the pinned tool's `AUTH0_EXCLUDED_CLIENTS` option to exclude
its explicitly named source and target deployment accounts. It does not
relax comparison to hide arbitrary additional applications. Check client-name
uniqueness before using name-based exclusions. Target-only resource survival
is verified through separate API inventory before strict export comparison.

Example export/import commands with protected configuration files:

```sh
a0deploy export --config_file ./source-private.json --format yaml --output_folder ./source-yaml
a0deploy export --config_file ./source-private.json --format directory --output_folder ./source-directory
a0deploy import --config_file ./target-private.json --input_file ./source-yaml/tenant.yaml
a0deploy import --config_file ./target-private.json --input_file ./source-directory
```

Set `AUTH0_ALLOW_DELETE` to `false` and copy the exact manifest-generated
exclusion array into each configuration. Keep configuration files mode `0600`
and export directories mode `0700`. Run `preflight-inventory` with the source
Management API's resource-server collection before exporting: a user API named
`Auth0 Management API` must stop the migration, since the pinned exporter
omits that name. Only the known built-in API receives the naming upgrade;
its identifier, IDs and scopes remain stable.

## Preserving client credentials on a fresh destination

Ordinary Auth0 Deploy CLI exports omit client secrets and may omit IDs.
For bootstrap, create a separate metadata export with `--export_ids` (or
`AUTH0_EXPORT_IDENTIFIERS: true`). Use that export for `migration bootstrap`;
use the ordinary export for `a0deploy import`, whose name/reference matching
then updates the pre-created applications without sending read-only IDs to
public create endpoints. The bootstrap command
merges those client properties with secrets from a separate protected JSON
file and applies them only when creating one fresh, ordinary destination
tenant. Use a configuration with `seed_mode: create_only`, durable storage,
and a master key. The local bootstrap seed contains exactly one destination
tenant, its local zeroauthy Management API client/grant, and destination
domains. Never use an overwrite-mode seed after import: it may replace the
destination state.

Example credentials file (mode `0600` or stricter):

```json
{
  "source-confidential-client-id": "source-client-secret"
}
```

Check a prepared bootstrap without writing:

```sh
zeroauthy migration bootstrap \
  --config zeroauthy.yaml \
  --input ./source-export \
  --format directory \
  --bootstrap-seed ./destination-bootstrap.yaml \
  --credentials-file ./client-credentials.json \
  --exclude-client-id SOURCE_TOOL_CLIENT_ID \
  --check
```

Remove `--check` to apply. Exclusions are repeatable and explicit. A matching
rerun checks tenant identity, immutable client authentication, credentials and
grants and then returns without reseeding. Partial or changed destinations
fail for operator reconciliation; the command does not silently rotate
credentials or resume by replacing them. Ephemeral memory storage is refused.

The upstream observer helper only exports. It never imports to Auth0. Store
observer exports in restricted locations and do not attach raw exports or
credential files to issues or logs.

Plan 22 adds nonempty branding settings, the active default theme, prompt
settings, custom text and partials to the strict local round trip. Each family
has a negative comparison that must detect a changed field or file. Theme IDs
are matched only through the exported theme's stable display name; no other
theme fields are dropped. Directory prompt settings/custom-text/partials files
are combined without executing Liquid.

Plan 23 supersedes the former unavailable-template lane. Real custom-domain
inventory lets pinned Deploy CLI 9.1.0 export a nonempty Universal Login
`body`; strict comparisons retain template content in YAML and directory modes.
GET also preserves the `template` alias for existing SDK consumers. ACUL remains
excluded and is not counted as a successful empty export.

## Staged custom-domain migration

A destination's global hostname registry owns its domain declarations. Use a
separate destination deployment for a same-hostname migration; two tenants in
one deployment cannot both own that hostname. Never transport proxy keys,
certificate/account private material, origin aliases or target-specific proofs.
Keep original source exports for strict comparison, and prepare import copies
that remove target-local IDs, status, verification, certificate, timestamps and
`origin_domain_name`. This is explicit import preparation, not permission to
ignore user settings or silently drop a resource family.

Import declarations with `is_default: false` first. Publish each destination's
new TXT proof and verify through its Management API. Only then import the final
source default. A one-shot import selecting an unverified default must fail;
CLI import may already have applied earlier declarations, so inspect the target
before retrying. For a canonical-default source, explicitly PATCH the target's
`custom-domains/default` with its canonical hostname before final import: pinned
CLI only applies `is_default:true` and cannot clear an old custom default.

The API supports `x-azure-clientip` and empty-string disabled override, but
pinned CLI accepts only `true-client-ip`, `cf-connecting-ip`, `x-forwarded-for`
or null. Its import rejects the two API-only values. These are tool-unavailable
round trips: choose a supported source configuration explicitly, or migrate
those fields through the Management API outside CLI; never normalize them away.

Comparisons preserve domain/type/header/TLS/metadata/RP/default/template values.
Read-only IDs and proof state are destination-local. The dedicated lane checks
missing and changed values, repeat stability, explicit default preparation and
all four YAML/directory × generated/preserved credential modes. See
[custom domains](custom-domains.md) for ownership, origin and rollout rules.

## Roles and permissions (Plan 26)

The local migration lane includes tenant role definitions and their API
permissions, plus resource-server `enforce_policies` and `token_dialect`.
Import APIs before role permissions. The comparator resolves roles by logical
name and permission keys by API identifier and permission name; generated role
IDs are not stable migration identities. Directory exports read the `roles`
folder as well as YAML's `roles` collection. Missing roles, permission edges or
RBAC settings cause comparison failure.

User-role and direct user-permission assignments are separate Management API
operations; the Deploy CLI resource inventory does not imply those assignments
were migrated. The local lane assigns a fixture user after import and verifies
actual federated login/token enforcement. See [roles and permissions](rbac.md)
for scope ceilings, token profiles and storage-plugin upgrade requirements.

Plan 29 adds nonempty **organizations** to every cell of the same four-cell
matrix. Fixtures include display names, branding colors, metadata and enabled
enterprise connections with different automatic-membership/button flags. The
strict comparator matches organizations and their connection references by
name and retains all connection policy fields. API reads after import verify
that the organization links exist. Application `organization_usage`,
`organization_require_behavior` and `organization_discovery_methods` also
survive import, including the offline credential-preserving bootstrap.

Plan 30 extends the fixtures to disabled and enabled associations, local
connection names, entitlement state, third-party policy and application
associations (`use_for_member_access` true and false). These fields use the
pinned tool's organization handler; no new tool resource family is invented.
The comparator treats connections, application associations, grant associations
and domain declarations as sets while comparing every policy field.

Offline `LoadExport` and credential bootstrap preflight reject unsupported
organization keys, token quotas, invitation material, nondefault
`organization_member_access_level`, active grant `organization_usage` and
`allow_any_organization`. The 9.1.0 organization schema/update mapping does not
carry member access policy; the observed default `limited` remains compatible.
Its client-grant schema does not declare the two active grant policy fields.
Default deny/false from API reads is inert and accepted. Direct use of upstream
`a0deploy` bypasses our offline validation; use the preflight/credential staging
path before importing policy-bearing exports.

Discovery-domain configuration is supported by create-only seed. Domains start
pending and require an explicit destination Management API PATCH to attest
verified; importing verified status fails offline preflight. Domain proof fields
are destination-local and are not portable attestation. This matrix does not
claim discovery-domain or grant-association round trips. The upstream tool maps
organization grant associations using application name alone, which cannot
represent multiple audiences unambiguously. Use explicit seed client/audience
references for those associations.

The pinned tool exports **no members or member roles**, invitations, acceptance
receipts, ticket URLs or ticket secrets. Their migration is unavailable in this
matrix, not a passing migration test. Use the Management API or create-only
seed references for members and member roles. Create new invitations at the
destination; bearer tickets and acceptance receipts are never portable.

`make e2e-organizations` independently exercises the pinned Management SDK,
CLI, SPA SDK, hosted organization pages and console against local zeroauthy.
No Auth0 tenant requests are made by either local lane.

## Log streams (Plan 31)

Seed tenants may declare `log_streams` using the Management API's public
configuration fields, plus optional `id` and initial `status`:

```yaml
tenants:
  - name: example
    log_streams:
      - id: lst_audit
        name: Audit delivery
        type: http
        status: paused
        sink:
          httpEndpoint: https://logs.example.test/intake
          httpContentFormat: JSONARRAY
          httpAuthorization: ${AUDIT_AUTHORIZATION}
          httpCustomHeaders:
            - header: X-Audit-Key
              value: ${AUDIT_HEADER_KEY}
        filters:
          - {type: category, name: auth.login.success}
        pii_config:
          log_fields: [email]
          method: hash
          algorithm: xxhash
```

Streams are **create-only in both seed modes**. An explicit ID identifies an
existing stream even after a console rename. Without an ID, the name must
uniquely identify a stream within that tenant. Names and explicit IDs must be
unique in each seed tenant; ambiguous existing names or an explicit new ID
colliding with an existing name fail. Reapplying never overwrites configuration,
rotates credentials, resets checkpoints or resumes paused/suspended streams.
Existing streams are skipped before reading environment variables, so their
credentials need not remain in the seed environment after creation.

Every secret string is a whole `${ENV_NAME}` reference. Custom header names
remain literal; each header value is an environment reference. Missing or empty
variables fail a new creation atomically. Literal credentials and partial
interpolation are rejected. Public fields are not expanded. Secrets are sealed
under the master key and bound to the tenant, stream ID and immutable sink type.
Seed uses the secure HTTPS default; the API's explicit deployment override is
needed to configure development HTTP endpoints. `eventbridge` and `eventgrid`
are stored suspended and are never delivered locally.

The [documented Deploy CLI](https://auth0.com/docs/deploy-monitor/deploy-cli-tool)
supports log stream configuration and keyword replacement. Our pinned **9.1.0**
handler is enabled in the local four-cell matrix (generated/preserved client
credentials × YAML/directory). HTTP and Datadog fixtures preserve name, type,
paused status, filters, PII configuration, priority and every public sink field.
The directory resource is `log-streams/*.json`; YAML uses `logStreams`.
The comparator matches streams by unique name and ignores only generated IDs.
Field-loss negatives exercise each configuration field.

Default tool exports replace `httpAuthorization` and `datadogApiKey` with
`##LOGSTREAMS_HTTP_SECRET##` and `##LOGSTREAMS_DATADOG_SECRET##`. These placeholders
carry no credentials. Supply fresh private values separately through
`AUTH0_KEYWORD_REPLACE_MAPPINGS`; the matrix checks the resulting encrypted
secrets directly in its isolated database. The API returns redaction markers
and cannot recover credentials, even if the tool requests secret export.
The tool strips initial `status` on create, so paused status is applied by a
subsequent update. It omits suspended status from exports; the matrix therefore
uses paused fixtures. Custom header values and secret-bearing Sumo URLs are
redacted by the server, but 9.1.0 does not generate keyword placeholders for
those fields; stage their credentials explicitly instead of importing markers.
Logs and daily statistics are never Deploy CLI resources.

Tool evidence: `auth0/auth0-deploy-cli` v9.1.0,
`lib/tools/auth0/handlers/logStreams.js`,
`lib/context/{yaml,directory}/handlers/logStreams.js`,
`lib/context/defaults.js` and `lib/tools/utils.js` (MIT). Public API fields follow
[Create a log stream](https://auth0.com/docs/api/management/v2/log-streams/post-log-streams).
No Auth0 tenant observation is used by these tests.

## Event streams (Plan 32)

Seed tenants may declare `event_streams` with the Management API create fields,
plus an optional stable `id`:

```yaml
tenants:
  - name: example
    event_streams:
      - name: User events
        status: disabled
        subscriptions:
          - {event_type: user.created}
          - {event_type: user.updated}
        destination:
          type: webhook
          configuration:
            webhook_endpoint: https://events.example.test/intake
            webhook_authorization:
              method: bearer
              token: ${EVENT_RECEIVER_TOKEN}
      - name: Action events
        subscriptions: [{event_type: organization.created}]
        destination:
          type: action
          configuration: {action_name: Receive events}
```

Streams are create-only in both seed modes. Existing IDs are authoritative,
including after a console rename; without an ID, the tenant's unique stream
name identifies an existing stream. Reapplying leaves its status, destination,
subscriptions, encrypted credentials, checkpoint and failure counters untouched,
and does not read its environment variables. Duplicate seed names/IDs and a
new explicit ID colliding with an existing name fail. New streams use the
current tenant checkpoint and the default ten-stream quota inside the seed
transaction. They do not replay existing events.

Webhook `password`, `token` and `header_value` must be whole `${ENV_NAME}`
references. The selected authorization method determines which credential is
required. Missing/empty variables, literal credentials and partial interpolation
fail creation; public username, header name and endpoint fields remain literal.
Credentials are encrypted with tenant/stream/destination binding and excluded
from public configuration. Seed uses HTTPS. `eventbridge` remains disabled.

For Action destinations, `action_id` resolves an existing Action in the same
tenant. Seed additionally accepts `action_name`, following seed trigger name
references; supply exactly one reference. The Action must support `event-stream`.
Actions declared in the same seed are built before stream creation. As with
other Action seed failures, ordinary seed data may already be committed if an
Action build or the later stream transaction fails; reapplying safely completes
missing resources.

Pinned Deploy CLI **9.1.0** now includes `eventStreams`. The local migration
matrix compares nonempty webhook and Action fixtures in YAML's `eventStreams`
and directory `event-streams/*.json`. It retains names, subscriptions,
destinations and disabled status; generated IDs, timestamps and the local
runtime failure count are not portable settings. Action references resolve
through each export's own Action inventory. Destination strings are opaque
configuration and are never treated as script/file references. Missing fields
and dangling Action references fail comparison. Events and delivery records
are not exported.

Default tool exports insert these nonsecret webhook placeholders:

| Method | Write-only field | Placeholder |
| --- | --- | --- |
| `basic` | `password` | `##EVENT_STREAM_WEBHOOK_BASIC_AUTH_PASSWORD##` |
| `bearer` | `token` | `##EVENT_STREAM_WEBHOOK_BEARER_TOKEN##` |
| `custom_header` | `header_value` | `##EVENT_STREAM_WEBHOOK_HEADER_VALUE##` |

Supply fresh credentials privately with `AUTH0_KEYWORD_REPLACE_MAPPINGS` before
creating a destination stream. The local fixture stages its own explicit
keyword; the comparator accepts only the pinned tool's exact method-specific
export placeholders and rejects actual credential values. Exports cannot
recover source credentials, including with secret export requested. An update
that omits the credential preserves it when the authorization method stays the
same. Method changes require a fresh credential. Runtime checks verify initial
private reinjection, explicit rotation and retention after a pinned CLI import
omitting the token, plus execution of the imported Action. These results prove
public configuration migration and destination credential provisioning; they
do not claim that source secrets round trip.

Tool provenance: `auth0/auth0-deploy-cli` v9.1.0 (MIT),
`lib/context/defaults.js`,
`lib/context/{yaml,directory}/handlers/eventStreams.js` and
`lib/tools/auth0/handlers/eventStreams.js`. The tool is exercised only against
local zeroauthy. No Auth0 tenant observation was performed.

## Passwordless and phone provisioning

Seed supports `email`/`sms` passwordless connections, one `phone_provider`,
`phone_templates`, and Guardian `phone_settings`, `phone_selected_provider`,
`phone_message_types`, `phone_providers`, and `phone_templates`. Provider and
connection credentials use whole `${ENV_VAR}` references and are sealed before
storage. Guardian write-only fields use the same references. Existing phone
provider/template seed identities preserve operator edits; Guardian phone
settings follow the enclosing tenant seed mode. Database phone identifier
enables run the same conflict pre-check as the Management API.

The Guardian phone handlers (except `guardianFactorProviders`, which the CLI
itself cannot export; see [mfa.md](mfa.md#deploy-cli-and-troubleshooting)) and
`attackProtection` are included in the pinned manifest. Branding `phoneProviders` and `phoneTemplates` retain their explicitly
excluded migration status until an unmodified pinned handler export/import
lane proves secret reinjection, generated identities and template defaults.
Native SNS is a zeroauthy extension and is outside the pinned provider schema.
Use the direct API or seed for these resources; see [phone providers](phone-providers.md)
and [passwordless](passwordless.md). This is not a claim of four-cell migration
acceptance for new phone resources.
