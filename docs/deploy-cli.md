# Auth0 Deploy CLI migration

Plan 20 pins `auth0-deploy-cli` 9.1.0 and records its resource inventory and
field-specific comparison rules in
[`tests/e2e/deploy-cli/manifest.json`](../tests/e2e/deploy-cli/manifest.json).
The local CLI lane covers the nonempty resource families marked `included`
in that manifest, including organizations and federated connections. Database
connections remain excluded from this matrix; the pinned handler does not
establish their migration compatibility. `attackProtection` is marked
`tool-unsupported` because it queries the unimplemented phone-provider-protection
API. Direct SDK/API coverage remains authoritative for those resources.
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
