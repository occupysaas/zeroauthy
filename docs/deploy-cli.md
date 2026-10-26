# Auth0 Deploy CLI migration

Plan 20 pins `auth0-deploy-cli` 9.1.0 and records its resource inventory and
field-specific comparison rules in
[`tests/e2e/deploy-cli/manifest.json`](../tests/e2e/deploy-cli/manifest.json).
The local CLI lane covers nonempty clients, resource servers, client grants,
and tenant settings. The manifest explicitly marks three pinned handlers as
`tool-unsupported`: `databases` always queries the unimplemented Actions API;
`connections` filters out the only implemented strategy (`auth0`); and
`attackProtection` queries the unimplemented phone-provider-protection API.
Their parser/reference fixtures and direct Management API coverage remain,
but this tool lane does not establish their migration compatibility. Future
provider/Actions/phone milestones own removal of these exclusions.
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
