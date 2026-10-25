# Management API behavior used by auth0-deploy-cli

- **Reviewed:** 2026-10-25
- **Tool:** `auth0-deploy-cli` 9.1.0, MIT, npm registry package, source tag `v9.1.0`, git commit `b8178b4bf48f31d05e61f55918bba75d4c846c37`.
- **Evidence boundary:** public package/source and existing sanitized observations only. No upstream export was run by this implementation session.
- **Inspected package paths:** `lib/tools/auth0/handlers/index.js`, each registered `lib/tools/auth0/handlers/*.js`, `lib/context/{yaml,directory}/handlers/*.js`, `lib/tools/auth0/index.js`, `lib/readonly.js`, `LICENSE`.
- **Package provenance:** `npm view auth0-deploy-cli@9.1.0` returned version 9.1.0, MIT, the commit above and npm tarball `auth0-deploy-cli-9.1.0.tgz` (sha512 integrity begins `OOMHY6kJnPUOF`, npm shasum `06b641b3b579176229dcbee6e9cfd10e3e82ac65`).

## D1 inventory summary

- Registry is the `auth0ApiHandlers` object in the pinned `lib/tools/auth0/handlers/index.js`; it registers 49 handler keys, including `clientAuthCredentialsPre` as a deploy-only pre-pass. Task 1's manifest inventories every registry key. The public `AUTH0_EXCLUDED` config filters `handler.type`, so Task 9 validates exact type names from installed 9.1.0 before running.
- The pinned tool has YAML and directory serializers under `lib/context/yaml` and `lib/context/directory`. Directory exports split resource families into files/directories and support file references; YAML stores resource collections in one tenant document and supports references. The local fixtures exercise both through the unchanged CLI.
- Existing observations establish: clients match by `client_id`, then name; client secrets and read-only runtime/system fields are omitted; database connections match by name then ID and enabled clients are applied through a dedicated endpoint; resource servers match by ID then identifier and the Management API is excluded by its name; grants use ID then client/audience/subject identity, with the tool's own and system grants excluded. See `management-clients.md`, `management-apis.md` and `management-connections.md` for sanitized details.
- Exported client credentials are not available in ordinary tool exports. Preserving IDs/secrets therefore uses the separate protected create-only bootstrap; generated-ID mode uses explicit reference mapping. Export equality alone does not prove behavior for fields stored but not enforced.
- The minimum local nonempty included families are `clients`, `resourceServers`, `clientGrants`, `databases`, `connections`, `tenant` and `attackProtection`. `databases`/`connections` are distinct pinned handlers and both receive fixtures.
- The local harness sets `AUTH0_ALLOW_DELETE=false`, validates `manifest.json`, records the actual installed version and compares resource counts, relationships and file hashes. Upstream observer export remains a separate lane; it is unavailable until an authorized observer supplies a sanitized report.

## D2 retired-resource boundary

Pinned handler paths are `lib/tools/auth0/handlers/{rules,rulesConfigs,hooks}.js`; the adapters live under the corresponding YAML/directory handler paths. Only the documented collection read paths needed for export are in the Plan 20 shim inventory: `GET /api/v2/rules`, `GET /api/v2/rules-configs`, and `GET /api/v2/hooks`. These collection handlers are separate from signing-key APIs and do not authorize wildcard fallback routing. Task 6 checks required read scopes and rejects writes for unsupported execution features. Exact tenant-specific error identifiers remain a local contract because no observer report was supplied.

## Changelog review

The public Auth0 changelog was reviewed from the 2026-10-22 repository review through 2026-10-25. No signing-key, retired-resource or deploy-cli contract change affecting Plan 20 was found. The 2026-10-21 Agent Mode item is unrelated to these surfaces. This is a public changelog review, not live tenant evidence.
