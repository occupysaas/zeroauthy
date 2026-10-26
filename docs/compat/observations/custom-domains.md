# Custom domains source review — 2026-10-26

No live upstream observation was performed. A separate authorized observer is
unavailable. This file records public-source review and local decisions, not
observed parity. The executable inventory is
[customdomain/inventory.json](../../../internal/customdomain/inventory.json).

Reviewed public Management API create/list/get/update/delete/verify/test/default
references under https://auth0.com/docs/api/management/v2/custom-domains/ and
[managed](https://auth0.com/docs/custom-domains/auth0-managed-certificates) /
[self-managed](https://auth0.com/docs/customize/custom-domains/self-managed-certificates)
setup. Public create schema requires type, accepts TXT and recommended TLS only,
and documents four client-IP header names plus empty/null. Metadata has ten string
properties with 255-character values; no separate key-length bound is documented.
Public examples saying ready on creation conflict with the pending-verification
success description: local create remains pending. Public response enums are
pending_verification/ready/failed; verification verified/pending/failed; certificate
provisioning/provisioning_failed/provisioned/renewing_failed. Public CA enum names
are letsencrypt/googletrust; local production issuance uses the configured ACME CA.

node-auth0 7.4.0 (MIT), management/api/resources/customDomains/client/Client.mjs
and management/api/types/types.d.mts, corroborates all nine operations and fields.
Its nullable metadata value type is broader than the public string-value prose;
local null metadata values are rejected. Its source does not establish server
errorCode behavior. Public test documentation does not specify a scope; local
update:custom_domains is conservative. Standard existing Management error envelope
and status codes apply; upstream errorCode parity remains unobserved.

Local limits and differences: 253 normalized ASCII hostname bytes, IDNA lookup
mapping, public suffix rejection, one hundred API-owned domains, 64 KiB bodies,
quoted exact domain/status/type AND queries only (eight terms, 1024 bytes), and
sort domain:1 only. Empty arrays and objects are preserved. RP ID is stored-only.

Deploy CLI 9.1.0 (MIT), lib/tools/auth0/handlers/customDomains.js, supports only
true-client-ip, cf-connecting-ip, x-forwarded-for or null; API x-azure-clientip and
empty string must fail its migration lane without normalization. It imports
is_default:true after declarations and cannot clear a target default. Import
pending declarations, prove domains separately, then import defaults. For a
canonical-default source explicitly reset the target via the Management API first.
No proof, key or certificate is portable.

Deploy CLI branding.js exports a template only with nonempty custom-domain
inventory and reads payload.body. The [public GET contract](https://auth0.com/docs/api/management/v2/branding/get-universal-login)
returns body, while PUT accepts template. Add body to GET responses and retain the
existing template response alias for Plan 22 consumers; both contain the same
validated saved template. ACUL is excluded, not a successful empty export.

Local fixtures use an isolated container network, Pebble HTTPS directory on 14000,
management on 15000, challenge HTTP on 5002, TLS on 5001, authoritative DNS on
8053, and fake provider on 18080. Only loopback-published harness ports are used.
The DNS wire implementation is existing golang.org/x/net v0.61.0 dns/dnsmessage
(BSD-3-Clause); no new production DNS dependency. Fixture CA digest is recorded
with its compose definition once fetched; missing fixture access is unavailable,
never a passing issuance test. No public CA order or real provider write authorized.

Fixture pin resolved from the official GHCR 2.8.0 manifest: linux/amd64 image
`ghcr.io/letsencrypt/pebble@sha256:358790ea96cb0bafc00679fb117919c58fe11120276572d92c23b89152e5a24d`.
Pebble is MPL-2.0, isolated test service only; see tests/e2e/domains/fixtures.lock.json.
