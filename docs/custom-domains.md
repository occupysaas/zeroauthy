# Custom domains and certificates

A tenant keeps its pinned canonical hostname and Management API audience. The
Custom domains console page adds separately verified public authentication
hosts. These hosts have their own issuer, cookies and authentication grants.
A deployment-wide registry prevents another tenant, an operator alias or a
private origin from claiming the same normalized hostname.

## Rollout and existing tenants

Back up the database and the deployment's master key before schema migration
0020. Drain and stop **all older nodes** before migrating. Do not serve a mixed
fleet: older resolvers do not understand pending claims, origin bindings or
fenced certificate state. Apply migrations, start the new nodes with identical
hostname configuration and wrapper keys, check readiness, then restore traffic.

Startup pins canonical identity and reconciles existing operator/seed aliases.
It preserves legacy alias bytes/order and existing API audiences. Conflicting
ownership or canonical configuration drift requires operator reconciliation;
startup never silently rotates an audience. Seed `domains` remains privileged
operator configuration; it does not prove or activate an API-created domain.
Omitting seed aliases preserves API-owned domains. A tenant with no hostname
and no base domain remains unroutable until an operator assigns its first host.

Legacy grants, sessions, codes, PAR, device codes and tickets with empty origin
belong to the pinned canonical origin. Pre-upgrade noncanonical artifacts need
reauthentication or ticket reissue. A first presenter cannot bind old grants to
an alias. Default changes do not retarget existing grants or queued mail.

For rollback, stop the new workers and listeners first. Restore a pre-upgrade
database backup with the matching wrapper key before starting the old binary
against the old schema. Do not point an old resolver at the new database's
pending aliases. Restoring a backup also rolls back grants and configuration;
plan the outage and recovery with that state boundary in mind.

## Managed TLS configuration

Static TLS and externally terminated HTTP remain available when ACME is off.
Automatic certificates require explicit deployment opt-in. For example:

```yaml
server:
  listen: ":443"
  base_domain: auth.example.com
  tls_cert_file: /run/secrets/canonical-chain.pem
  tls_key_file: /run/secrets/canonical-key.pem
  custom_domains:
    origin_domain: auth.example.com
    dns_resolver: "192.0.2.53:53" # replace with your reachable DNS resolver
  acme:
    enabled: true
    directory_url: https://acme-v02.api.letsencrypt.org/directory
    email: operations@example.com
    terms_accepted: true
    deployment_id: production-auth
    challenge: http-01
    http_listen: ":80"
    workers: 2
security:
  master_key_file: /run/secrets/zeroauthy-master-key
```

`directory_url` must use HTTPS. `dns_resolver` defaults to the first system
resolver. `workers` accepts 1–8. The stable deployment ID, directory URL and
master key must match across replicas. A CA bundle file (`ca_bundle_file`) adds
trust for a private CA without disabling verification. Changing deployment ID,
directory or wrapper key makes the old encrypted material unreadable; startup
or issuance must report the mismatch rather than replacing the account key.

HTTP-01 needs public TCP 80 forwarded to the HTTP challenge listener. It serves
exact active challenge tokens, and redirects only GET/HEAD for active registered
hosts. TLS-ALPN-01 instead needs public TCP 443 reaching zeroauthy's TLS listener
without ALPN termination; set `challenge: tls-alpn-01` and `http_listen: ""`.
There is no automatic fallback. Static certificates must cover canonical and
system hosts not covered by the hosted wildcard; they are not implicitly issued.
Unknown SNI and expired certificates fail. Handshakes never perform DNS lookup,
place orders or call a DNS provider.

Workers share encrypted account/order/private-key/certificate/challenge state
through the configured store. Storage-clock leases last 120 seconds and renew
every 30 seconds; publication checks fencing and domain generation inside the
transaction. CA/DNS I/O stays outside transactions. Interrupted saved orders can
resume, but exactly-once CA orders after a lost reply are not guaranteed.
Renewal begins at two-thirds of actual certificate lifetime with up to 5%
deterministic jitter. A failed renewal retains a valid old certificate; expiry
always denies serving. Monitor certificate expiry, retry/failure status, worker
health and DNS proof loss rather than assuming that a once-ready domain stays
usable forever. Back up wrapper keys together with the encrypted database.

## Proof, routing and defaults

Create either `auth0_managed_certs` or `self_managed_certs`. Creation is pending;
copy the returned TXT record exactly and use Verify after DNS propagation.
TXT ownership proof is distinct from CNAME/address routing to the serving
listener. Only `txt` verification and `recommended` TLS policy are supported.
Hostname inputs use IDNA, reject IPs/ports/wildcards/reserved namespaces and
have a global normalized owner. There are at most 100 API-owned domains per
tenant; metadata allows ten strings of at most 255 Unicode characters each.

Proof checks have a five-second budget and at most eight CNAME hops. Verification
and diagnostics share distributed limits of one attempt/domain/30 seconds and
20 attempts/tenant/minute; a refusal returns Retry-After. Initial proof retries
back off through 1m/5m/15m/1h/6h and pause at 72 hours. An established domain
has a 24-hour proof-loss grace period. Manual Verify can restart proof checks.
A managed domain becomes ready only after proof and valid certificate publication.

A ready custom domain may be selected as the notification default. The console
distinguishes a configured default from a currently usable one. PATCH
`/api/v2/custom-domains/default` with `{"domain":"<canonical-host>"}` restores
the canonical default. An unavailable implicit default falls back to canonical
without erasing the pointer. An explicit `auth0-custom-domain` selection must
be a usable same-tenant host, or the request fails before creating a ticket/job.
Queued verification-email jobs retain their selected origin; if that host loses
readiness or ownership, the job fails visibly and sends nothing. It never
silently retargets. Authentication-triggered mail keeps its originating host.

Codes, refresh tokens, sessions, PAR, device flows and tickets are origin-bound.
Cross-host redemption is rejected before consumption/rotation or protection
mutation. Management API tokens must have the serving public issuer while the
canonical API audience stays stable. System console operators use their separate
system issuer. Public Liquid context exposes only `custom_domain.domain` and
metadata; proof, origin aliases, keys and certificate internals stay private.

## Customer proxies and one-time keys

Self-managed domains require a configured origin suffix with TLS coverage and
explicit `server.trusted_proxy_cidrs`. Configure the customer's proxy to dial
the returned `origin_domain_name`, preserve the intended TLS SNI/Host pairing,
and supply `cname-api-key`. Only the first successful explicit Verify returns
the key, after its hash and ready state commit. Save it directly to the proxy's
secret manager. Reads, lists and exports cannot recover it; a lost or uncertain
verify reply requires delete/recreate and fresh proof. Repeated verification
does not rotate or reveal a new key. The console clears the transient secret on
navigation and does not persist it in browser storage or URLs.

The immediate peer CIDR, key, active domain/generation and Host/SNI must all
match. Public self-managed hosts also require proxy authentication. A proxy key
for one tenant cannot authenticate another. `X-Forwarded-Host` cannot choose a
new tenant or origin. Managed domains require direct TLS with matching Host/SNI.
After successful proxy admission, the configured client-IP header must contain
one IPv4/IPv6 address, without comma lists, ports or zones. Missing/invalid values
return 400 before attack-protection changes. Null or empty disables the override
and uses the peer. Proxy secrets and forwarding headers are stripped before
scripts/handlers/logging. The admitted address feeds shared attack protection.

The legacy `trust_proxy_headers` boolean remains for non-custom routes. Without
trusted CIDRs it emits a deprecation warning; migrate to an explicit peer allowlist.
Do not authorize arbitrary public peers as trusted proxies.

The Test operation probes only the known domain's HTTPS discovery document.
It enforces a ten-second/64-KiB budget, at most two pinned globally routable
addresses, certificate/hostname trust and same-origin endpoints, without
redirects or environment proxies. Private/mixed DNS answers are refused.
`success: true` describes this bounded probe, not all customer proxy settings.

## Deployment-owned wildcard

For one-label tenant/system hosting, enable:

```yaml
server:
  acme:
    hosted_wildcard:
      enabled: true
      zone: example.com
      token_file: /run/secrets/digitalocean-token
```

This requires ACME plus a portless `base_domain` contained in that DigitalOcean
zone. The worker issues the apex and `*.base_domain` through DNS-01. It does not
cover arbitrary-depth or unrelated customer names. The token is deployment-owned;
it is never stored in tenant settings or exported. Provider calls use the fixed
DigitalOcean API host with ten-second deadlines. Propagation has a ten-minute
budget; CNAME/NS challenge delegation is unsupported. Cleanup deletes only owned
record IDs/values and preserves unrelated simultaneous TXT records. Hosted retry
backoff is per worker in memory, so restart can retry earlier; leases still
serialize replicas and the certificate controls renewal eligibility.

## API, tools and limits

The nine operations are list/create/read/update/delete, verify, test and
get/set default under `/api/v2/custom-domains`. They require their corresponding
`read/create/update/delete:custom_domains` scopes; Test uses update locally.
Bodies are limited to 64 KiB. The supported list query is a finite documented
subset, not arbitrary Lucene. See the [frozen inventory](../internal/customdomain/inventory.json)
and [evidence notes](compat/observations/custom-domains.md).

`relying_party_identifier` is validated and stored only; WebAuthn enforcement
belongs to a later milestone. Custom public signing JWKS remains stored-only;
TLS certificates never become token-signing keys. Exact upstream tenant behavior
was not observed. Local lifecycle, proxy trust, errors and hosted wildcard are
explicit engineering choices, not a certification claim.

See [Deploy CLI migration](deploy-cli.md) for staged declaration/proof/default
imports, API-only header values and template-body export. No migration transports
proxy keys, target-specific proof or certificate material. ACUL stays excluded.
Local acceptance uses pinned Pebble, authoritative DNS and a fake DigitalOcean
API; real CA orders/provider writes require separate operator action.
