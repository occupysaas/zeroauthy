# Plan 37b — WS-Federation (the `wsfed` addon) and ADFS connections

**Date:** 2026-11-16. **Status:** implemented 2026-11-22 (D-0140; [implementation record](../2026-11-22-plan-37b-implementation-record.md)); merge pending CI and maintainer approval.

**Roadmap entry:** [management roadmap, Plan 37](2026-10-19-zeroauthy-management-roadmap-design.md);
[parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md) item **F3**
(track F, after F2 = Plan 37a, whose `internal/samlcore` this plan reuses).
Read the [clean-room policy](../../../CLEAN_ROOM.md) (Auth0's MIT
`node-wsfed` may be read and studied; provenance recorded), `AGENTS.md`,
the [Plan 37a spec](2026-11-16-zeroauthy-saml-design.md) and the
[Plan 36 spec](2026-11-16-zeroauthy-enterprise-oidc-design.md).

## 1. Outcome and scope

- **zeroauthy as WS-Federation IdP (passive requestor):** a client with
  the `wsfed` addon (and `callbacks` / `client_aliases`, where Auth0 keeps
  the configuration) signs users into WS-Fed relying parties (SharePoint,
  legacy .NET/WIF apps) at `/wsfed/{client_id}` with a SAML 1.1 assertion
  in a `RequestSecurityTokenResponse`, publishes federation metadata, and
  handles `wsignout1.0` / `wsignoutcleanup1.0`.
- **ADFS connections (`adfs` strategy):** zeroauthy as a WS-Fed relying
  party of an ADFS server (or any WS-Fed IdP): metadata from `adfs_server`
  or `fedMetadataXml`, thumbprint validation, claims mapping, HRD,
  sign-out.
- **Entra `use_wsfed`** (Plan 25's `waad` rejected option, F1 deferral):
  stays rejected unless Task 1 finds Auth0 still documents it for new
  connections (W1).

**Rule:** strict 1:1 with Auth0's documented behaviour; WS-Federation 1.2
(OASIS) and `node-wsfed` defaults where the docs are silent. Local rulings
**LR37b-n**, observation points **W1–Wn** in **D-0140** (F3 block
D-0140–0149).

### In scope

1. Client: `addons.wsfed` (presence enables; "configuration is stored in
   `callback` and `client_aliases`" — OpenAPI), `client_aliases` (realms
   accepted as `wtrealm`), callbacks as allowed `wreply`.
2. IdP endpoints: `GET /wsfed/{client_id}` and `GET /wsfed?wtrealm=…`
   (`wa=wsignin1.0`, `wtrealm`, `wreply`, `wctx`, `whr` → connection hint),
   `wa=wsignout1.0` / `wsignoutcleanup1.0`, federation metadata at
   `/wsfed/FederationMetadata/2007-06/FederationMetadata.xml` and
   `/wsfed/{client_id}/FederationMetadata/2007-06/FederationMetadata.xml`.
3. Token: SAML 1.1 assertion (`node-wsfed` default) signed with the
   tenant key, RSA-SHA256/SHA-256 by default, lifetime 8 h default
   (node-wsfed), wrapped in `t:RequestSecurityTokenResponse` with `Context`
   = `wctx`, POSTed as `wresult` to the `wreply` URL. Claims: the same
   profile mapper and `api.samlResponse` options as Plan 37a (Auth0 shares
   them between SAML and WS-Fed, W2).
4. `adfs` connections: `adfs_server` (metadata host or URL) xor
   `fedMetadataXml`, `signInEndpoint`, `thumbprints`, `prev_thumbprints`,
   `thumbprints_sha384`, `entityId` (default `urn:auth0:{tenant}:{connection}`),
   `user_id_attribute`, `should_trust_email_verified_connection`,
   `domain_aliases`, `set_user_root_attributes`, `icon_url`,
   `non_persistent_attrs`, `upstream_params` (stored-only), `tenant_domain`.
5. ADFS login: redirect to `signInEndpoint` with `wa=wsignin1.0`,
   `wtrealm` = `entityId`, `wctx` = attempt state; ACS
   `POST /login/callback` with `wresult`; validate the SAML 1.1 or 2.0
   assertion inside (signature by a thumbprinted cert, audience =
   `entityId`, validity, replay); map claims; identity
   `adfs|<connection>|<user_id_attribute or name identifier/UPN>` (W3).
6. Console, seed, Deploy CLI, docs, tests.

### Not in scope

- WS-Trust active endpoints (`/trust/13/usernamemixed`): not documented
  for new tenants (LR37b-1).
- JWT-in-WS-Fed (`node-wsfed` `jwt` option): not documented by Auth0
  (LR37b-2).
- SAML 2.0 token type for the IdP side unless documented (W4).

### Anti-goals

- Same XML anti-goals as Plan 37a (wrapping, XXE, replay, SHA-1 only by
  configuration), via `internal/samlcore`.
- **Open `wreply`.** `wreply` must be one of the client's callbacks
  (exact match, Auth0 callback wildcard rules); otherwise the error page.
- **Realm confusion.** `wtrealm` resolves to exactly one client
  (`client_id` or a `client_aliases` entry); aliases are unique per
  tenant (enforced at write, LR37b-3).

## 2. Evidence

- Management OpenAPI (read 2026-11-16): `ConnectionOptionsADFS` (fields
  above; `adfs_server` "federation metadata host or XML URL", errors when
  combined with `fedMetadataXml`; thumbprints "used with WS-Federation
  protocol"; `entityId` default), `addons.wsfed` ("WS-Fed (WIF) addon
  indicator. Actual configuration is stored in `callback` and
  `client_aliases`").
- `auth0/node-wsfed` (MIT, read 2026-11-16): lifetime default 8 hours,
  `rsa-sha256`/`sha256` defaults, SAML 1.1 assertions, RSTR wrapping with
  `Context`, `wresult` form post, metadata path
  `/FederationMetadata/2007-06/FederationMetadata.xml`.
- Auth0 docs on WS-Fed applications and ADFS connections (read at build
  time for endpoint paths and claim defaults, W5).
- OASIS WS-Federation 1.2 passive requestor profile; SAML 1.1.

## 3. Storage, console, tests

- Client `client_aliases` (unique per tenant) and `addons.wsfed` in the
  client JSON; ADFS options in connection JSON; replay and metadata cache
  from Plan 37a; WS-Fed session participants join Plan 37a's
  `saml_sessions` for sign-out cleanup; no new table expected (else one
  migration numbered at merge).
- Console: Addons → WS-Fed (realm aliases, callbacks, usage tab with
  metadata URL); Enterprise → ADFS create/detail.
- Seed, Deploy CLI four-cell round trip (`addons.wsfed`, `client_aliases`,
  `adfs` connections).
- Tests: IdP request table (`wtrealm` by ID and alias, `wreply`
  allowlist, `wctx` echo, `whr`), RSTR/SAML 1.1 shape and signature,
  metadata, sign-out cleanup; ADFS rules (xor of sources, thumbprints),
  login with a fixture WS-Fed IdP (built on `samlcore`), SAML 1.1 and 2.0
  tokens, replay, HRD.
- E2E `make e2e-wsfed`: a WS-Fed RP and IdP fixture (Node, small, written
  for the test with the Plan 37a npm SAML library if approved, or Go
  fixtures); Playwright both directions.

## 4. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR37b-1 | No WS-Trust active endpoints. |
| LR37b-2 | No JWT tokens in WS-Fed. |
| LR37b-3 | `client_aliases` unique per tenant. |

Observe later: **W1** Entra `use_wsfed` status; **W2** shared SAML/WS-Fed
response options; **W3** ADFS user ID format; **W4** SAML 2.0 tokens on
the IdP side; **W5** WS-Fed endpoint paths and claim defaults from the
docs.
