# Plan 37a — SAML 2.0 (identity provider addon and service-provider connections)

**Date:** 2026-11-16. **Status:** ruled 2026-11-21 (§11); implementation in
progress on `plan-37a-saml`.

**Roadmap entry:** [management roadmap, Plan 37](2026-10-19-zeroauthy-management-roadmap-design.md)
(full; sub-project 4 of the core spec); [parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md)
item **F2** (track F, after F1 = Plan 36). F3 (WS-Federation, ADFS) and F4
(SCIM, self-service SSO) follow and reuse this plan's XML signing core.
Read the [clean-room policy](../../../CLEAN_ROOM.md) (open-source Auth0
code: `auth0/node-samlp`, MIT, may be read and studied; provenance
recorded), `AGENTS.md`, the [Plan 36 spec](2026-11-16-zeroauthy-enterprise-oidc-design.md)
(connection keys, HRD, global token revocation fields) and the
[Plan 24 spec](2026-10-26-zeroauthy-social-connections-design.md)
(federation core).

## 1. Outcome and scope

- **zeroauthy as SAML IdP:** a client with the `samlp` addon gets SAML
  2.0 Web SSO at `/samlp/{client_id}`, metadata at
  `/samlp/metadata/{client_id}`, single logout, IdP-initiated SSO, and
  Auth0's claim mapping (`mappings`, name-identifier probes, UPN, typed
  attributes), signed with the tenant's signing key.
- **zeroauthy as SAML SP:** a `samlp` connection signs users in from an
  external SAML IdP (Okta, Entra, ADFS-as-SAML, Shibboleth, …):
  `AuthnRequest` with HTTP-Redirect or HTTP-POST binding, signed
  requests, response/assertion signature validation, encrypted assertions,
  IdP-initiated logins, attribute mapping (`fieldsMap`), SP metadata,
  single logout, HRD through `domain_aliases` (Plan 36), connection keys
  (Plan 36's keys API gains `samlp`).

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first), SAML 2.0 Core/Bindings/Profiles/Metadata (OASIS) where Auth0 is
silent, and `node-samlp` defaults where Auth0's docs omit them (each such
default recorded with provenance and confirmed by E2E). Local rulings
**LR37a-n**, observation points **S37-1…n** in **D-0130** (F2 block
D-0130–0139).

### In scope

1. Client addon `addons.samlp` (OpenAPI members: `mappings`, `audience`,
   `recipient`, `createUpnClaim`, `mapUnknownClaimsAsIs`,
   `passthroughClaimsWithNoMapping`, `mapIdentities`, `signatureAlgorithm`,
   `digestAlgorithm`, `issuer`, `destination`, `lifetimeInSeconds`,
   `signResponse`, `nameIdentifierFormat`, `nameIdentifierProbes`,
   `authnContextClassRef`, plus `logout`, `binding`, `typedAttributes`,
   `includeAttributeNameFormat`, `signingCert` read at build time, S37-1).
2. IdP endpoints: `GET|POST /samlp/{client_id}` (SP-initiated
   `AuthnRequest`, Redirect and POST bindings; `connection` and
   `organization` query parameters as documented), IdP-initiated
   (`GET /samlp/{client_id}` without a request), `GET /samlp/metadata/{client_id}`,
   `GET|POST /samlp/{client_id}/logout`.
3. `samlp` strategy connections (OpenAPI `ConnectionOptionsSAML`: `cert` /
   `signingCert` / `thumbprints` / `thumbprints_sha384`, `metadataUrl`,
   `metadataXml`, `signInEndpoint`, `signOutEndpoint`, `destinationUrl`,
   `recipientUrl`, `entityId`, `protocolBinding`, `signSAMLRequest`,
   `signatureAlgorithm`, `digestAlgorithm`, `deflate`, `requestTemplate`,
   `fieldsMap`, `user_id_attribute`, `idpinitiated`, `disableSignout`,
   `decryptionKey`, `assertion_decryption_settings`, `signing_key`,
   `domain_aliases`, `debug`, `set_user_root_attributes`, `non_persistent_attrs`,
   `icon_url`, `global_token_revocation_jwt_iss`/`_sub` (with Plan 41a's
   endpoint)).
4. SP endpoints: ACS `POST /login/callback?connection=<name>` (Auth0's
   documented ACS form, S37-2), SP metadata
   `GET /samlp/metadata?connection=<name>`, SP single logout.
5. `/api/v2/connections/{id}/keys` for `samlp` (Plan 36 repository).
6. Organizations: SAML connections enabled on organizations and the
   `organization` parameter on the IdP endpoint (Plans 29/30).
7. Console, seed, Deploy CLI, docs, tests.

### Not in scope

- WS-Federation and ADFS (F3), SCIM and self-service SSO (F4).
- SAML artifact binding and the SOAP back-channel (Auth0 does not
  document them, LR37a-1).
- SAML ECP.
- (`api.samlResponse.*` is **in** scope, not out: the IdP addon needs the
  documented setters (§4.4) for the outgoing response; this closes A1's
  deferral, LR37a-2.)

### Anti-goals

- **XML signature wrapping.** Signature validation uses a library or code
  that verifies the referenced element by ID, re-parses only the signed
  bytes, rejects multiple assertions, comments-in-NameID tricks and
  external entity / DTD processing; the code path that reads attributes
  uses the verified element only.
- **Assertion replay.** Each assertion ID is single use for its validity
  window (store-backed, shared by replicas); `NotBefore`/`NotOnOrAfter`,
  `Audience`, `Recipient`, `InResponseTo` (for SP-initiated) checked with
  2 minutes of skew (LR37a-3).
- **Weak crypto by default.** SHA-1 signatures accepted only when the
  connection or addon explicitly selects `rsa-sha1` (Auth0 allows it);
  default `rsa-sha256`.
- **XXE / billion laughs.** DTDs refused; input ≤ 256 KiB; depth ≤ 50.
- **IdP-initiated login CSRF.** IdP-initiated SP logins are accepted only
  when `idpinitiated.enabled` is true, and land on the configured
  client and protocol, never on an attacker-chosen `redirect_uri` outside
  the client's callbacks.
- **Secrets in logs.** SAML responses are logged only with `debug: true`,
  and then with assertions' attribute values scrubbed by the key-name
  scrub; private keys never.

## 2. Evidence

- Management OpenAPI (read 2026-11-16): `ConnectionOptionsSAML` (fields
  above, with descriptions such as `entityId` "defaults to
  `urn:auth0:{tenant}:{connection}`", `thumbprints` "automatically computed
  from" the certs, `deflate` for HTTP-Redirect, `requestTemplate` with
  `@@variableName@@` substitution, `user_id_attribute`, `debug` issues `w`
  log events), client `addons.samlp` members.
- Auth0 "Configure Auth0 as SAML identity provider"
  (`/docs/authenticate/single-sign-on/outbound-single-sign-on/configure-auth0-saml-identity-provider`):
  Identity Provider Login URL `https://{tenant}/samlp/{CLIENT_ID}?connection=…`,
  custom domains, `organization` parameter, Application Callback URL = ACS
  URL, signing certificate download (`{tenant}.pem`), "login and logout
  are handled by the same URL".
- `auth0/node-samlp` (MIT, read 2026-11-16): defaults `lifetimeInSeconds`
  3600, `signatureAlgorithm` `rsa-sha256`, `digestAlgorithm` `sha256`,
  the claim-type namespaces of `PassportProfileMapper`
  (`…/claims/nameidentifier`, `emailaddress`, `name`, `givenname`,
  `surname`, `upn`, `http://schemas.xmlsoap.org/claims/Group`), name
  identifier probes. Each default is listed in D-0130 with file and
  commit.
- OASIS SAML 2.0 Core, Bindings, Profiles, Metadata; XML Signature 1.1;
  Exclusive XML Canonicalization 1.0; XML Encryption 1.1.

## 3. XML core

- One internal package `internal/samlcore`: parse (safe), canonicalize
  (exc-c14n with and without comments), sign and verify (enveloped
  signatures, RSA-SHA256/384/512 and RSA-SHA1 opt-in, ECDSA where the
  library supports it), encrypt/decrypt assertions (AES-128/256-GCM and
  -CBC data, RSA-OAEP / RSA-1_5 key transport, the latter refused unless
  configured, S37-3), build and parse AuthnRequest, Response, LogoutRequest,
  LogoutResponse, EntityDescriptor.
- The signing and canonicalization implementation is the §9.1 decision:
  (a) vendor `russellhaering/goxmldsig` (Apache-2.0) and `beevik/etree`
  (BSD-2) into `internal/third_party` like `argon2`, (b) add them as
  modules, or (c) write it in-tree. Recommended: (a).

## 4. IdP addon

### 4.1 Flow

1. SP sends `AuthnRequest` (Redirect or POST) to `/samlp/{client_id}`;
   zeroauthy validates issuer = addon `audience` or client callbacks
   (S37-4), optional request signature (when the client has a configured
   SP certificate, S37-5), `AssertionConsumerServiceURL` ∈ the client's
   callbacks (or the addon `recipient`), stores `RelayState`.
2. Normal hosted login (connection from `?connection=`, organization from
   `?organization=`, MFA, Actions).
3. Post-login Actions run with `event.transaction.protocol` `samlp`;
   `api.samlResponse.*` setters apply.
4. Response: signed assertion (and response when `signResponse`), POSTed
   to the ACS with `RelayState`.

### 4.2 Assertion content

- `Issuer`: addon `issuer` or `urn:<tenant domain>` (S37-6).
- `Subject/NameID`: first non-empty of `nameIdentifierProbes` (default:
  the nameidentifier, email, name claims), format `nameIdentifierFormat`
  (default `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`).
- `Conditions`: `NotBefore` now, `NotOnOrAfter` now +
  `lifetimeInSeconds`; `AudienceRestriction` = addon `audience` or the SP
  issuer.
- `AuthnStatement` with `authnContextClassRef` (default
  `urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`, S37-7) and
  `SessionIndex` = zeroauthy session ID.
- Attributes: the `PassportProfileMapper` defaults, then `mappings`
  (`{"<user field>": "<attribute name>" | [names]}`), `createUpnClaim`,
  `passthroughClaimsWithNoMapping`, `mapUnknownClaimsAsIs`,
  `mapIdentities`, `typedAttributes`, `includeAttributeNameFormat`.
- Signed with the tenant's current signing key (Plan 20) unless the addon
  `signingCert`/Actions `setSigningCert`/`setKey` provide another
  (S37-8).

### 4.3 Metadata and logout

- `GET /samlp/metadata/{client_id}`: IdP `EntityDescriptor` with signing
  certificates (current and next), SSO endpoints (Redirect, POST), SLO
  endpoints.
- SLO at `/samlp/{client_id}/logout`: accepts `LogoutRequest` (verifies
  issuer and, when configured, signature), ends the zeroauthy session,
  triggers back-channel logout (Plan 41a initiator `rp-logout`, since an
  SP asked; S37-9) and propagates `LogoutRequest`s to other SAML session participants
  when `logout.slo_enabled` (S37-10), then answers `LogoutResponse` to the
  requester (or redirects to `logout.callback`).

### 4.4 `api.samlResponse`

The 25 documented setters (A1 spec list) map onto the §4.2 inputs for
this response only; invalid values throw in the Action.

## 5. SP connections

### 5.1 Configuration

- From `metadataUrl` (fetched with the federation outbound policy,
  refreshed daily, S37-11) or `metadataXml`, or explicit
  `signInEndpoint` + `cert`/`signingCert`.
- `entityId` default `urn:auth0:<tenant>:<connection>` (documented).
- `thumbprints`/`thumbprints_sha384` computed on write from the certs
  (documented), read-only.
- `signing_key` and `decryptionKey`: from the Plan 36 keys API (created
  lazily) or supplied (PEM pair), sealed.
- `requestTemplate`: `@@AssertServiceURLAndDestination@@`, `@@ID@@`,
  `@@IssueInstant@@`, `@@ProtocolBinding@@`, `@@Issuer@@`,
  `@@AssertionConsumerServiceURL@@`, `@@Destination@@` substitution
  (S37-12 for the full variable list); the template must parse to a valid
  `AuthnRequest`.

### 5.2 Login

1. `/authorize?connection=<samlp>` (or HRD) → `AuthnRequest` (signed when
   `signSAMLRequest`; deflated on Redirect when `deflate`) with
   `RelayState` = attempt state.
2. IdP POSTs to the ACS; zeroauthy validates (anti-goals), decrypts if
   encrypted, maps the profile (`fieldsMap` `{auth0_field: saml_attribute
   | [attrs]}`, defaults to the standard claim types), user ID =
   `samlp|<connection>|<user_id_attribute or NameID>` (S37-13), then the
   Plan 24 identity pipeline.
3. IdP-initiated: when `idpinitiated.enabled`, an unsolicited response is
   accepted (no `InResponseTo`) and the login continues to
   `idpinitiated.client_id` with `client_protocol` (`oidc` | `samlp` |
   `wsfed`) and `client_authorizequery`.

### 5.3 Logout

Unless `disableSignout`, logout of a session that came from a SAML
connection sends a `LogoutRequest` to `signOutEndpoint` (front channel,
Redirect binding) and accepts the IdP's `LogoutResponse` at the SP SLO
endpoint (path per S37-14; local `/samlp/logout?connection=<name>`);
IdP-initiated `LogoutRequest` ends the session (Plan 41a initiator
`idp-logout`).

## 6. Storage

- SAML connection options in the existing connection JSON + sealed secrets;
  `saml_replay(tenant_id, connection_or_client, assertion_id_hash,
  expires_at)`; IdP SAML session participants for SLO
  (`saml_sessions(tenant_id, session_id, client_id, name_id, session_index)`);
  metadata cache; one migration numbered at merge; gRPC capability
  `saml.v1`.

## 7. Console, seed, Deploy CLI

- Applications → Addons → SAML2 Web App (settings JSON editor with the
  documented members, usage tab with endpoints and certificate download).
- Enterprise → SAML: create from metadata URL/XML or manual, keys tab,
  login experience (domains, button), IdP-initiated settings, debug.
- Seed: addon and connection options.
- Deploy CLI 9.1.0: clients' `addons.samlp` and `samlp` connections in the
  four-cell round trip.

## 8. Tests

- `internal/samlcore`: test vectors for exc-c14n, sign/verify round trips,
  the signature-wrapping attack corpus (moved element, duplicated
  assertion, comment injection in NameID, unsigned response with signed
  assertion swap), XXE refusal, encryption round trips, fuzz targets for
  the parser.
- IdP: SP-initiated and IdP-initiated with a test SP; mappings table;
  `api.samlResponse` setters; SLO.
- SP: login against a fixture IdP (built on `samlcore`), metadata import,
  encrypted assertions, replay, skew, IdP-initiated policy, SLO.
- E2E `make e2e-saml` (new lane): a real SAML SP library and a real SAML
  IdP implementation from npm (`@node-saml/node-saml` and `samlify`, or
  equivalents) — **new pins need approval** (§9.2); Playwright through both
  directions; Deploy CLI round trip.

## 9. Decisions needed from the maintainer

1. **XML signature implementation** (§3): vendor goxmldsig + etree into
   `internal/third_party` (recommended), add them as Go modules, or write
   in-tree.
2. **E2E pins** for a third-party SAML SP and IdP (npm), since Auth0's own
   SAML libraries are server-side.
3. **SHA-1 and RSA-1_5** support (Auth0 allows `rsa-sha1`): allowed only by
   explicit configuration (proposed), or refused.

## 10. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR37a-1 | No artifact binding or SOAP back channel. |
| LR37a-2 | `api.samlResponse.*` built here. |
| LR37a-3 | 2-minute clock skew; assertion IDs single use. |

Observe later (`docs/superpowers/plan-1-followups.md`): **S37-1** the
addon members beyond the OpenAPI list; **S37-2** ACS URL form; **S37-3**
key transport algorithms; **S37-4** how Auth0 matches the SP issuer;
**S37-5** SP request signature validation; **S37-6** default IdP issuer;
**S37-7** default `AuthnContextClassRef`; **S37-8** signing certificate
choice; **S37-9** back-channel initiator for SAML SLO; **S37-10**
`slo_enabled` semantics; **S37-11** metadata refresh; **S37-12**
`requestTemplate` variables; **S37-13** SAML user ID format; **S37-14**
SP logout response endpoint.

## 11. Maintainer rulings (2026-11-21)

1. §9.1: vendor `russellhaering/goxmldsig` and `beevik/etree` into
   `internal/third_party` (recommended option).
2. §9.2: E2E pins `@node-saml/node-saml` (service provider) and `samlify`
   (identity provider).
3. §9.3: SHA-1 and RSA-1_5 only by explicit configuration.

Implementation rulings LR37a-4…6 are in D-0130: the add-on `signingCert` is
the SP's certificate (Auth0's OpenAPI meaning), other add-on keys are refused,
and SAML global token revocation fields are stored only.
