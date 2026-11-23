# WS-Federation and ADFS

zeroauthy speaks WS-Federation (the passive requestor profile) in both
directions, as Auth0 does:

- **Identity provider.** An application with the **WS-Fed Web App** add-on
  (`addons.wsfed`) signs users in to WS-Fed relying parties, such as
  SharePoint or a .NET application using WIF, with a signed SAML 1.1 token.
- **Relying party.** An `adfs` enterprise connection signs users in through
  ADFS, or any WS-Fed identity provider.

WS-Trust active endpoints (`/trust/13/usernamemixed`) and JWT tokens in
WS-Fed are not supported (LR37b-1, LR37b-2). Decisions, defaults and sources
are recorded in
[D-0140](compat/decisions.md#d-0140-ws-federation-identity-provider-and-adfs-connections-plan-37b).
The XML signature code and its limits are those of [SAML](saml.md).

## zeroauthy as identity provider

### Enable the add-on

As in Auth0, the add-on itself holds no settings: the reply URLs are the
application's **callbacks** and the realms are its **`client_aliases`**.
Set them with the Management API, the console (**Applications → WS-Fed Web
App**), the seed or the Deploy CLI:

```bash
curl -X PATCH "https://$TENANT/api/v2/clients/$CLIENT_ID" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"callbacks":["https://portal.example.com/_trust/"],
       "client_aliases":["urn:sharepoint:portal"],
       "addons":{"wsfed":{}}}'
```

- `addons.wsfed` may be any JSON object of at most 4 KiB; it is stored and
  returned unchanged and has no effect (LR37b-4). `null` removes it.
- `client_aliases`: at most 100 realms of 1 to 1,024 characters. Each alias
  is unique in the tenant: an alias another application uses is refused with
  `409` (LR37b-3).
- `form_template` is stored and returned only; zeroauthy always posts with
  its own form (LR37b-5).
- PATCH replaces the whole `addons` object. To keep a SAML2 Web App add-on
  on the same application, send both; the console does.

Writing `client_aliases` or `form_template` needs the `wsfed.v1` storage
capability (migration 0045 for SQLite, PostgreSQL and MySQL); memory has it,
and a storage plugin must advertise it.

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /wsfed/{client_id}` | Sign-in (`wa=wsignin1.0`, the default) and sign-out (`wa=wsignout1.0`, `wa=wsignoutcleanup1.0`). |
| `GET /wsfed?wtrealm=…` | The same, with the application found by its realm: its client ID or one of its `client_aliases`. |
| `GET /wsfed/FederationMetadata/2007-06/FederationMetadata.xml` | Federation metadata of the tenant (passive endpoint `/wsfed`). |
| `GET /wsfed/{client_id}/FederationMetadata/2007-06/FederationMetadata.xml` | Federation metadata of an application (passive endpoint `/wsfed/{client_id}`). |

Sign-in parameters:

| Parameter | Behavior |
|---|---|
| `wtrealm` | The realm and token audience. On `/wsfed/{client_id}` it must be the client ID or one of its aliases. |
| `wreply` | Where the token is posted. It must be a callback (the `redirect_uri` rules, http or https only). Absent: the first callback. |
| `wctx` | Returned as the `wctx` form field and as the `RequestSecurityTokenResponse` `Context` (at most 2,048 bytes). |
| `whr` | The connection to sign in with, skipping the login page. |
| `wfresh=0` | Authenticate again even with a session. |

An invalid request (unknown realm, `wreply` outside the callbacks) gets an
error page; nothing is posted to the relying party. After login, a failure
also ends at an error page, since WS-Fed has no error token (LR37b-8).

### The token

The relying party receives an auto-posted form with `wa=wsignin1.0`,
`wresult` and `wctx`. `wresult` is node-wsfed's
`t:RequestSecurityTokenResponse` holding one SAML 1.1 assertion:

| Default | Value |
|---|---|
| Issuer | `urn:{tenant host}` |
| Audience | `wtrealm`, else `wreply`; values that are not `http(s):` or `urn:` get `urn:` |
| Lifetime | 8 hours (node-wsfed) |
| Signature | The tenant signing key, RSA-SHA256 and SHA-256, enveloped over the `AssertionID`, exclusive c14n |
| Subject | Bearer confirmation, NameIdentifier format unspecified |
| Claims | The SAML profile mapper with the add-on defaults: `…/ws/2005/05/identity/claims/{nameidentifier,emailaddress,name,givenname,surname,upn}`, identities and unmapped claims |

Customise the token in a post-login Action with `api.samlResponse`, as
Auth0 documents for WS-Fed: attributes, the UPN, identities and passthrough
switches, lifetime, audience, issuer, algorithms and the signing key apply
(W2). `event.transaction.protocol` is `wsfed`. `setRelayState` has no effect.

### Sign-out

- `wa=wsignout1.0` hands the browser to `/v2/logout` for the application:
  the session ends (with upstream and back-channel logout) and the browser
  returns to `wreply`, which must be one of the application's **allowed
  logout URLs**.
- `wa=wsignoutcleanup1.0` ends the session and answers with the signed-out
  page.

zeroauthy does not send `wsignoutcleanup1.0` to the other relying parties of
the session (LR37b-9).

## zeroauthy as relying party (ADFS connections)

### Create a connection

Give the ADFS administrator:

- the **realm identifier**: the connection's `entityId`, by default
  `urn:auth0:{tenant}:{connection}`;
- the **endpoint**: `https://{tenant host}/login/callback`.

Then create the connection from the ADFS server or from its metadata:

```bash
curl -X POST "https://$TENANT/api/v2/connections" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"name":"corp-adfs","strategy":"adfs","enabled_clients":["'$CLIENT_ID'"],
       "options":{"adfs_server":"adfs.corp.example.com"}}'
```

- `adfs_server` is a host (zeroauthy adds
  `/FederationMetadata/2007-06/FederationMetadata.xml`) or an HTTPS metadata
  URL. It is fetched through the federation outbound policy when the
  connection is created and whenever its options are written, at most
  128 KB. Exactly one of `adfs_server` and `fedMetadataXml` (the metadata
  document, at most 102,400 bytes) is required.
- `signInEndpoint`, `thumbprints`, `thumbprints_sha384` and
  `prev_thumbprints` come from the metadata and are read-only. When the
  metadata's certificates change, the previous thumbprints stay trusted as
  `prev_thumbprints`.
- `entityId`, `user_id_attribute`, `should_trust_email_verified_connection`,
  `set_user_root_attributes`, `domain_aliases` and `non_persistent_attrs`
  apply; `icon_url`, `tenant_domain` and `upstream_params` are stored only
  (LR37b-6).

There is no daily metadata refresh: write the options again after a
certificate rollover (the previous thumbprints cover the overlap).

### Login

zeroauthy redirects to the sign-in endpoint with `wa=wsignin1.0`,
`wtrealm` = the entity ID, `wreply` = `/login/callback` and `wctx` = the
login attempt. ADFS posts `wresult` and `wctx` back. The token must:

- be one SAML 1.1 or SAML 2.0 assertion, the only child of the only
  `RequestedSecurityToken`;
- carry an enveloped signature by a certificate whose SHA-1 or SHA-384
  thumbprint is trusted; SHA-1 signatures are refused;
- name the entity ID as its audience and be within its validity window
  (2 minutes of skew);
- not have been used before (the SAML replay store, shared by replicas);
- answer this browser's login attempt (no unsolicited WS-Fed login).

The user ID is `adfs|{connection}|{id}`, where `{id}` is the
`user_id_attribute` claim, else the subject's NameIdentifier, else the
`nameidentifier`, `upn` or `emailaddress` claim (LR37b-7, W3). Email, name,
given name and surname come from the ADFS claim types of Auth0's claim
rules. `email_verified` is true only with
`should_trust_email_verified_connection: always_set_emails_as_verified`.

`adfs` connections take part in home realm discovery by `domain_aliases`.
Logout of a session from an `adfs` connection ends at the IdP's
`wa=wsignout1.0`, with `wreply` = the logout `returnTo` (LR37b-10).

## Not yet supported

- Front-channel sign-out of the other WS-Fed relying parties of a session.
- Encrypted WS-Fed tokens (Auth0 points to SAML for encryption).
- Profile attributes from additional ADFS claim types.
- IdP-initiated WS-Fed login to zeroauthy.

## Testing

`make e2e-wsfed` runs the production server with throwaway keys against
two small fixtures that sign and verify XML with the pinned `xml-crypto`
6.4.0, not with zeroauthy's code:

- a relying party that verifies the SAML 1.1 token with the certificates of
  zeroauthy's federation metadata, then signs out with `wsignout1.0`;
- an ADFS stand-in that answers `wsignin1.0` with a signed SAML 1.1 token
  and handles `wsignout1.0`;
- the pinned Deploy CLI four-cell round trip of a WS-Fed client and an
  `adfs` connection.

The browser runs through Playwright. A secret scan checks the logs.
