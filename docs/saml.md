# SAML 2.0

zeroauthy speaks SAML 2.0 in both directions, as Auth0 does:

- **Identity provider.** An application with the **SAML2 Web App** add-on
  (`addons.samlp`) signs users in to a SAML service provider.
- **Service provider.** A `samlp` enterprise connection signs users in
  through an upstream SAML identity provider, such as Okta, Entra ID, ADFS
  or Google Workspace.

Both directions support the HTTP-Redirect and HTTP-POST bindings and front-channel single logout (SLO).
The artifact binding, the SOAP back channel and ECP are not supported
(LR37a-1). Decisions, defaults and sources are recorded in
[D-0130](compat/decisions.md#d-0130-saml-20-identity-provider-and-service-provider-plan-37a).

## zeroauthy as identity provider

### Enable the add-on

Set `addons.samlp` on a client with the Management API, the console
(**Applications → SAML2 Web App**), the seed or the Deploy CLI:

```bash
curl -X PATCH "https://$TENANT/api/v2/clients/$CLIENT_ID" \
  -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"callbacks":["https://sp.example.com/saml/acs"],
       "addons":{"samlp":{"audience":"urn:sp.example.com",
         "mappings":{"email":"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"},
         "logout":{"callback":"https://sp.example.com/saml/slo"}}}}'
```

`{"addons":{"samlp":null}}` or `{"addons":null}` removes it. Add-on keys
other than `samlp` are refused with `400` (LR37a-5). Writing an add-on
needs the `saml.v1` storage capability. SQLite, PostgreSQL, MySQL and memory
have it; a storage plugin must advertise it.

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET\|POST /samlp/{client_id}` | SSO: an `AuthnRequest` (Redirect or POST), or IdP-initiated login without one. `connection` and `organization` query parameters are honoured. |
| `GET /samlp/metadata/{client_id}` | IdP metadata: entity ID, signing certificate, SSO and SLO endpoints. |
| `GET\|POST /samlp/{client_id}/logout` | SLO: a service provider's `LogoutRequest`, or a `LogoutResponse` during propagation. |

The console's **SAML2 Web App** tab shows these URLs for each application.

### Settings

zeroauthy implements the documented `addons.samlp` members:

`audience`, `recipient`, `destination`, `issuer`, `mappings`,
`createUpnClaim`, `mapUnknownClaimsAsIs`, `passthroughClaimsWithNoMapping`,
`mapIdentities`, `signatureAlgorithm`, `digestAlgorithm`, `lifetimeInSeconds`,
`signResponse`, `nameIdentifierFormat`, `nameIdentifierProbes`,
`authnContextClassRef`, `typedAttributes`, `includeAttributeNameFormat`,
`binding`, `signingCert` and `logout` (`callback`, `slo_enabled`).

| Default | Value |
|---|---|
| Issuer | `urn:{tenant host}` (observation S37-6) |
| Audience | `audience`, otherwise the `AuthnRequest` `Issuer` |
| Assertion lifetime | 3600 seconds |
| Signature and digest | RSA-SHA256 and SHA-256. `rsa-sha1`/`sha1` only when selected explicitly. |
| Signed element | The assertion. `signResponse: true` signs the response instead, as Auth0 documents. |
| NameID probes | `nameidentifier`, `emailaddress`, `name` claims |

Rules worth knowing:

- **The ACS must match exactly.** It must equal one of the client's
  `callbacks` or the add-on `recipient`. Wildcards and placeholders don't
  apply, because an ACS receives bearer assertions.
- **The `signingCert` is the service provider's certificate**, as in Auth0's
  OpenAPI. When it is set, `AuthnRequest`s and SLO messages from the service
  provider must be signed with its key. Unsigned ones are refused (LR37a-4).
  zeroauthy always signs with the tenant signing key unless an Action selects
  another key.
- **Set `audience` or `signingCert`.** Without `audience`, the assertion's
  audience is the `AuthnRequest` `Issuer`, which an unsigned request chooses
  (Auth0's default). The assertion still goes only to a registered ACS.
- **`Destination` is checked.** A request `Destination`, when present, must
  equal the endpoint it was sent to.
- **Metadata needs an explicit mapping.** `app_metadata` and
  `user_metadata` reach the assertion only through explicit dotted mappings,
  for example `"mappings":{"dept":"app_metadata.department"}`.
- **Errors after the ACS is validated** go back to the service provider as a
  signed SAML error `Response`: `AuthnFailed` for denied or required login,
  otherwise `Responder`.

### Actions

Post-login Actions see `event.transaction.protocol === "samlp"` and can
change the response through `api.samlResponse`:

`setAudience`, `setRecipient`, `setDestination`, `setIssuer`,
`setLifetimeInSeconds`, `setSignResponse`, `setSignatureAlgorithm`,
`setDigestAlgorithm`, `setNameIdentifierFormat`, `setNameIdentifierProbes`,
`setAuthnContextClassRef`, `setCreateUpnClaim`, `setMapUnknownClaimsAsIs`,
`setPassthroughClaimsWithNoMapping`, `setMapIdentities`, `setTypedAttributes`,
`setIncludeAttributeNameFormat`, `setAttribute`, `setRelayState`, `setKey` and
`setCert` (a signing key pair), `setSigningCert`, and `setEncryptionCert` or
`setEncryptionPublicKey` with `setEncryptionAlgorithm` (an encrypted
assertion).

Setters return `api`, so chain through `api.`. A key and its certificate
must match. If they don't, the login fails with a signed error response.
The private key never reaches logs.

### Single logout

A signed-in session records each service provider it answered: its NameID
and SessionIndex. When one service provider sends a `LogoutRequest`, zeroauthy
ends the session and sends a `LogoutRequest` to each other participant
whose add-on has a `logout.callback` and doesn't set `slo_enabled: false`.
Then it answers the requester at its `logout.callback`.

A `LogoutRequest` that doesn't match the browser's session ends nothing
and is answered with status `Requester`. The logout chain state lives in a
sealed, ten-minute browser cookie.

## zeroauthy as service provider

### Create a connection

Use the console (**Authentication → Enterprise → SAML**), the
Management API, the seed or the Deploy CLI. Two ways to configure it:

```json
{"name":"corp-saml","strategy":"samlp","enabled_clients":["$CLIENT_ID"],
 "options":{"metadataUrl":"https://idp.example.com/metadata.xml"}}
```

```json
{"name":"corp-saml","strategy":"samlp",
 "options":{"signInEndpoint":"https://idp.example.com/sso",
            "signOutEndpoint":"https://idp.example.com/slo",
            "signingCert":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
            "fieldsMap":{"email":"mail","name":"displayName"}}}
```

`metadataUrl` is fetched over the guarded HTTPS client, outside any store
transaction, on create and whenever `options` are written. The derived
`signInEndpoint`, `signOutEndpoint` and `signingCert` are stored, and values
in the written options win. There is no refresh job: after the IdP rotates
its certificate, write the options again without `signingCert` (observation
S37-11). Edits that leave `options` alone fetch nothing.

`signingCert` accepts PEM, base64 DER, or base64 of the PEM: Auth0's stored
form, which the Deploy CLI exports and imports. The `thumbprints` are read
only: they are recomputed from the certificates on every write.

Give the identity provider these values (the console shows them on the
connection):

| Value | Default |
|---|---|
| Entity ID (audience) | `urn:auth0:{tenant}:{connection}`, or `options.entityId` |
| ACS (HTTP-POST) | `https://{tenant host}/login/callback?connection={connection}` |
| SP metadata | `https://{tenant host}/samlp/metadata?connection={connection}` |
| SP single logout | `https://{tenant host}/samlp/logout?connection={connection}` |

### Keys

SP signing and decryption keys are connection keys (see
[enterprise connections](enterprise-connections.md)). They are created on
demand, sealed with the master key, and published in the SP metadata.
`options.signing_key.key` and `options.decryptionKey.key` are refused. Use
the connection keys API instead (a parity deviation, Task 7 ruling).

- **Request signing.** `signSAMLRequest: true` signs `AuthnRequest`s.
  `LogoutRequest`s and `LogoutResponse`s are always signed.
- **Encrypted assertions.** Assertions encrypted to the SP's encryption key
  are decrypted. The key transports are RSA-OAEP and RSA-OAEP-256; RSA-1_5
  is used only when allowed explicitly. Data encryption is AES-GCM, or
  AES-CBC for Okta and ADFS defaults. The assertion's signature is checked
  after decryption, and a response with neither the response nor the
  assertion signed is refused.

### Login checks

A response must carry a valid signature, by a configured certificate or a
pinned thumbprint, on the response or the assertion. Signature-wrapping
shapes are refused. It must also pass these checks:

- the `Destination` and `Recipient`, and an audience every
  `AudienceRestriction` names;
- the bearer confirmation;
- `InResponseTo` matches the attempt;
- `NotBefore` and `NotOnOrAfter`, with 2 minutes of skew (LR37a-3).

Each assertion ID is single use within its validity window. The replay
table is shared by every replica.

User profiles come from `fieldsMap`, then the default attribute names (the
Microsoft claim URIs, `email`/`mail`, `name`/`displayName`, `givenName`,
`sn` and so on). The user ID is `samlp|{connection}|{NameID}`, or
`user_id_attribute`. `email_verified` is false unless `fieldsMap` maps it
to a true attribute.

### IdP-initiated login

Unsolicited responses are refused unless the connection allows them:

```json
"idpinitiated":{"enabled":true,"client_id":"$CLIENT_ID",
                "client_protocol":"oidc","client_authorizequery":"response_type=code&scope=openid"}
```

The response is validated like any other, and the user then continues to
that application.

### Single logout

On `/v2/logout` or OIDC RP-initiated logout, zeroauthy sends a signed
`LogoutRequest` for the upstream session to `signOutEndpoint`. The upstream
session is the NameID and SessionIndex from login. zeroauthy finishes at
`returnTo` once the IdP's `LogoutResponse` arrives.

`disableSignout: true` skips the upstream request. An IdP-initiated
`LogoutRequest` must be signed by the IdP, and it ends the session only
when it names this browser's upstream session.

### Not yet supported

- Global token revocation fields on `samlp` connections are stored only
  (LR37a-6).
- `options.debug` is stored only; SAML responses are never logged.
- `options.deflate: false` is stored, but HTTP-Redirect requests are always
  deflated, as SAML Bindings §3.4.4 requires.

## Testing

`make e2e-saml` runs the production server with throwaway keys against:

- pinned `@node-saml/node-saml` 5.2.0 as a service provider: SP-initiated
  login, then single logout signed both ways and an unsigned request refused;
- pinned `samlify` 2.15.1 as an identity provider: login, ID token claims
  and upstream single logout;
- the pinned Deploy CLI four-cell round trip of an add-on client and a
  `samlp` connection.

The browser runs through Playwright. A secret scan checks the logs.
