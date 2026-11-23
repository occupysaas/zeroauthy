# Self-service SSO

Self-service SSO lets a customer's administrator configure their own
enterprise connection, as in Auth0: you create a **self-service profile**,
issue an **SSO ticket** for one connection, and send the ticket link to the
customer. The link opens a hosted assistant on your tenant's domain where
the customer enters their identity provider's settings, tests the sign-in,
optionally sets up SCIM provisioning, and finishes (D-0150).

Storage plugins need `scim.v1` version 2; without it the routes answer 501.

## Profiles

In the console: **Authentication → Self-service SSO**. With the Management
API:

```sh
curl -X POST https://$TENANT/api/v2/self-service-profiles \
  -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"Partners","allowed_strategies":["samlp","oidc"],
       "branding":{"logo_url":"https://cdn.example.com/logo.png","colors":{"primary":"#116a7b"}},
       "user_attributes":[{"name":"email","description":"Work email","is_optional":false}]}'
```

- `name` is unique in the tenant (409). Bodies are checked against Auth0's
  schemas: `description` up to 140 characters, `logo_url` https only,
  `colors.primary` `#rgb` or `#rrggbb`.
- `allowed_strategies`: `samlp`, `oidc`, `okta`, `waad` and `adfs`. Auth0's
  other values (`google-apps`, `auth0-samlp`, `okta-samlp`,
  `keycloak-samlp`, `pingfederate`) answer 400 because zeroauthy has no such
  connection type (Q7). An empty list allows all five.
- `user_attributes` are shown to the customer as the attributes to send.
  `user_attribute_profile_id` is stored only (Early Access in Auth0).
- Custom text: `PUT /api/v2/self-service-profiles/{id}/custom-text/en/get-started`
  with `{"introduction": "…"}`; values up to 2000 characters. Basic styling
  tags and https or mailto links are kept; any other markup is shown as
  text.
- Deleting a profile deletes its custom text and tickets; connections it
  created stay.

## Tickets

```sh
curl -X POST https://$TENANT/api/v2/self-service-profiles/$PROFILE_ID/sso-ticket \
  -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' \
  -d '{"connection_config":{"name":"partner-saml"},
       "enabled_clients":["'$CLIENT_ID'"],
       "enabled_organizations":[{"organization_id":"'$ORG_ID'","assign_membership_on_login":true}],
       "domain_aliases_config":{"domain_verification":"optional","pending_domains":["partner.example.com"]},
       "provisioning_config":{"scopes":["get:users","post:users","put:users","patch:users","delete:users"]},
       "ttl_sec":86400}'
# {"ticket":"https://login.example.com/self-service/connections-flow?ticket=…"}
```

- A ticket names exactly one connection: `connection_config` creates a new
  one (its name must be free), `connection_id` edits an existing one whose
  strategy the profile allows.
- `ttl_sec`: up to 432000 seconds (5 days), the default.
- The `auth0-custom-domain` header picks the ticket's host among the
  tenant's domains; otherwise the canonical host.
- The token appears only in the returned link and is stored as a hash.
  Revoke with `POST …/sso-ticket/{token}/revoke` (the `ticket=` value of the
  link); revoking an unknown ticket also answers 202.
- A ticket works until it expires, is revoked, or the assistant finishes.

## The assistant

`https://{host}/self-service/connections-flow`. On the first request the
token moves from the URL into an HttpOnly, Secure, SameSite=Strict cookie
scoped to `/self-service`; every request checks the ticket again.

The customer:

1. Reads the values for their identity provider: callback URL, SAML ACS URL
   and entity ID.
2. Chooses an identity provider among the profile's strategies and enters
   its settings: SAML metadata URL or sign-in URL and certificate; OpenID
   Connect discovery URL, client ID and optional secret; Okta domain and
   credentials; a single Entra ID directory and credentials; ADFS server or
   metadata. Everything else (name, applications, organizations, display
   settings) comes from the ticket.
3. Chooses email domains, only among the ticket's `pending_domains`.
4. Tests the sign-in, when the ticket enables an application: an ordinary
   login through the ticket's first application with the new connection
   (zeroauthy has no side-effect-free test mode).
5. Creates a SCIM token when the ticket has `provisioning_config` and the
   connection accepts SCIM; the token is shown once.
6. Finishes; the link stops working.

The assistant writes through the Management API's own handlers, so the
connection passes the same validation, metadata fetching and secret
handling as `POST /api/v2/connections`; the writes are logged as the caller
`self-service-assistant`.

Edit tickets (`connection_id`) change the sign-in settings unless
`enabled_features.sso` is `false`; domains and provisioning only when
`enabled_features.domain_verification` and `.provisioning` are `true`.

Not supported: domain ownership verification (domains come only from the
ticket), languages other than `en`, and Auth0's other identity provider
types.

## Connection profiles

`/api/v2/connection-profiles` stores Auth0's connection profiles (name,
`connection_name_prefix_template`, `enabled_features`, organization
defaults, strategy overrides, SCIM token settings), and
`/api/v2/connection-profiles/templates` lists zeroauthy's two built-in
templates, `cpt_sso` and `cpt_scim` (Auth0's catalogue is not documented,
Q10). Auth0's ticket request has no field naming a connection profile, so
tickets do not apply them.

## Scopes

| Routes | Scopes |
|---|---|
| Profiles | `read:`, `create:`, `update:`, `delete:self_service_profiles` |
| Custom text | `read:`, `update:self_service_profile_custom_texts` |
| Tickets | `create:sso_access_tickets`, revoke `delete:sso_access_tickets` |
| Connection profiles and templates | `read:`, `create:`, `update:`, `delete:connection_profiles` |

## Testing

`make e2e-self-service` creates a profile and ticket with the pinned
node-auth0 SDK, runs the assistant in Chromium against a samlify identity
provider, signs in through the new connection, creates a SCIM token,
finishes, and checks the server log holds no ticket or token.
