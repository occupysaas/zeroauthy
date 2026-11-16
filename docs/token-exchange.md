# Custom token exchange

Custom token exchange lets an application trade a token from another system
for zeroauthy tokens, using the RFC 8693 grant. A token exchange profile binds
a `subject_token_type` to an Action; the Action checks the incoming token and
decides which user the new tokens are for. This guide covers setup and the
places where zeroauthy decides something Auth0's documentation leaves open;
the rulings are recorded in
[D-0063](compat/decisions.md#d-0063-client-credentials-private_key_jwt-jar-and-custom-token-exchange-contracts-and-local-rulings).
For client keys and signed requests, see
[Client authentication](client-authentication.md).

## Setting it up

1. **Write and deploy an Action** with the `custom-token-exchange` trigger
   (version `v1`, handler `onExecuteCustomTokenExchange`).
2. **Create a profile** that names the Action's id, a `subject_token_type` and
   a `name`.
3. **Allow it on the application**: `token_exchange` with
   `allow_any_profile_of_type: ["custom_authentication"]`. Only first-party
   applications may set it (LR35-6, C5). Public applications may use the grant
   too (C10).
4. **Allow skipping consent on the API** (`skip_consent_for_verifiable_first_party_clients`),
   since no consent screen can appear. Otherwise a request that names the API
   is `403 access_denied` (C11).

### Profiles

`/api/v2/token-exchange-profiles` has list (checkpoint paging with `from` and
`take`), create, get, patch and delete, with the scopes
`read:`, `create:`, `update:` and `delete:token_exchange_profiles`.

| Field | Rule |
|---|---|
| `name` | 3 to 50 characters. |
| `subject_token_type` | 8 to 100 characters, beginning `https://` or `urn:`, unique in the tenant (`409`). These prefixes are reserved: `http://auth0.com`, `https://auth0.com`, `http://okta.com`, `https://okta.com`, `urn:ietf`, `urn:auth0`, `urn:okta`. |
| `action_id` | A deployed Action with the `custom-token-exchange` trigger; fixed after creation. |
| `type` | `custom_authentication`. |

A tenant holds at most 100 profiles (`403`, C8). A patch changes only `name`
and `subject_token_type`. An Action that a profile binds cannot be deleted
(C9). The console has **Actions > Token exchange profiles**.

## The request

```sh
curl -sS https://$HOST/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=$CLIENT_ID -d client_secret=$CLIENT_SECRET \
  -d subject_token_type=urn:acme:legacy-token \
  -d subject_token="$LEGACY_TOKEN" \
  -d audience=https://api.acme.test -d scope="openid read:things"
```

Also accepted: `organization`, `actor_token` with `actor_token_type` (both or
neither) and `requested_token_type`. The application authenticates with its
registered method, `private_key_jwt` included. An unknown `subject_token_type`
is `400 invalid_request`. An application that is third-party or has no
`token_exchange` setting gets `unauthorized_client`.

## The Action

```js
exports.onExecuteCustomTokenExchange = async (event, api) => {
  const claims = await checkLegacyToken(event.transaction.subject_token, event.secrets.LEGACY_KEY);
  if (!claims) {
    api.access.rejectInvalidSubjectToken('The token is not valid');
    return;
  }
  api.authentication.setUserByConnection('Username-Password-Authentication', {
    user_id: claims.sub,
    email: claims.email,
    email_verified: true,
  });
};
```

Exactly one of `setUserById` and `setUserByConnection` must have been called;
otherwise the exchange fails with a `server_error`-class answer (C12).

### Event

`event.client`, `event.organization` (when requested and valid),
`event.request`, `event.resource_server.identifier`, `event.tenant.id`,
`event.secrets` and `event.transaction` with `subject_token`,
`subject_token_type`, `actor_token`, `actor_token_type`,
`requested_scopes` and `requested_token_type`.
`actor_token_user` is set only when the actor token is an unexpired ID token
this tenant signed for one of its applications. `event.request.body` is
empty. `event.transaction.metadata` is not provided: it is an Early Access
feature upstream.

### API

| Member | Behaviour |
|---|---|
| `access.deny(code, reason)` | Fails the exchange (`400`) with that error code. Any custom code is allowed, except one that contains a secret value (refused). |
| `access.rejectInvalidSubjectToken(reason)` | `400 invalid_request` and one throttle count. The response carries a fixed description, not your reason (C22). |
| `authentication.setUserById(id)` | The user must exist in this tenant. |
| `authentication.setUserByConnection(name, attributes, options)` | Database connections only (C21). Attributes: `user_id` (required), `email`, `email_verified`, `family_name`, `given_name`, `name`, `nickname`, `phone_number`, `phone_verified`, `picture`, `username`, `verify_email`. Options `creationBehavior` (`create_if_not_exists`, the default, or `none`) and `updateBehavior` (`none`, the default, or `replace`; C14). A changed `email`, `email_verified`, `phone_number`, `phone_verified` or `username` on an existing user is an error. `verify_email` is accepted but sends nothing yet (LR35-14). A new user goes through the same path as passwordless sign-up, including registration Actions. |
| `authentication.setOrganization(idOrName)` | Selects the organization; it is resolved before any user is created. A request `organization` that differs is `400 invalid_request`. |
| `authentication.setActor(actor)` | Adds an RFC 8693 `act` claim. Every level needs a `sub`, with up to 5 further string, number or boolean properties per level, and up to 5 actors in total. |
| `user.setAppMetadata`, `user.setUserMetadata` | Metadata patches; `null` deletes a key. |
| `cache.get`, `set`, `delete` | As in the other triggers. |

`api.transaction.setMetadata` is unsupported and fails as an unknown member.
A blocked user is `invalid_grant`. A user the Action selects that does not
exist, or `creationBehavior: none` finding no user, is `400 invalid_request`.

## After the Action

The tenant's post-login Actions run next, with the restrictions that no
factor can be challenged or enrolled and no redirect or prompt can happen:
`challengeWith`, `enrollWith`, `multifactor.enable` with a provider other than
`none`, `api.redirect.*` and `api.prompt.*` fail the exchange. The tenant's
MFA policy is not applied to an exchange (C20). Then tokens are issued: an
access token, an ID token when `openid` is in `scope`, and a refresh token
under the usual `offline_access` and API rules, except that none is issued
when `setActor` was used. The access token carries no `gty`;
`event.transaction.protocol` is `oauth2-token-exchange` in post-login. Login
counters and `last_login` update as for any login (C13).

## Second factors are not requested

The tenant's MFA policy is **not** applied to a custom token exchange: the
Action decides whose tokens are issued, and no second factor is asked for.
This is a local ruling pending observation of Auth0 (D-0063, C20). If you
require a second factor, do not enable the grant for that application.

## The response

A successful exchange returns the usual token response plus
`issued_token_type`, always `urn:ietf:params:oauth:token-type:access_token`
(RFC 8693 section 2.2.1; LR35-15). `requested_token_type` is passed to the
Action but does not change what is issued.

## What persists when a later step fails

The Action's user creation or update, and any metadata it wrote, are saved
before the later steps run. If organization membership, post-login or token
minting then fails, the exchange is refused but those changes stay.

## Throttling and logs

The suspicious-IP stage `pre-custom-token-exchange` bounds failed attempts per
IP: the default is 10 attempts with a 600000 ms rate; a stored value is kept.
Only `rejectInvalidSubjectToken` spends an attempt. A blocked request is
`429 too_many_attempts` and the Action does not run. See
[attack protection](attack-protection.md).

A successful exchange writes the log `secte` (with `actor` when set), a
failure `fecte`; see [logs](logs.md). The subject token, actor token and
every other credential are masked in logs and Action logs.

## In the seed

```yaml
tenants:
  - name: acme
    actions:
      - name: legacy-exchange
        supported_triggers: [{id: custom-token-exchange, version: v1}]
        code: |
          exports.onExecuteCustomTokenExchange = async (event, api) => { /* ... */ };
        deploy: true                      # a profile needs a deployed Action
    token_exchange_profiles:
      - name: Legacy tokens
        subject_token_type: urn:acme:legacy-token
        action: legacy-exchange           # an Action name, seeded or existing
    clients:
      - client_id: bridge
        name: Bridge
        app_type: regular_web
        client_secret: change-me-to-something-long
        token_exchange: {allow_any_profile_of_type: [custom_authentication]}
```

- A profile is identified by its `subject_token_type`. Profiles are created
  after the Actions, so a seed that has them is applied by the server (not by
  `zeroauthy seed`, which cannot build Actions).
- Re-applying creates missing profiles and, in the default mode, gives an
  existing profile the seed's `name` and Action. In `create_only` mode an
  existing profile is left alone. The seed never deletes a profile.
- The seed uses the Management API's profile rules, and refuses profiles at
  startup on a store without `client_credentials.v1`.
