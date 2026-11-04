# Migrating from Auth0

Moving a tenant from Auth0 to zeroauthy has three parts: configuration
(applications, APIs, connections, settings), users, and switching your apps
to the new domain. This page gives the order and points to the detailed
guides. zeroauthy uses Auth0's name here only to describe compatibility; it
is not affiliated with Auth0 or Okta.

## Before you start

- Check the [compatibility page](compatibility.md) against the features your
  tenant uses. Rules and Hooks are not supported (move them to Actions first,
  on Auth0); SAML, WebAuthn and enterprise directories are not in 1.0.
- Set up zeroauthy with persistent storage, a master key and TLS
  ([deployment](deployment.md)), and create the destination tenant. Run it on
  port 443: the Auth0 CLI and Deploy CLI assume `https://<domain>` without a
  port.
- In the destination tenant, create a **Machine to machine** application and
  authorize it for the tenant's Management API
  (`https://<tenant host>/api/v2/`) with the scopes the tools need. Its client
  ID and secret go into the Deploy CLI configuration and user-import scripts.

## 1. Configuration with the Deploy CLI

zeroauthy is tested with Auth0 Deploy CLI 9.1.0 (`a0deploy`), unmodified, in
YAML and directory formats. Export from Auth0, then import into zeroauthy:

```sh
a0deploy export --config_file ./auth0-source.json --format yaml --output_folder ./export
a0deploy import --config_file ./zeroauthy-target.json --input_file ./export/tenant.yaml
```

In `zeroauthy-target.json`, set `AUTH0_DOMAIN` to the zeroauthy tenant host,
`AUTH0_CLIENT_ID` and `AUTH0_CLIENT_SECRET` to the machine-to-machine
application above, and `AUTH0_ALLOW_DELETE` to `false`. Keep both files mode
`0600`.

Know the limits before you import ([Deploy CLI guide](deploy-cli.md)):

- **Database connections are not part of the tested set.** Create them in the
  console or with `POST /api/v2/connections` using the same names and
  password policies, before importing users.
- **Client secrets are not exported** by the Deploy CLI, so imported
  applications get new secrets. To keep client IDs and secrets, create the
  destination with `zeroauthy migration bootstrap` from an `--export_ids`
  export and a file of the source secrets
  ([preserving client credentials](deploy-cli.md#preserving-client-credentials-on-a-fresh-destination)).
- **Guardian factor providers** (`guardianFactorProviders`) export as an empty
  list because of a bug in the Deploy CLI itself. Set Twilio or SNS settings
  again through the console or the Management API
  ([MFA](mfa.md#deploy-cli-and-troubleshooting)).
- **Custom domains** need new ownership proof on the destination; import them
  in stages ([staged custom-domain migration](deploy-cli.md#staged-custom-domain-migration)).
- Rules, Hooks and their configurations are excluded and never run.
- Check credentials of social connections and email and phone providers after
  the import, and enter any that did not come across.

## 2. Users

### Export from Auth0

Start a user export job on Auth0 (`POST /api/v2/jobs/users-exports`, or the
Auth0 dashboard's export extension) in JSON (newline-delimited) format with
the fields you need (`email`, `email_verified`, `user_id`, `name`,
`given_name`, `family_name`, `nickname`, `picture`, `user_metadata`,
`app_metadata`, `blocked`).

Auth0 user exports never contain password hashes. Auth0 provides password
hashes only on request to its support, for eligible plans. Without them,
users choose a new password (see below).

### Import into zeroauthy

Convert the export to a JSON array in Auth0's user import format, adding
`custom_password_hash` (or `password_hash` for Auth0's cost-10 bcrypt hashes) from
the hash file when you have it. zeroauthy accepts the hash algorithms Auth0's
import accepts and upgrades each hash to argon2id on the user's first
sign-in. Then import per database connection:

```bash
curl -sS "https://$HOST/api/v2/jobs/users-imports" \
  -H "Authorization: Bearer $MGMT" \
  -F connection_id="$CONNECTION_ID" -F upsert=false \
  -F send_completion_email=false -F users=@users.json
```

Each request must stay under 512000 bytes, so split large files. Check every
job's summary and `/errors`. Keeping `user_id` preserves user IDs (and the
`sub` claim) for database users. TOTP, email and phone MFA enrollments can be
imported with `mfa_factors`. Details, limits and hash examples are in
[user import](user-import.md).

### Users without password hashes

- **Reset on first login:** import without hashes, then send password-change
  tickets (`POST /api/v2/tickets/password-change`) or let users use "Forgot
  password?".
- **Migrate on login:** create a [custom database](custom-db.md#migrating-off-a-legacy-store)
  connection in import mode whose `login` script verifies the password against
  your old store; each user moves to zeroauthy on their first successful
  sign-in.

Social and enterprise users are created again when they first sign in
through the new connection, with new user IDs. Link or merge them afterwards
if your app stores user IDs.

## 3. Switch your apps

- Point each SDK's `domain` (or issuer URL) at the zeroauthy tenant host and
  update client secrets if they changed. Callback, logout and origin URLs come
  over with the applications.
- Tokens, sessions and refresh tokens issued by Auth0 are not valid on
  zeroauthy: users sign in again once. APIs that validate access tokens must
  trust the new issuer and JWKS (`https://<tenant host>/.well-known/jwks.json`).
- Tools that call the Management API (node-auth0, the Auth0 CLI) need the new
  domain and a zeroauthy machine-to-machine application.
- Test the whole login in a staging copy first, and keep the Auth0 tenant
  until you are sure.
