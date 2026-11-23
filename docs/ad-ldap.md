# Active Directory / LDAP connections

An `ad` connection signs users in against Active Directory or another LDAP
directory through Auth0's open-source
[AD/LDAP Connector](https://github.com/auth0/ad-ldap-connector), installed
unchanged inside your network (Plan 38a, D-0160). The connector dials out
to zeroauthy over a WebSocket; zeroauthy never reaches your directory
directly. Connectors already installed for Auth0 can be repointed by
provisioning them again with the zeroauthy ticket.

Storage plugins need the `ad_hub.v1` capability; without it `ad`
connections cannot be created (501).

## Create the connection

```sh
curl -X POST https://$TENANT/api/v2/connections \
  -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"corp-ad","strategy":"ad","enabled_clients":["'$CLIENT_ID'"],
       "options":{"tenant_domain":"corp.example.com","domain_aliases":["corp.example.com"]}}'
```

The response carries `provisioning_ticket_url`
(`https://{tenant host}/p/ad/{ticket}`). In the console: **Authentication →
Enterprise → Create → Active Directory / LDAP**, then open the connection
to copy the ticket URL.

The ticket is valid for the connection's life (the connector reads it at
every start, LR38a-4). Treat it as a secret: whoever has it can register a
connector and receive the passwords users type. To revoke it, delete the
connection and create a new one.

| Option | Effect |
|---|---|
| `tenant_domain` | The AD domain: home realm discovery and the connector's domain. |
| `domain_aliases` | Email domains that home realm discovery sends to this connection's password stage. |
| `ips`, `kerberos` | With `kerberos: true`, logins from these addresses or CIDR ranges go to the connector's Windows integrated sign-in (below). |
| `disable_self_service_change_password` | Stored; zeroauthy never offers the forgot-password link for `ad` connections (LR38a-12). |
| `brute_force_protection` | On by default: failed logins count per connection and username (Attack protection). |
| `disable_cache` | Stored only: zeroauthy keeps no credential cache (LR38a-1). |
| `set_user_root_attributes` | `on_each_login` (default), `on_first_login` or `never_on_login`. |
| `agentIP`, `agentMode`, `agentVersion`, `signInEndpoint`, `certs`, `thumbprints`, `thumbprints_sha384` | Managed by the connector: set when it registers, returned on reads, ignored on writes so exports round-trip (LR38a-6). |

## Install the connector

Run the connector's installer (Windows) or `node setup/index.js` with the
provisioning ticket URL, as Auth0 documents. At every start the connector:

1. reads `{ticket}/info` (hub URL, connection name, domain, realm);
2. posts its certificate to the ticket and receives the connection's
   signing key; the two most recent connector certificates are kept, so
   two connectors can serve one connection;
3. opens the WebSocket `wss://{tenant host}/ad-hub` and authenticates with a
   token signed by its key;
4. measures latency against `GET /test`.

`GET /api/v2/connections/{id}/status` answers `200` while a connector is
connected (on any replica) and `404 not connected to any node` otherwise;
the console's connection page shows the same, with the connector's
version, address and certificates.

zeroauthy's hub requires TLS, directly or behind a proxy trusted with
`server.trust_proxy_headers` (LR38a-2). If zeroauthy uses a private CA,
put its certificate in a directory and point the connector's
`SSL_CA_PATH` at it: the connector replaces Node's CA list
(`NODE_EXTRA_CA_CERTS` alone is not enough).

## Sign-in

The hosted login shows a username and password form for the `ad`
connection when the application asks for it (`connection=corp-ad`), when
it has no database connection, or when identifier-first home realm
discovery matches a `domain_aliases` domain. The connector looks the name
up with its `LDAP_USER_BY_NAME` filter and binds as the user. Users are
`ad|{connection}|{id}` (the connector profile's `id`: objectGUID, uid or
cn); `displayName`, `name.givenName`, `name.familyName`, `nickname` and the
first `emails` value fill the profile, and `groups` with the other
directory attributes are the identity's `profileData` (LR38a-8). Emails
are verified only when the connector's profile mapper says
`email_verified: true`.

| Connector answer | Login page |
|---|---|
| `WrongUsername`, `WrongPassword` | Wrong credentials (401), counted by brute-force protection |
| `AccountDisabled`, `AccountExpired`, `AccountLocked` | User blocked (403) |
| `PasswordExpired`, `PasswordChangeRequired` | Password change required (403), unless the connector allows them |
| anything else, a 10-second timeout, no connector | Login method not available (503); nothing falls back |

Passwords travel only over the authenticated hub and are never logged or
stored. Sign-up is never offered.

## Kerberos

With `kerberos: true`, a login from an `ips` range on the tenant's
canonical host (the connector accepts one `postTokenUrl`, LR38a-10) goes to
the connector's `signInEndpoint` (`{SERVER_URL}/wsfed`) with WS-Fed
parameters; the connector's signed token returns to `/login/callback` and
is validated against its registered certificates. Elsewhere the password
form is shown.

## Password changes

```sh
curl -X PATCH https://$TENANT/api/v2/users/ad%7Ccorp-ad%7Cjdoe \
  -H "authorization: Bearer $MGMT_TOKEN" -H 'content-type: application/json' \
  -d '{"password":"N3w-Directory-Passw0rd","connection":"corp-ad"}'
```

The new password is sent to the connector (`change_password`), which needs
`ENABLE_WRITE_BACK`; the body must carry only `password` (and
`connection`). The directory's refusal answers 400, no connector 503.
The user must have signed in once (zeroauthy sends back the name they
signed in with).

## Several replicas

A connector holds a socket to one replica; logins on other replicas reach
it through the replica's internal HTTPS URL (LR38a-3). Set on every
replica:

| Setting | Value |
|---|---|
| `server.replica_url` | This replica's `https://` URL reachable by the others (no path); the listener must serve TLS on it. |
| `server.replica_ca_file` | PEM bundle trusted for the other replicas' certificates (empty: system roots). |

Forwarded requests are signed with a key derived from the connection's
signing key, expire after a minute and are accepted once.

## Seed and Deploy CLI

A seeded `ad` connection gets its ticket where it is applied; tickets and
connector-managed options never come from a seed or an import. Deploy
CLI exports round-trip: `provisioning_ticket_url` and the managed options
in an import are ignored.

## Testing

`make e2e-ad` runs the connector v8.0.5 (pinned commit) in a container
against its own mock LDAP server: provisioning, hub authentication,
logins, groups, the Deploy CLI round trip, a password change through the
connector, status and a log audit.

## Not supported

A native LDAP bind from zeroauthy (the connector is required); the
connector's admin UI and auto-update (they stay the connector's);
credential caching; the hosted forgot-password flow for `ad` users
(LR38a-12); `search_users` (zeroauthy never sends it, D38-9).
