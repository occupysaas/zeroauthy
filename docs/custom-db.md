# Custom database connections

A custom database connection lets users sign in against a user store you already run, such as a SQL table or an HTTP service, instead of (or on the way to) zeroauthy's own user table. The connection keeps the shape of an Auth0 custom database: you write short JavaScript scripts, and zeroauthy runs them in Node.js when someone logs in, signs up or resets a password. Scripts written for Auth0 run as written, with two known differences from Auth0: native addons do not load under Node's permission model, and some built-in modules (`child_process`, `vm`, `v8`, `worker_threads` and similar) are blocked. The design decisions are D-0022 (runtime and isolation), D-0023 (errors) and D-0024 (profiles) in [compat/decisions.md](compat/decisions.md).

## Two modes

| | Legacy (`import_mode: false`) | Import (`import_mode: true`) |
|---|---|---|
| Source of truth | Your store, always | Your store until a user has migrated, then zeroauthy |
| Passwords | Never stored; the `login` script checks every sign-in | Hashed (argon2id) and stored locally after the first successful `login` script run |
| Hosted login, password grants (`password-realm` and the plain `password` grant, which honours `realm`) | `login` on every attempt | `login` for a user not yet migrated. Afterwards the local hash decides and normally no script runs; the script can still run for a migrated user reached through a login the local record no longer matches, but the local hash still decides |
| Sign-up (`/dbconnections/signup`, `/u/signup`) | `get_user` (does the user exist?), then `create`, then `login` to confirm the account | `get_user` (optional), then an ordinary local sign-up; `create` is never called |
| Forgot password | `get_user`; the reset email is sent only for a user it finds | A local user wins; otherwise `get_user` finds the user, who is copied locally without a password |
| Completing a reset | `change_password` | Local; sets the password hash, which finishes the migration |
| Profile fields | Email, username and `email_verified` follow your store on every login; see "Profiles" | Same, on a user's first login (the script is not called afterwards) |

`verify`, `delete` and `change_email` can be stored, but nothing calls them yet: they wait for verification emails and the Management API.

In import mode `get_user` is optional. Without one, sign-up goes ahead locally and a reset request for an address with no local user sends no email.

## Seed syntax

Connections are declared in the seed file, with Auth0's option names:

```yaml
tenants:
  - name: acme
    clients:
      - client_id: web
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["https://app.example.com/"]
    connections:
      - name: legacy-users
        enabledDatabaseCustomization: true
        import_mode: false
        set_user_root_attributes: on_each_login   # or on_first_login
        enabled_clients: [web]
        configuration:
          API: "https://users.internal.example.com"
          TOKEN: "s3cret"
        customScripts:
          login: |
            async function login(email, password, callback) {
              const res = await fetch(configuration.API + "/check", {
                method: "POST",
                headers: { "content-type": "application/json", authorization: "Bearer " + configuration.TOKEN },
                body: JSON.stringify({ email, password }),
                signal: AbortSignal.timeout(5000),
              });
              if (res.status === 401) return callback(new WrongUsernameOrPasswordError(email));
              if (!res.ok) return callback(new Error("user store answered " + res.status));
              callback(null, await res.json());
            }
          get_user: |
            async function getUser(email, callback) {
              const res = await fetch(configuration.API + "/users?email=" + encodeURIComponent(email), {
                headers: { authorization: "Bearer " + configuration.TOKEN },
                signal: AbortSignal.timeout(5000),
              });
              if (res.status === 404) return callback(null);
              if (!res.ok) return callback(new Error("user store answered " + res.status));
              callback(null, await res.json());
            }
```

Rules the seed enforces:

- `customScripts`, `configuration` and `import_mode` need `enabledDatabaseCustomization: true`.
- `customScripts` keys are `login`, `get_user`, `create`, `verify`, `change_password`, `delete` and `change_email`. Each script is at most 100 kB (102400 bytes).
- `configuration` holds at most 64 string values. A key is 1-128 characters of `A-Za-z0-9_`, and a value is at most 4096 bytes.
- `configuration` is plaintext in the seed file only. It is encrypted with the master key when applied, bound to the tenant and connection, and stored sealed. Protect the seed file as you would a secret.
- A legacy connection has no local passwords, so the seed refuses `users` on it. Seeded users are allowed only on import-mode connections.
- A customized connection must define a `login` script.

`tests/e2e/seed.yaml` has a working legacy and import pair backed by a small HTTP store.

## Script contract

A script is one function. Name it as you like; zeroauthy also recognizes the usual names (`login`, `getUser`, `getByEmail`, `create`, `verify`, `changePassword`, `remove`, `deleteUser`, `changeEmail`). Each function takes its arguments and a Node-style `callback(err, result)`; it may also be `async`, and a promise that rejects counts as `callback(err)`.

| Script | Signature | Result |
|---|---|---|
| `login` | `(emailOrUsername, password, callback)` | A profile (below); `WrongUsernameOrPasswordError` if the credentials are wrong |
| `get_user` | `(emailOrUsername, callback)` | A profile, or `callback(null)` for no such user |
| `create` | `(user, callback)` | `callback(null)`. `user` has `tenant`, `client_id`, `connection`, `email`, `password`, and `username`, `user_metadata` and `app_metadata` when present. Use `new ValidationError("user_exists", "...")` for a duplicate |
| `change_password` | `(email, newPassword, callback)` | `callback(null, true)` when changed; `false` when it was not |
| `verify` | `(email, callback)` | Stored, not called yet |
| `delete` | `(id, callback)` | Stored, not called yet |
| `change_email` | `(email, newEmail, verified, callback)` | Stored, not called yet |

**Globals.** `configuration` (the connection's settings, read-only values), `global` (an object the scripts of one connection share while the tenant's process lives, for caching; do not rely on it persisting), `require` (see below), `fetch`, `Headers`, `Request`, `Response`, `crypto`, `console`, and the three error classes.

**Error classes.**

- `new WrongUsernameOrPasswordError(identifier)`: the credentials are wrong. The user sees the ordinary wrong-credentials answer.
- `new ValidationError(code, message)`: the input was rejected. On sign-up the code `user_exists` means the user exists; other codes are shown as a rejected sign-up with your message.
- `new UnauthorizedError(message)`: refuse with a message the user should see. Its message is shown to the user, on every surface. The one other message that reaches users is a `create` script's `ValidationError` on sign-up, which is shown like a rejected sign-up field.
- Any other `Error`, a thrown exception, or an invalid profile is a script failure: the user sees a generic error and the details go to the server log (tenant, connection, script, kind and message). zeroauthy itself never logs passwords or configuration, and it replaces any configuration value in a script's console output and error messages with `■■■■■■■■` before logging (and in the try endpoint's response). Other secrets your scripts print (passwords, tokens fetched at run time) are logged as they are.

How each surface answers is in D-0023.

**Throttles.** A failure the script raised (a plain `Error`, a `ValidationError`, a thrown exception, an invalid profile, a collision) counts as a failed attempt against the login brute-force throttles, because many legacy scripts report a wrong password that way. Failures that kept the script from answering are refunded: a timeout, Node.js missing or too old, a missing script, a configuration that cannot be opened, or a storage error.

### Profiles

`login` and `get_user` return an object. Fields:

- `user_id` (required): a non-empty string or an integer, at most 200 bytes, with no control characters and no `|`. The zeroauthy user ID is `auth0|<user_id>`, so a value of `1042` gives `auth0|1042`.
- `email` and/or `username`: at least one. Email is lowercased and must be valid; username must follow the usual username rules.
- `email_verified`: boolean.
- `name`, `nickname`, `given_name`, `family_name` (at most 300 characters each), `picture` (an https URL).
- `user_metadata`, `app_metadata`: objects.

A bad profile is a script failure; the log names the field, not its value.

Which fields follow your store after the first login (D-0024):

- Email, username and `email_verified` follow your store on every login.
- `name`, `nickname`, `given_name`, `family_name` and `picture` follow it on every login by default, or only at creation with `set_user_root_attributes: on_first_login`.
- `user_metadata` and `app_metadata` are copied once, when the local user is created. Changes made in zeroauthy are never overwritten.
- A profile that clashes with a different user (the ID exists without an identity on this connection, or another user holds the email or username) fails closed and is logged.
- A user blocked in zeroauthy is refused even when the script accepts the password.

## Runtime

- **Node.js 22.13 or later** must be on the server's `PATH`, or set `custom_db.node` to its path. If Node.js is missing or too old, scripts fail as "unavailable" (users see a generic error, the log says why). Install it in container images. The check is cached, so restart zeroauthy after installing or upgrading Node.js.
- **Settings** (YAML `custom_db`, or `ZEROAUTHY_CUSTOM_DB__*`):

  | Key | Default | Meaning |
  |---|---|---|
  | `node` | `node` | Node.js executable |
  | `modules_dir` | none | Absolute path of an npm prefix whose packages scripts may `require` |
  | `max_memory_mb` | 256 (at least 32) | JavaScript heap limit of a tenant's process |
  | `idle_timeout` | 5m | Idle processes are stopped after this |

- **npm packages.** `require()` of Node's safe built-ins works as usual. For third-party packages, install them under a directory you control and point `custom_db.modules_dir` at it:

  ```bash
  npm install --prefix /opt/zeroauthy/modules pg bcryptjs
  ```

  Scripts then use `require("pg")`. Native addons do not load under Node's permission model, so prefer pure-JavaScript packages (for example `bcryptjs` instead of `bcrypt`). Packages in `modules_dir` are code you are choosing to trust: they run with the script's powers. Every file under `modules_dir` is readable by every tenant's scripts, and symlinks are followed, so keep secrets, `.env` files and symlinks out of it.
- **Limits.** One execution may run for 20 seconds; after that the tenant's process is killed. A script may be at most 100 kB.
- **Process model.** Each tenant gets its own Node.js process, started on first use and stopped when idle. Within it, each connection has its own `vm` context.

## Security

What zeroauthy enforces:

- The runner starts with an empty environment. Configuration reaches it only in the request, so scripts cannot read the server's environment variables.
- Node's permission model (`--permission`) allows file reads only in the runner's directory and `modules_dir`, and grants no writes, child processes, workers, addons or WASI. A script cannot read host files, start processes, or reach the server's environment even if it escapes `vm`.
- Methods that signal other processes of the same uid (`process.kill`, `process._kill`, `process._debugProcess`, `process._debugEnd`) and `os.setPriority` are locked and throw. Locking is by name; a future Node release that adds another such method would need it added (D-0022).
- The trust boundary is the tenant, not the connection: the scripts of one tenant run in one shared runner process and can observe each other's requests.
- Tenants never share a process, and `configuration` is encrypted at rest, bound to its tenant and connection.
- The runner's `require` denylist only gives clearer errors. It is not a security control; `--permission` is.

What you must provide when tenants are not trusted:

- **Egress.** Scripts need to reach their user stores, so network access is open, including internal and link-local addresses such as cloud metadata endpoints. Restrict egress with a firewall or an egress proxy.
- **Process isolation.** Runners share the server's uid and kernel. Run zeroauthy under a dedicated uid or in a container, so a runner cannot reach other software on the machine.
- **Memory.** `max_memory_mb` bounds the JavaScript heap only; Buffers sit outside it. Use cgroup or container limits for a hard cap.
- Scripts can read basic host facts through `os` (hostname, network interfaces, CPU count, uptime).

## Migrating off a legacy store

1. Start in import mode (`import_mode: true`) with `login` (and `get_user`) pointing at the old store. Each user migrates on their first successful sign-in; a user who resets their password first migrates too.
2. Watch the logs and the user count until the users you care about have migrated.
3. Switch `get_user` to call back with no user (`callback(null)`), or remove it, and switch `login` to always report no user (`callback(new WrongUsernameOrPasswordError(email))`). `login` must stay defined, because the seed requires it on every customized connection. Migrated users keep working from their local hashes, and the old store is no longer contacted.

Auth0's own automatic-migration guide describes the same sequence.
