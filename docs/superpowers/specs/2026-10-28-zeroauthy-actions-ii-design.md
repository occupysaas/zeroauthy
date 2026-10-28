# zeroauthy — Plan 28: Actions II (signup, password and email triggers, Modules)

- **Status:** Draft for maintainer review; implementation is not started. Builder check done 2026-10-28; its four questions are settled as author calls (§4.1, §4.2, §5, §8).
- **Date:** 2026-10-28
- **Roadmap:** [Plan 28](2026-10-19-zeroauthy-management-roadmap-design.md#plan-28--actions-ii).
- **Predecessor:** [Plan 27 implementation record](../2026-10-27-plan-27-implementation-record.md).
- **Builds on:** [Plan 27 Actions I design](2026-10-27-zeroauthy-actions-design.md).
  Everything there (trust model, sandbox, builds, pinning, fail-closed rules,
  execution records, test endpoint) applies unless this document says otherwise.
- **Implementation plan:** [Plan 28](../plans/2026-10-28-zeroauthy-plan-28-actions-ii.md).

## 1. Intent and scope

Plan 27 gave tenants Actions at login and machine-to-machine token issuance.
Plan 28 extends Actions to every other extension point zeroauthy can
actually call today, and adds **Actions Modules** (shared code reused by
several Actions), so Actions copied from Auth0 tenants for signup, password
and email flows work as written.

The maintainer handed scope to the author (2026-10-28: "skip the questions").
The scoping rule (author's call): **a trigger is in Plan 28 only if zeroauthy
already has the flow that fires it.** A trigger with no caller can't be
tested end to end, and its event would be invented rather than real.

In scope:

| Trigger | Fires from (zeroauthy today) | Kind |
|---|---|---|
| `pre-user-registration` | database-connection signup (`/dbconnections/signup`, hosted signup; custom-DB signup before its create script) | blocking |
| `post-user-registration` | the same signups, after the user exists | non-blocking |
| `post-change-password` | database-connection password changes (§6) | non-blocking |
| `password-reset-post-challenge` | the hosted password-reset page, after the emailed link is opened and before the new-password form | blocking, can redirect |
| `custom-email-provider` | every email zeroauthy sends when the tenant's email provider is `custom` (Plan 21 stores it but cannot run it) | non-blocking, retryable |

Plus the ten Actions Modules operations (§8), the Action `modules` field
(currently refused, D-0053), console, seed and Deploy CLI support.

Deferred, each to the plan that builds its flow:

- `send-phone-message` and `custom-phone-provider` → **Plan 34** (SMS/voice
  and phone providers). Maintainer note (2026-10-28): users will want more SMS
  choices than Twilio, e.g. Amazon and Microsoft. Auth0's own answer is the
  `custom-phone-provider` trigger, which can send through any service (Amazon
  SNS, Azure Communication Services, Vonage and so on), plus built-in Twilio.
  Plan 34 should ship that trigger with ready-made, tested Action examples for
  those services. Adding native non-Twilio phone providers would go beyond
  Auth0 and must be raised with the maintainer as a deviation then.
- `custom-token-exchange` → Plan 35.
- `event-stream` → Plan 32.
- Newer Auth0 triggers seen in the public trigger enum (`password-hash-migration`,
  `login-post-identifier`, `signup-post-identifier`, `post-credential-validation`)
  and Early Access members (pre-user-registration custom user IDs, Akamai risk
  signals, `security_context` JA3/JA4) → listed as deferred in the inventory;
  re-checked against the changelog in Task 1.
- `api.authentication.*` (MFA challenge in password reset) → Plan 33;
  `api.prompt.render` (Forms) → Plan 38. Until then they throw "not supported
  by zeroauthy" and fail the flow closed, like Plan 27's unsupported members.

**Anti-goals.** A failing or timing-out *blocking* Action must never let a
signup or password reset through. A failing *non-blocking* Action must never
undo or block the signup, password change or email that triggered it, and must
never be silently lost (it leaves an execution record and a log line). An
email must never be sent twice because zeroauthy retried something the Action
did not ask to retry, except in the lease-expiry case documented in §5.

## 2. Evidence and constraints

Read `CLEAN_ROOM.md` first. Public sources consulted 2026-10-28:

- Trigger overview: https://auth0.com/docs/customize/actions/explore-triggers
- Per-trigger `event`/`api` references under
  `https://auth0.com/docs/customize/actions/reference/<trigger>/<trigger>-{event,api}-object`
  for the five triggers above.
- Pre-user-registration and post-user-registration overviews; post-change-password overview.
- Modules: https://auth0.com/docs/customize/actions/modules and
  `.../modules/write-your-first-action-module`; limitations page.
- Management API reference: `get-action-modules`, `post-action-module`,
  `get-action-module`, `patch-action-module`, `delete-action-module`,
  `get-action-module-actions`, `post-action-module-rollback`,
  `get-action-module-versions`, `post-action-module-version`,
  `get-action-module-version`; `post-action` (`modules` field,
  `ActionTriggerTypeEnum`).

Facts found (in our words):

- Pre-user-registration runs before a user is created in a database or
  passwordless connection and blocks. `api`: `access.deny(reason, userMessage)`,
  `user.setAppMetadata/setUserMetadata` (aggregated, written with the
  user), `cache.*`, `validation.error(code, message)`. `event` has the
  prospective user (no `user_id`), connection, client, request (with `body`),
  tenant, transaction, secrets.
- Post-user-registration and post-change-password are non-blocking; the
  pipeline continues without waiting and their outcome does not affect the
  transaction. Their `api` is `cache.*` only.
- Password-reset-post-challenge runs after the first reset challenge,
  before the password is reset. `api`: `access.deny(reason)`,
  `authentication.challengeWith/challengeWithAny`, `redirect.*` (with
  `/continue`), `cache.*`, `prompt.render`, `transaction.setResultUrl(url, {query})`.
- Custom-email-provider: `event.notification` (`from`, `to`, `subject`,
  `html`, `text`, `locale`, `message_type`), user, client, tenant (with
  `friendly_name`, `support_email`, …), request, connection. `api`:
  `cache.*`, `notification.retry(reason)` (failed but recoverable; retried up
  to 5 times over the following minutes) and `notification.drop(reason)`
  (failed, never retried); only the last call counts; reasons truncated to
  1024 characters.
- Modules: `require('actions:<module-name>')`; module code exposes
  `module.exports` and reads its own secrets as `actions.secrets`; modules
  have npm dependencies but may not require other modules; they run in the
  importing Action's runtime. Saving changes the draft; publishing makes an
  immutable numbered version. An Action references an exact module version
  (`modules: [{module_id, module_version_id}]`; Deploy CLI uses
  `module_name` + `module_version_number`). Deleting a module in use is `412`;
  publishing with no draft change is `409`; too many versions is `412`.
  Module create `201` (`409` duplicate name), update `200` (name immutable),
  delete `204`, version create `200`, rollback copies an old version into
  the draft. Code ≤ 65,536 chars, name ≤ 255.
- Changelog items already logged by Plan 27 Task 1: Modules GA (Sept 2026);
  pre-user-registration custom user ID assignment Early Access (Sept 2026).

Not documented publicly (Task 1 freezes each as a **D-0054** entry, with live
observation on the maintainer's staging tenant when the observer credentials
are available, otherwise recorded as unavailable and the default below used):

1. Whether Management API user creation fires pre-/post-user-registration
   (default: **no**; signups only).
2. Which password changes fire post-change-password (default: hosted reset
   page including change-password tickets, and Management API `PATCH
   /users/{id}` with `password`; not bulk import or custom-DB-only changes).
3. The wire error for a pre-registration deny/validation error at
   `/dbconnections/signup` (default: `400 {"name":"ExtensibilityError",
   "code":"extensibility_error","description":<userMessage>,"statusCode":400}`
   for `deny`, and `code` = the Action's code for `validation.error`; hosted
   signup shows the user message on the signup page).
4. How an uncaught error or timeout in custom-email-provider is treated
   (default: same as `retry`).
5. The module version limit (default: 100 versions per module) and
   module count limit (default: 100 per tenant).
6. Whether rollback publishes (default: no; it only replaces the draft, as
   the reference describes).

Global constraints (unchanged from Plan 27): Go 1.26.7; Node ≥ 22.13; npm only
on build nodes; SQL migrations additive, next number **0024**; next decision
**D-0054**; tests never contact npm or Auth0; fail closed.

## 3. Trigger catalogue and Management changes

`GET /actions/triggers` lists the seven supported triggers (Plan 27's two plus
the five above) with `binding_policy: trigger-bound`. Creating an Action for
any other trigger stays `400`. Handler names:

| Trigger | Handlers |
|---|---|
| pre-user-registration | `onExecutePreUserRegistration` |
| post-user-registration | `onExecutePostUserRegistration` |
| post-change-password | `onExecutePostChangePassword` |
| password-reset-post-challenge | `onExecutePostChallenge`, `onContinuePostChallenge` (Task 1 confirms the exact names from the reference; the runner accepts the documented names only) |
| custom-email-provider | `onExecuteCustomEmailProvider` |

The test endpoint supports every trigger with Plan 27's dry-run rules: metadata
writes, denials, redirects, result URLs and `notification.retry/drop` are
recorded, not applied; nothing is queued or sent.

The Action `modules` field becomes accepted (§8). `registry_url` and binding
`secrets` remain refused.

## 4. Blocking triggers

### 4.1 Pre-user-registration

Runs inside `identity.Database.Signup` (the single path for
`/dbconnections/signup` and hosted signup) after input validation and the
password policy, before the store insert or a custom-DB create script.

- `event.user`: the submitted profile (`email`, `username`, `name`,
  `given_name`, `family_name`, `nickname`, `picture`, `phone_number`,
  `user_metadata`, `app_metadata` as submitted). No `user_id`, no password.
- `event.request`: `ip`, `hostname`, `method`, `language`, `user_agent`, and
  `body` with every password-like field removed.
- `event.client`, `event.connection`, `event.tenant`, `event.secrets`,
  `event.transaction` (hosted signup only: `locale`, `protocol`,
  `redirect_uri`, `requested_scopes`, `response_mode`, `response_type`,
  `state`, `ui_locales`, `prompt`, `login_hint`, `acr_values`),
  `event.custom_domain.domain` when the request used a custom domain
  (`domain_metadata` empty). `geoip`, `security_context`,
  `authentication.riskAssessment` are omitted (D-0054).
- `api.user.setAppMetadata/setUserMetadata` merge into the user as it is
  created, through existing metadata validation, in the same write.
  Invalid metadata fails the flow. For custom-DB connections whose script owns
  the users (legacy mode), the merged `user_metadata` is passed to the
  `create` script exactly as submitted `user_metadata` is today, and
  `app_metadata` is applied only to zeroauthy's local user record when it is
  written after the script succeeds (author's call; the script contract is
  unchanged).
- `deny` / `validation.error` stop the flow and the signup (wire shape §2
  item 3). Nothing is created.
- Error, timeout or unsupported call: signup fails with a generic error
  (`/dbconnections/signup` `400 extensibility_error` with a generic
  description; hosted page generic error with the execution reference). The
  user is not created.
- If the insert then fails (for example the email already exists), the
  normal signup error is returned and the metadata is discarded.

### 4.2 Password-reset-post-challenge

Runs when the hosted reset page is opened with a valid, unspent reset ticket
(emailed link or change-password ticket), before the new-password form is
shown.

State lives **on the reset ticket in the store** (author's call; the reset
page is otherwise stateless): migration 0024 adds a challenge outcome (`passed`
time and an optional Action result URL) to password-reset tickets.

- GET with bindings present and no recorded pass: run the flow. On success
  record the pass on the ticket, then show the form. A recorded pass skips the
  flow for any browser that opens the same link (the ticket itself is the
  bearer credential, as today).
- `deny`, error or unsupported call records nothing, so reopening the link
  runs the flow again (a deny may depend on the request, e.g. IP).
- POST `/u/reset-password` refuses (generic reset error, ticket not spent)
  when the trigger currently has bindings and the ticket has no recorded pass,
  so a submit cannot skip the challenge. With no bindings, POST behaves as
  today.

- `event`: user (canonical profile), connection, client (when the ticket
  has one), request, tenant, transaction (`locale`, `correlation_id` empty),
  secrets.
- `access.deny(reason)`: the page shows the reset-error view with `reason`;
  the ticket is **not** spent (Auth0: deny stops the reset; other side effects
  stand).
- `redirect.sendUserTo` / `encodeToken` / `validateToken`: Plan 27's
  continue machinery, but the continue state is bound to the reset ticket's
  hash and the `za_reset` page cookie instead of a login session. `/continue`
  then resumes with `onContinuePostChallenge`; when the resumed flow
  completes, the pass is recorded on the ticket and the form is shown.
- `transaction.setResultUrl(url, {query})`: after a successful reset the
  browser goes to this URL (with the query added) instead of the ticket's
  result URL. Same URL rules as ticket `result_url` (absolute `https`, or
  `http` only for localhost). An invalid URL fails the flow.
- `authentication.*`, `prompt.render`: throw "not supported by zeroauthy";
  the flow fails closed (reset page shows the generic error with the
  execution reference; ticket not spent).

## 5. Non-blocking triggers and the job queue

Post-user-registration, post-change-password and custom-email-provider run
after the triggering request, from a durable per-tenant
**Actions job queue** in the store (author's call, so work survives restarts
and is shared across server nodes). Each job holds: tenant, trigger, the
binding list and versions pinned at enqueue time (Plan 27 pinning), the
event snapshot sealed with the master-key envelope (it can contain reset links
and profile data), attempt count, next-attempt time, lease, status and the
execution IDs of its runs.

- The job is enqueued **in the same store transaction** as the user insert,
  password change or email hand-off, so a crash cannot commit the change and
  lose the job; nothing runs until that transaction commits. Where a flow has
  no surrounding transaction (custom-DB script calls), the enqueue follows the
  local write it accompanies.
- The jobs worker claims due jobs with a lease (default 60 s, longer than
  the 20 s flow budget). A node that dies mid-run loses the lease and the job
  runs again: delivery is **at-least-once** in that one case, documented for
  operators.
- Post-user-registration and post-change-password run once. A failed run is
  recorded (execution record with error, operator log line with execution
  ID) and not retried; Auth0 documents no retry for these.
- Custom-email-provider: success when the flow ends without `retry`/`drop`.
  `retry(reason)` (and, by default, an uncaught error or timeout — §2 item 4)
  schedules another attempt: up to 5 retries at 30 s, 1, 2, 4 and 8 minutes
  (local schedule for "over the following minutes"). `drop(reason)` ends it.
  After the last retry it is marked failed. Reasons are truncated to 1024
  characters and logged with the execution ID.
- Completed and failed jobs are purged with their execution records after 10
  days. Queue depth per tenant is capped (default 10,000 pending jobs);
  above the cap, enqueue fails: for registration and password triggers the
  user's action still succeeds and the drop is logged; for email the send
  reports failure as Plan 21 does for a provider error.
- Per-tenant concurrency for job runs reuses the Actions process limits; job
  runs share the tenant's Actions process with blocking triggers, so a
  timeout kills in-flight calls as in Plan 27.

`post-user-registration` `event`: the created user (with `user_id`,
`created_at`, `email_verified`, metadata after pre-registration), connection,
request, tenant, transaction (hosted signup), secrets. `post-change-password`
`event`: user (`user_id`, `email`, `email_verified`, `username`,
`phone_number`, `phone_verified`, `last_password_reset`), connection, request,
tenant, secrets. zeroauthy starts tracking `last_password_reset` on the user
for database connections (it is currently untracked, D-0043 note).

## 6. Custom email provider

When a tenant's email provider is `custom` and enabled, every message that
Plan 21 would hand to a provider transport (verification, reset, welcome,
blocked account, stolen credentials, and the console's test send) becomes a
custom-email-provider job instead. `event.notification` carries the rendered
`from`, `to`, `subject`, `html`, `text`, `locale` and the `message_type` from
Auth0's enum that matches the zeroauthy template; the test send uses
`try_provider_configuration_email`. Other enum values are never produced
until their flows exist.

- With `custom` enabled and no Action bound to the trigger, the send fails
  as a provider configuration error (no silent fallback to another provider).
- Saving `custom` no longer requires it to be disabled; the Plan 21
  "stored-only" restriction is removed and `docs/email.md` updated.
- The send call returns once the job is queued; delivery status is visible
  in the execution record. The test send waits for the first attempt (up to
  the 20 s budget) and reports its outcome, so the console can show whether
  the Action succeeded, asked to retry, dropped or failed.

## 7. Post-change-password sources

Fires after these commit (default per §2 item 2): hosted reset page submit
(reset email or change-password ticket), Management API user update that sets
`password` on a database-connection identity. Not fired by bulk import, by
password-hash migration, or when a custom-DB `change_password` script reports
no change.

## 8. Actions Modules

| Operation | Scope | Success |
|---|---|---|
| `GET /actions/modules` (`page`, `per_page`; no paging when absent) | `read:actions` | 200 `{modules,total,page,per_page}` |
| `POST /actions/modules` (`name`, `code`, `secrets?`, `dependencies?`, `api_version?`, `publish?`) | `create:actions` | 201; 409 duplicate name |
| `GET /actions/modules/{id}` | `read:actions` | 200 |
| `PATCH /actions/modules/{id}` (`code?`, `secrets?`, `dependencies?`; no `name`) | `update:actions` | 200 |
| `DELETE /actions/modules/{id}` | `delete:actions` | 204; 412 if used |
| `GET /actions/modules/{id}/actions` | `read:actions` | 200 `{actions,total,page,per_page}` |
| `POST /actions/modules/{id}/rollback` (`module_version_id`) | `update:actions` | 200; draft replaced |
| `GET /actions/modules/{id}/versions` | `read:actions` | 200 paged |
| `POST /actions/modules/{id}/versions` | `update:actions` | 200; 409 nothing to publish; 412 limit |
| `GET /actions/modules/{id}/versions/{versionId}` | `read:actions` | 200 |

`publish: true` on create waits for the draft build like Plan 27's
`deploy: true` (up to the build timeout) and then publishes in the same
request; a failed or timed-out build returns the same error as Plan 27's
deploy path and the module is not created. `POST .../versions` with a draft
build that is not `built` is `400` (D-0053's `ErrDraftNotBuilt` mapping); `409`
is kept for "no draft change since the last version".

Shapes follow the public schema (`actions_using_module_total`,
`all_changes_published`, `latest_version_number`, `latest_version`).
`secrets` on PATCH replaces the whole list (Auth0 rule); values are
write-only and sealed per tenant+module like Action secrets.

**Build and runtime.** A module draft has its own dependency set and build
(Plan 27 build pipeline, same limits). Publishing requires the draft build to
be `built`, snapshots code, dependencies, build and secrets into an immutable
version. An Action's draft lists module versions by
`{module_id, module_version_id}` or `{module_name, module_version_number}`;
responses return all four fields. Deploying an Action pins those module
versions into the Action version, so later module publishes change nothing
until the Action is redeployed (Auth0: no automatic upgrades). Unknown module
or version → `400`. At most 10 modules per Action (local).

In the runner, `require('actions:<name>')` returns the module version pinned
for that Action version, evaluated once per (Action version, module version)
in its own context. The module's own `require` resolves only inside the
module's build tree; it cannot require `actions:*`. Its `actions.secrets` are
the module version's secrets, masked in logs like Action secrets. Module
objects are not shared between Actions.

"In use" (delete `412`, `actions_using_module_total`, `GET .../actions`)
means referenced by any Action's draft or any Action's currently deployed
version (author's call). Deleting a module that only older Action versions or
queued jobs still pin removes the module from the API but keeps those pinned
module versions as hidden tombstones (code, build, sealed secrets) until no
Action version or job references them; they are purged with the last
referencing Action version or job. Pinned runs and redeploys of old versions
therefore keep working, matching Plan 27's "finish on pinned versions" rule.

## 9. Storage and plugins

Migration 0024 (three dialects): modules, module versions, module secrets,
Action-version → module-version pins, Action-draft module references,
module tombstones, the Actions job queue, the reset-ticket challenge outcome,
`users.last_password_reset`. Memory and gRPC plugin support
behind an Actions capability bump (Plan 27 rule: older plugins fail startup
when Actions are configured). Tenant deletion removes everything. Purges run
on the jobs worker.

## 10. Console, seed, Deploy CLI

Console: the Triggers page lists all seven triggers; the Action editor gains
"Modules" (pick module and version) and test payload templates per trigger;
a new Modules section (list, create, editor with dependencies and secrets,
build status, publish, versions, rollback, "used by" list); the email
provider page enables `custom` with a note that it needs a bound Action and a
test-send result view. Execution lookup shows job attempts.

Seed: modules (code, dependencies, secrets, publish) and Action module
references by name+number, create-only ownership like Plan 27. Deploy CLI:
round trip modules and Action module references in YAML and directory
formats × generated/preserved credentials, if the pinned Deploy CLI 9.1.0
supports them (Task 1 checks its source); otherwise record unavailable and
cover Actions on the new triggers only.

## 11. Acceptance

- Every new operation: scopes, 401/403/404 cross-tenant, 409/412 paths,
  malformed bodies, limits; inventory and OpenAPI updated.
- Memory/SQLite/PostgreSQL/MySQL/gRPC conformance for modules, pins and the
  job queue (claim/lease/expiry, retry schedule, purge, concurrency), and
  migration from 0023 data.
- Engine/runner: each trigger's event and api (supported, empty, unsupported
  members), module require/secrets/isolation (a module cannot read the Action's
  secrets or another tenant's modules), pinning across module publishes.
- Integration: signup deny/validation/metadata/error on both signup paths and
  custom-DB signup; post-registration and post-change-password run after
  commit and never block; reset-page deny, redirect/continue, result URL,
  unsupported challenge; custom email success, retry schedule, drop, no
  binding, test send.
- E2E: auth0-cli `actions` plus `auth0 api` for modules; node-auth0 for the
  module operations it exposes (raw requests otherwise); browser flows for
  hosted signup deny message and reset-page redirect round trip; a custom
  email provider Action delivering verification email to a local HTTP sink;
  console Playwright flows; Deploy CLI matrix (§10).
- Full regression lanes, SQL script and OpenID conformance as in Plan 27.

Record actual results in a Plan 28 implementation record; update the matrix,
decisions, operator guide (`docs/actions.md`, `docs/email.md`) and roadmap only
to the demonstrated degree.
