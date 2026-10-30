# Plan 31 — Logs, log streams, stats

**Date:** 2026-10-30. **Status:** specification; implementation not started.

**Predecessor:** [Organizations II](2026-10-29-zeroauthy-organizations-ii-design.md),
merged as `4975aef` on main. Roadmap entry: [management roadmap §3, Plan 31](2026-10-19-zeroauthy-management-roadmap-design.md).
Read the [clean-room policy](../../../CLEAN_ROOM.md) and the [Actions guide](../../actions.md).

## 1. Outcome and scope

An operator can see what happened in a tenant the way Auth0 shows it: every
login, signup, token exchange, logout, password and verification step, blocked
attempt and Management API write produces an Auth0-typed log event. The
operator can search the events, open one, follow them live, send them to an
external system through a log stream, and read daily login and signup counts.

**Maintainer ruling (2026-10-30):** "just make it similar to auth0". Every
choice follows Auth0's documented behaviour. Where zeroauthy has no equivalent
(subscription tiers, Auth0's cloud accounts), this spec makes a local ruling
and marks it as one.

**Primary use case.** The maintainer has used Auth0 logs only to troubleshoot
custom Actions flows. That journey is the first acceptance scenario (§9). It
starts with a failed or surprising login, goes from the log event to its Action
execution, then to each Action's result, error and `console.log` output, and
ends with watching the next attempt arrive live. Every other part of this plan
is Auth0 parity; this journey must also work smoothly.

Included:

- `GET /api/v2/logs` (Lucene `q`, page/per_page, checkpoint `from`/`take`),
  `GET /api/v2/logs/{id}`, `GET /api/v2/users/{id}/logs`.
- Log events written from the Authentication API, hosted pages, Management API,
  Actions, jobs and attack protection, with Auth0's event type codes.
- `/api/v2/log-streams` CRUD with filters, PII configuration and `startFrom`;
  delivery for `http`, `datadog`, `splunk`, `sumo`, `segment` and `mixpanel`.
- `GET /api/v2/stats/active-users` and `GET /api/v2/stats/daily`.
- Retention and purge, memory/SQL/gRPC storage, migration, console pages
  (Logs, Log streams, Actions logs, stats on Home), seed and Deploy CLI.

Excluded: event streams (Plan 32), GeoIP `location_info` (§3, local ruling),
`eventbridge`/`eventgrid` delivery (§6), Auth0's dashboard log export to CSV,
and the paid log-streaming "health" add-ons. No log-search service (no
Elasticsearch) is introduced; SQL is the engine.

## 2. Evidence and compatibility rules

Public references to review in Task 1:

| Contract | Primary source |
| --- | --- |
| Log object, Lucene fields, paging and checkpoint limits | [Get log events](https://auth0.com/docs/api/management/v2/logs/get-logs), [Log search query syntax](https://auth0.com/docs/deploy-monitor/logs/log-search-query-syntax) |
| Event type codes and descriptions | [Log event type codes](https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes) |
| Retention by plan | [Log data retention](https://auth0.com/docs/deploy-monitor/logs/log-data-retention) |
| User logs | [Get user log events](https://auth0.com/docs/api/management/v2/users/get-logs-by-user) |
| Log stream fields, sink types, filters, PII config, status | [Log streams API](https://auth0.com/docs/api/management/v2/log-streams/post-log-streams), [Log streams overview](https://auth0.com/docs/customize/log-streams) |
| HTTP stream payload, batching, content formats | [Custom log streams using HTTP webhooks](https://auth0.com/docs/customize/log-streams/custom-log-streams) |
| Filter categories | [Log stream event filters](https://auth0.com/docs/customize/log-streams/event-filters) |
| Stream suspension and retries | [Log streams health](https://auth0.com/docs/customize/log-streams#log-stream-health) |
| Active users, daily stats | [Get active users](https://auth0.com/docs/api/management/v2/stats/get-active-users), [Get daily stats](https://auth0.com/docs/api/management/v2/stats/get-daily) |
| Action execution IDs in login logs | [Actions troubleshooting](https://auth0.com/docs/customize/actions/test-actions), [Get execution](https://auth0.com/docs/api/management/v2/actions/get-execution) |

These are documentation evidence. Task 1 freezes into
`internal/logrules/inventory.json` and decision **D-0057**: every route's
scopes, query parameters and limits, the response envelopes, the log
object's fields, the full event-type-code table with descriptions and filter
categories, the Lucene field list, the stream sink schema for every type
(including which fields are secret), the status transitions and the error
codes. Points the documents leave open go to permitted firewalled
observation on the maintainer's tenant (CLEAN_ROOM.md). An implementer must
not observe the same area. If no evidence is available, the local rulings
below stand and the gap is recorded.

All IDs are tenant-scoped; cross-tenant references behave as missing. Keep
Management API authentication, live operator grant checks, strict body
parsing and pagination conventions. Publish `x-source` entries and
regenerate API, protobuf and console outputs. Use Go 1.26.7 and Node >=22.13
and keep the repository's dependency pins. No new Go module dependency is
needed.

## 3. The log event

### Shape

A stored event is the Auth0 log object: `log_id`, `date`, `type`,
`description`, `client_id`, `client_name`, `connection`, `connection_id`,
`strategy`, `strategy_type`, `user_id`, `user_name`, `audience`, `scope`,
`ip`, `hostname`, `user_agent`, `isMobile`, `organization_id`,
`organization_name`, `tenant_name`, `details` and `$event_schema` where
documented. Fields with no value are omitted, as Auth0 does. Task 1 freezes
the exact list.

`location_info` is omitted (local ruling). Auth0 derives it from its own
GeoIP data; zeroauthy ships none and adding a database is outside this plan.
Record it as a follow-up and in the compatibility matrix.

`log_id` is an opaque string of decimal digits, like Auth0's. Locally it
encodes a store-assigned sequence that orders events within a tenant;
callers must treat it as opaque. `GET /logs/{id}` accepts it.

### Event types

Write events for every feature zeroauthy has. The Task 1 table maps each
code to its trigger point in our code. It covers at least:

| Area | Codes (per Auth0's table) |
| --- | --- |
| Login | `s`, `f`, `fp`, `fu`, `fc`, `fcoa`/`scoa`, `ssa`/`fsa` (silent auth), `sertft`… |
| Signup | `ss`, `fs`, `signup_pwd_leak` |
| Tokens | `seacft`/`feacft` (code), `seccft`/`feccft` (client credentials), `sertft`/`fertft` (refresh), `sepft`/`fepft` (password), device-code success/failure codes, `sede`/`fede` where documented |
| Logout | `slo`, `flo` |
| Password | `scp`/`fcp`, `scpr`/`fcpr`, `scpn`, `pwd_leak`, `reset_pwd_leak` |
| Verification and email | `sv`/`fv`, `svr`/`fvr`, `sce`/`fce`, `sn`/`fn` |
| Users | `du`/`fdu`, `sui`/`fui` (import job), `sd`/`fd` where documented |
| Blocks | `limit_wc`, `limit_mu`, `limit_sul`, `ubr` (unblock) |
| Management API | `sapi`, `fapi`, `mgmt_api_read` |
| Organizations | invitation acceptance codes where documented |
| Other | `w`, `depnote`, `api_limit` where applicable |

The ellipsis and "where documented" are deliberate: Task 1 replaces this
table with the frozen list. A code zeroauthy cannot produce (for example
an MFA code before Plan 33) is listed as "not emitted yet" with its plan.
No event is invented under a new code; anything without an Auth0 code goes
only to the server log.

### Management API events

One middleware writes `sapi` for every successful Management API write and
`fapi` for every failed one, plus `mgmt_api_read` for reads that return
secrets, as Auth0 documents. This replaces the per-handler `audit` server-log
calls (91 call sites) and the management design §6 "server log until logs
exist" rule; the server log keeps a one-line record. `details` carries the
request (method, path, query, redacted body, `auth` with the client ID or
operator user ID and strategy) and the response status and redacted body,
following Auth0's documented `details` shape. Redaction (§3 privacy) is the
same allowlist approach for every resource. Reads without secrets write
nothing.

### Actions

Every log event produced by a flow that ran Actions carries
`details.actions.executions` with the execution IDs, as Auth0 does. A login
denied by `api.access.deny` writes `f` with the denial reason as the
description. An Action that threw writes the matching failure code with a
generic description and the execution ID. Asynchronous trigger jobs (post
user registration, post change password, custom email provider) that fail
after retries write a failure event carrying the execution ID. Secrets never
appear; the existing redactor applies.

`GET /api/v2/actions/executions/{id}` keeps its Auth0 response shape. Captured
`console.log` lines are a console-only troubleshooting feature (§7). Auth0
shows them in its dashboard's Actions real-time logs, not through the
Management API. Store up to 64 KiB of redacted console lines per Action
result with the execution and keep them for the execution's existing ten-day
retention (local ruling). They are exposed only through the system API to
the console.

### Privacy

IP and user agent are recorded as Auth0 records them. Never log passwords,
OTPs, tickets, codes, tokens, client secrets, Action secrets, private keys,
email provider credentials, stream sink secrets or invitation URLs.

**Maintainer requirement (2026-10-30):** passwords must never reach logs.
Any property named like a secret or password is hidden automatically before
it reaches its destination. This is enforced in three independent layers,
so a mistake in one does not leak:

1. **Allowlist at the source.** Request and response bodies in `details`
   pass through a per-resource allowlist. Anything not allowlisted is
   replaced by Auth0's redaction marker as frozen in Task 1.
2. **Key-name scrubber at every sink.** One function in `internal/logscrub`
   runs on the final JSON of every event immediately before it is stored,
   handed to a stream sender, returned to the console, or written to the
   server log. It walks every object and array at any depth, including JSON
   encoded inside strings in `details.request.body` and
   `details.response.body`. It replaces the value of any property whose
   name, compared case-insensitively after removing `_`, `-` and `.`,
   *contains* `password`, `passwd`, `pwd`, `secret`, `token`, `authorization`,
   `apikey`, `privatekey`, `credential`, `otp` or `recoverycode`. The value
   becomes the redaction marker, whatever its type. The list lives in
   `internal/logscrub` and only grows. This layer has no allowlist: a field
   that matches is hidden even if a lower layer allowed it. Over-hiding is
   accepted: harmless settings such as `token_endpoint_auth_method` or
   `refresh_token.rotation_type` also show the marker in Management API
   event bodies. The log object's own top-level fields are never matched.
3. **Per-request value mask.** A password, OTP or ticket submitted in the
   request is registered with that request's redactor, alongside the
   existing Action/custom-database secret redactor. Any free text captured
   while serving it (descriptions, error messages, custom-database and
   Action console lines) has that exact value masked. This catches a script
   that prints a password without a property name.

Events whose free text cannot be made safe are dropped rather than written.
Tests assert that a representative set of secrets, including a password
nested in metadata, a password inside a JSON string body, a password echoed
by an Action and a custom-database script `console.log(password)`, never
reaches any stored row, stream payload, console response or server log line.
A fuzz test feeds random nested JSON with secret-named keys through the
scrubber and checks that none survive.

### Write path

Log writes never fail or slow the request that caused them. Each process
has a bounded in-memory queue that a writer drains in batches into the store,
in its own transaction, separate from the business transaction. If the queue
is full, the event is dropped, a counter goes up and the server log warns at
most once a minute. Shutdown flushes with a deadline. This is weaker than
transactional logging and is a deliberate local ruling that matches Auth0's
"logs are not guaranteed" wording. Recording an event is at-most-once.

Events are visible to readers when their batch commits. Checkpoint reads
(`from`) return only events at least two seconds old, so that an event
committed late by another instance cannot be skipped. This matches Auth0's
documented eventual consistency. Page reads have no delay.

## 4. Retention and storage

Auth0 ties retention to the subscription (1 to 30 days). zeroauthy has no
tiers, so retention is deployment configuration: `logs.retention`, default
30 days and minimum 1 day (local ruling). An hourly sweep deletes expired
events in bounded batches across instances, using the existing leader/lease
pattern. Deleting a tenant deletes its logs, streams and stats. Deleting a
user keeps that user's events, as Auth0 does.

SQL migration `0028_logs.sql` (renumber if another one lands first) in
SQLite, PostgreSQL and MySQL. It adds:

- the log table: tenant, sequence (store-assigned, monotonic), log ID,
  date, type, user/client/connection/organization IDs, IP and the event
  JSON. Indexes cover (tenant, sequence), (tenant, user, sequence),
  (tenant, type, sequence) and (tenant, date).
- the log stream table and its checkpoint, lease and failure columns;
- the daily stats table (tenant, UTC date, logins, signups, leaked passwords,
  created/updated).

The memory store keeps a bounded per-tenant ring (default 10,000 events,
local) for tests and single-node development.

A separately negotiated **Logs v1** gRPC capability carries the log,
stream and stats repositories. Without it, the Management routes in this
plan return 501 `logs_unavailable`, events go to the server log only, and the
console shows the section as unavailable. Transient capability errors are
retried, not cached. Older plugins keep working.

## 5. Logs API

`GET /api/v2/logs`:

- **Page mode:** `page`, `per_page` (max 100), `sort` (`date:1`/`date:-1`,
  default newest first), `fields`/`include_fields`, `include_totals`, `q`.
  Auth0 limits page mode to the first 1,000 results; `(page+1)*per_page`
  above that is 400 with Auth0's error code.
- **Checkpoint mode:** `from` (a log ID) and `take` (max 100) return events
  after `from` in ascending order. Without `from`, `take` returns the most
  recent events. `q` and checkpoint parameters combine as Auth0 documents.
  `auth0 logs tail` uses this mode.
- Scope `read:logs`. `GET /logs/{id}` uses the same scope.

`GET /api/v2/users/{id}/logs` takes `page`, `per_page`, `sort` and
`include_totals` with scopes `read:logs` and `read:logs_users`, as
documented.

The Lucene subset reuses the parsing approach of `internal/orgsearch`
(bounded AST, one evaluator for memory, parameterized SQL for each driver) in
a new `internal/logsearch`. It accepts the fields Task 1 freezes (at least
`type`, `date` ranges, `user_id`, `user_name`, `client_id`, `client_name`,
`connection`, `connection_id`, `ip`, `strategy`, `organization_id`,
`description`, `log_id`, `hostname`), AND/OR/NOT, grouping, quoted strings,
trailing wildcards and date ranges. Leading wildcards, fuzzy, regex and
unknown fields are rejected with 400. Query length and depth have the same
bounds as organization search. SQL fetches one page at a time.

## 6. Log streams

Routes: `GET/POST /api/v2/log-streams`, `GET/PATCH/DELETE
/api/v2/log-streams/{id}` with `read:`, `create:`, `update:` and
`delete:log_streams`. Fields: `id`, `name`, `type`, `status` (`active`,
`paused`, `suspended`), `sink`, `filters`, `isPriority`, `pii_config` and the
create-only `startFrom`. Unknown fields and type-mismatched sink fields are
rejected. `type` is immutable.

Sinks delivered locally:

| Type | Delivery |
| --- | --- |
| `http` | POST to `httpEndpoint` with `httpContentType`, `httpContentFormat` (`JSONARRAY`, `JSONLINES`, `JSONOBJECT`), `httpAuthorization`, `httpCustomHeaders` |
| `datadog` | Datadog logs intake for `datadogRegion` with `datadogApiKey` |
| `splunk` | Splunk HEC at `splunkDomain`/`splunkPort` with `splunkToken`, `splunkSecure` |
| `sumo` | `sumoSourceAddress` |
| `segment` | Segment track API with `segmentWriteKey` |
| `mixpanel` | Mixpanel import API with region, project and service account |

Each delivered item is `{"log_id": …, "data": <log object>}` in the
documented formats. Task 1 freezes each vendor's request shape from Auth0's
documentation and the vendor's public API documents. `eventbridge` and
`eventgrid` need an Auth0-operated cloud account. They are accepted and
stored, so Deploy CLI round trips work, but are never delivered. They are
created with `status: "suspended"`, the console says why, and resuming them
is 400 (local ruling).

Sink secrets (authorization, API keys, tokens, passwords, write keys) are
encrypted with the master key and redacted on read as Task 1 freezes. A
PATCH that omits a secret keeps it.

**Filters** use Auth0's category names (for example
`auth.login.success`). Task 1 maps every emitted code to one category. An
empty filter list sends everything.

**PII config** (`log_fields` among `first_name`, `last_name`, `username`,
`email`, `phone`, `address`; `method` `mask` or `hash`; `algorithm`
`xxhash`) is applied to the outgoing copy only, never to stored events.
xxhash64 is implemented in-tree, with no new dependency (local ruling).

**Delivery** is ordered and at-least-once per stream. Each stream keeps a
checkpoint (the last delivered sequence). A worker holds the stream's lease
(the Plan 28 lease pattern: a lease-until column and conditional update, not
a second job engine). It reads the next batch after the checkpoint, at least
two seconds old (§3), filters it, applies PII config, sends it with a 10 s
timeout, and advances the checkpoint only on a 2xx response. Batches hold
up to 100 events. `startFrom` sets the initial checkpoint; otherwise the
stream starts at the latest event.

Failures retry with exponential backoff (1 s to 5 min). After failures
lasting 24 hours (local default for Auth0's undocumented threshold), the
stream becomes `suspended` and delivery stops. PATCH to `active` resumes from
the checkpoint, and events that expired meanwhile are skipped, as on Auth0. A
`paused` stream keeps its checkpoint. Delivery state (last success, last
error class, consecutive failures) is kept for the console through the
system API and never includes response bodies or secrets.

**Outbound network.** Endpoints must be HTTPS, except when the deployment sets
`logs.streams.allow_insecure_http` for local testing. Private, loopback and
link-local addresses are refused at dial time (after DNS resolution) unless
`logs.streams.allow_private_networks` is set. The custom-domain/HTTP client
helpers' existing dialer guard is reused if one exists; otherwise this plan
adds one in `internal/httpx`.

## 7. Stats, console and provisioning

**Stats.** `GET /api/v2/stats/daily?from=YYYYMMDD&to=YYYYMMDD` returns
`[{date, logins, signups, leaked_passwords, created_at, updated_at}]` from the
daily table. The log writer updates the table from the same batch (successful
login codes, signup success, leaked-password codes), so stats survive log
retention. The default and maximum range follow Task 1. `GET
/api/v2/stats/active-users` returns the number of users whose last
successful login is within 30 days, computed from user `last_login`. Scope
`read:stats`.

**Console.** The planned `logs` section becomes live under Monitoring:

- **Logs:** a table with time, type (code and description), description,
  application, connection and user. It has a search box taking the Lucene
  subset, quick filters (failures only, one user, one application), paging and a **Live** toggle
  that polls in checkpoint mode. A detail drawer shows the full JSON and
  links to the user, application and each Action execution.
- **Action execution view:** trigger, status, each Action's name, timing,
  error and captured console lines, linked from log details and from the
  Actions section.
- **Actions logs:** a live view of recent executions for the tenant, with
  trigger and Action filters, showing console lines as they arrive. This
  follows Auth0's dashboard Actions real-time logs. It polls a system API
  endpoint; nothing is held only in one process's memory.
- **Log streams:** list, create/edit per type with secret fields write-only,
  status with pause/resume, and delivery state. The `eventbridge`/`eventgrid`
  forms explain that they are not delivered.
- **Home:** logins and signups for the last 30 days, using the shared
  dataviz palette, plus active users.

All requests capture the tenant and ignore stale responses after a tenant
switch. Localize all strings through the existing catalog.

**Seed and Deploy CLI.** Seed may declare log streams (create-only, secrets
from the environment as existing secrets do). The pinned Deploy CLI's log
stream handler round trips stream configuration in YAML and directory
formats with secrets excluded, as the tool does. Logs and stats are never
exported.

## 8. Decisions this spec makes (local rulings)

1. Retention is deployment configuration, default 30 days.
2. Log recording is asynchronous and at-most-once; it never fails a request.
3. Checkpoint reads wait two seconds so they never skip a late commit.
4. `location_info` is omitted.
5. `eventbridge`/`eventgrid` are stored and permanently suspended.
6. A stream is suspended after 24 hours of failures.
7. Outbound stream delivery refuses private networks unless configured.
8. Action console lines are kept 64 KiB per result for ten days, console only.
9. Management API events come from one middleware, not per handler.
10. A key-name scrubber hides secret- and password-named properties at every
    sink, on top of Auth0-style allowlisting (maintainer requirement).

Each is recorded in D-0057 and the compatibility matrix.

## 9. Acceptance and completion

- **Actions troubleshooting journey (first).** A browser login runs a
  post-login Action that logs to the console and then denies access. The
  console's Logs page shows the `f` event with the denial reason within
  seconds (Live on). Its detail links to the execution, which shows the Action,
  its error and its console lines with secrets masked. `auth0 logs tail` (pinned
  auth0-cli) shows the same event. Fixing the Action and retrying shows `s`
  with the execution ID.
- `auth0 logs list` with a filter, `node-auth0` `logs.getAll` page and
  checkpoint modes and `users.getLogs` agree with the stored events across
  memory, SQLite, PostgreSQL and MySQL.
- Each emitted code in the frozen table has a test that triggers it. Codes
  marked "not emitted yet" are listed in the guide.
- An `http` stream delivers to a local test server in all three formats with
  filters and PII masking. It survives a server restart without loss (and
  with possible duplicates), suspends after simulated long failure and resumes.
  `auth0 logs streams` commands manage it.
- No secret from the representative set appears in any stored event, stream
  payload, console response or server log line, including passwords nested in
  metadata, inside JSON string bodies, or printed by Actions and
  custom-database scripts. The scrubber fuzz test passes.
- Daily stats and active users match the events produced by the E2E.
- Queue overflow drops events without failing logins; retention purge
  removes only expired rows; tenant deletion removes everything.
- Logs v1 capability matrix: an old plugin keeps working with logs
  unavailable.
- Run the focused tests, the full Go race suite, all three SQL drivers, the
  console tests and the affected E2E lanes. Report every actual result and
  every check not run. Plan 19's database hold applies only to Plan 19.

The implementation record maps each condition to evidence or an explicit
limitation. Writing this spec and its plan does not mean anything is
implemented or passing.
