# Plan 32 — Event streams

**Date:** 2026-11-01. **Status:** implemented and locally verified 2026-11-02; see the [completion record](../2026-11-01-plan-32-implementation-record.md) for actual results, deviations and limitations.

**Predecessor:** [Logs, log streams, stats](2026-10-30-zeroauthy-logs-streams-stats-design.md),
merged as `03a8d7a` on main. Roadmap entry: [management roadmap §3, Plan 32](2026-10-19-zeroauthy-management-roadmap-design.md).
Read the [clean-room policy](../../../CLEAN_ROOM.md), the [logs guide](../../logs.md)
and the [Actions guide](../../actions.md).

## 1. Outcome and scope

An operator can subscribe to changes in a tenant the way Auth0 offers it.
When a user, organization or enterprise connection is created, updated or
deleted, zeroauthy produces an Auth0-shaped CloudEvent. Event streams send
those events to a webhook or an `event-stream` Action. The operator can
test a stream, see failed deliveries, redeliver them, and read the same
events live from the Events API.

**Maintainer ruling (2026-11-01):** "same rules, just follow Auth0's
documentation". Every choice follows Auth0's documented behaviour. Where
Auth0 depends on its own cloud (AWS EventBridge) or leaves a number
unstated, this spec makes a local ruling and marks it as one.

Included:

- `/api/v2/event-streams`: list (`from`/`take`), create, get, update,
  delete; `POST /{id}/test`; `GET /{id}/deliveries` and
  `GET /{id}/deliveries/{event_id}`; `POST /{id}/redeliver` and
  `POST /{id}/redeliver/{event_id}`.
- `GET /api/v2/events`: the Server-Sent Events (SSE) Events API.
- CloudEvents for every catalog event type zeroauthy has a feature for
  (§3), written in the same transaction as the change.
- Delivery to `webhook` (basic, bearer and custom-header authorization) and
  to `action` destinations, the `event-stream` Action trigger that Plan 28
  deferred, retries, failure records, redelivery and auto-disable.
- Memory/SQL/gRPC storage, migration, console page, seed and Deploy CLI.

Excluded: `eventbridge` delivery (§6: stored, never delivered), `group.*`
and `organization.group.*` events (groups are Plan 38), `context.request.geo`
contents (no GeoIP, as Plan 31), and Auth0 plan-based quotas.

## 2. Evidence and compatibility rules

Public references to review in Task 1:

| Contract | Primary source |
| --- | --- |
| Routes, bodies, scopes, status codes | [Management API OpenAPI document](https://auth0.com/docs/oas/management/v2/management-api-oas.json) (`event-streams` and `events` paths), [Create an event stream](https://auth0.com/docs/api/management/v2/event-streams/post-event-streams) |
| Event types and payload schemas | [Event catalog schema](https://auth0.com/docs/oas/events/events-schema.json) (catalog version 0.13.6 at writing), [Events catalog](https://auth0.com/docs/events) |
| Overview and destinations | [Events](https://auth0.com/docs/customize/events), [Create an event stream](https://auth0.com/docs/customize/events/create-an-event-stream) |
| Retries, ordering, duplicates, auto-disable | [Events best practices](https://auth0.com/docs/customize/events/events-best-practices) |
| Test, deliveries, redelivery | [Test, monitor and retry event streams](https://auth0.com/docs/customize/events/event-testing-observability-and-failure-recovery) |
| Events API (SSE) | [Consume events with the Events API](https://auth0.com/docs/customize/events/consume-events-with-events-api) |
| `event-stream` Action trigger | [Event stream trigger](https://auth0.com/docs/customize/actions/explore-triggers/event-stream), [event object](https://auth0.com/docs/customize/actions/reference/event-stream/event-stream-event-object), [API object](https://auth0.com/docs/customize/actions/reference/event-stream/event-stream-api-object) |
| Write-only authorization secrets | [Terraform `auth0_event_stream` resource docs](https://registry.terraform.io/providers/auth0/auth0/latest/docs/resources/event_stream) (`password`, `token`, `header_value`) |

These are documentation evidence. The published OpenAPI document omits the
write-only secrets; the Auth0 guide (`token`) and the Terraform documentation
(`password`, `token`, `header_value`) name them. Task 1 freezes into
`internal/eventrules/inventory.json` and decision **D-0058**: every route's
scopes, parameters, limits, bodies and errors; the event-type list with its
payload field allowlists (from the catalog schema); the destination schemas
with secret fields marked; the delivery and auto-disable numbers; and the
SSE wire format.

Points the documents leave open go to permitted firewalled observation on the
maintainer's tenant (CLEAN_ROOM.md), by a separate observer session, in
`docs/compat/observations/event-streams.md`. An implementer must not observe
the same area. Observation points:

- **E1** Request headers and body of a webhook delivery (content type,
  user agent, any signature or ID header) and the response timeout.
- **E2** Which user changes produce `user.updated`: metadata edits, password
  change, block, email verification, login (`last_login`/`logins_count`),
  identity link/unlink. Whether `previous_object` is full or partial.
- **E3** The delivery `id` format, whether a delivery record exists for
  successful deliveries, and what happens to a failed record after a
  successful redelivery.
- **E4** The test endpoint: synchronous attempt or queued; the default
  `data` when none is given; response when the stream is disabled.
- **E5** Auto-disable: the meaning of the "three consecutive delivery attempt
  failures" bullet next to "500 failures in a row" and "5000 total"; the
  error when re-enabling above the threshold.
- **E6** Maximum number of streams per tenant (the 409 case), duplicate name
  behaviour, and whether PATCH may change `action_id` or the destination type.
- **E7** `GET /api/v2/events`: heartbeat and `offset-only` cadence, how long
  a cursor stays valid (the 410 case), connection cycling and the
  concurrent-connection limit (the 403 case).
- **E8** The `eventbridge` response's `aws_partner_event_source` value.

If no evidence is available, the local rulings below stand and the gap is
recorded. All IDs are tenant-scoped; cross-tenant references behave as
missing. Keep Management API authentication, live operator grant checks,
strict body parsing (`additionalProperties: false`) and pagination
conventions. Publish `x-source` entries and regenerate API, protobuf and
console outputs. Use Go 1.26.7 and Node >=22.13 and keep the repository's
dependency pins. No new Go module dependency is needed.

## 3. Events

### Types

The Task 1 table lists all 25 catalog types. zeroauthy emits:

| Type | Emitted when |
| --- | --- |
| `user.created` | any path creates a user: signup, Management API, import job, federated/social first login, custom-database import, seed |
| `user.updated` | a user's stored profile changes, per E2 (local default below) |
| `user.deleted` | a user is deleted |
| `organization.created`/`updated`/`deleted` | organization CRUD |
| `organization.member.added`/`deleted` | membership changes, including invitation acceptance and `assign_membership_on_login` |
| `organization.member.role.assigned`/`deleted` | organization member role changes |
| `organization.connection.added`/`updated`/`removed` | organization enabled-connection changes |
| `connection.created`/`updated`/`deleted` | only for connections whose strategy is in the catalog's list (`oidc`, `okta`, `samlp`, `pingfederate`, `adfs`, `ad`, `google-apps`, `waad`); today that means `oidc` and `waad` |

Not emitted yet: `group.*` and `organization.group.role.*` (Plan 38). A
connection strategy added later starts emitting when the catalog lists it.
No event is invented under a new type.

**Local default for `user.updated` (until E2 answers):** emitted for
Management API updates, identity link/unlink, password change or reset,
email verification, block/unblock and metadata changes from Actions; not
emitted for `RecordLogin` (`last_login`, `last_ip`, `logins_count`) or for
an imported-hash upgrade. A transaction that changes the same user several
times emits one event with the final state.

### Shape

Each event is a CloudEvents 1.0 JSON object as the catalog schema defines:

```json
{
  "specversion": "1.0",
  "type": "user.created",
  "source": "urn:auth0:<tenant domain>",
  "id": "evt_<22 alphanumerics>",
  "time": "2026-11-01T12:34:56.789Z",
  "a0tenant": "<tenant id>",
  "a0stream": "est_<22 alphanumerics>",
  "data": { "object": { … }, "previous_object": { … }, "context": { … } }
}
```

- `a0stream` is set only on stream deliveries, never in the Events API;
  `a0purpose: "test"` only on test events.
- `data.object` is built from an allowlist taken from the catalog schema
  for that type (for users: `user_id`, `email`, `email_verified`, `username`,
  `phone_number`, `phone_verified`, `created_at`, `updated_at`, `identities`,
  `app_metadata`, `user_metadata`, `picture`, `name`, `nickname`,
  `multifactor`, `last_ip`, `last_login`, `logins_count`, `blocked`,
  `given_name`, `family_name`, plus `deleted_at` on delete). Fields outside
  the allowlist never appear, so password hashes, imported hashes and
  upstream provider tokens cannot leak. Identities follow the Management
  API's identity shape without tokens.
- `previous_object` is set on `*.updated` events (full prior object by
  default; E2 may narrow it).
- `context` carries `tenant.id` always and, when the change came from a
  request, `request` (`ip`, `hostname`, `custom_domain`, `method`,
  `user_agent`, `geo: {}`), `client` (`id`, `name`, `metadata`),
  `connection` (`id`, `name`, `strategy`) and `transaction` where the
  catalog defines it. `geo` stays empty: zeroauthy ships no GeoIP data
  (local ruling, as Plan 31's `location_info`).

### Capture and the outbox

Events must not be lost when the change commits, and must not exist when it
rolls back. They are therefore written in the **same store transaction** as
the change, into a per-tenant event table that acts as an outbox. This is
stronger than Plan 31's at-most-once logs, on purpose: event streams drive
data synchronization.

Capture happens in one place. A store decorator in `internal/events` wraps
`store.Store`. Its `Users()`, `Organizations()` and `Connections()` views
intercept the mutating methods and append the event inside the current
`WithTx` (opening one when the caller has none). Request context (client,
connection, request fields) comes from a context value set by the HTTP
layers through `events.WithContext`, falling back to `tenant.id` only. This
covers every path listed in §3 without editing each of the ~30 call sites,
and a call site added later is covered automatically. Plugins see ordinary
repository calls plus the new `AppendEvents` within the same remote
transaction.

Each event gets a store-assigned sequence (monotonic per store) and an
`evt_` ID. Event content is stored once; streams reference it.

### Retention

Events are kept for `events.retention` (deployment configuration, default
7 days, minimum 1 day; local ruling pending E7). An hourly sweep under the
existing leader/lease pattern deletes expired events and their delivery
records in bounded batches. Deleting a tenant deletes its events, streams
and deliveries. Deleting a user keeps the events that name it.

## 4. Event streams API

Routes and scopes (frozen in Task 1 from the OpenAPI document):

| Route | Scope | Success |
| --- | --- | --- |
| `GET /event-streams?from&take` | `read:event_streams` | 200 `{eventStreams, next}` (take default 50, max 100) |
| `POST /event-streams` | `create:event_streams` | 201 |
| `GET /event-streams/{id}` | `read:event_streams` | 200, 404 |
| `PATCH /event-streams/{id}` | `update:event_streams` | 200 |
| `DELETE /event-streams/{id}` | `delete:event_streams` | 204 |
| `POST /event-streams/{id}/test` | `update:event_streams` | 202 with a delivery object |
| `GET /event-streams/{id}/deliveries` | `read:event_streams` or `read:event_deliveries` | 200 `{deliveries, next}` |
| `GET /event-streams/{id}/deliveries/{event_id}` | `read:event_deliveries` | 200, 404 |
| `POST /event-streams/{id}/redeliver` | `update:event_deliveries` | 202, 409 |
| `POST /event-streams/{id}/redeliver/{event_id}` | `update:event_deliveries` | 202, 409 |
| `GET /events` | `read:events` | 200 SSE |

**Stream object:** `id` (`est_` + 22 alphanumerics, 26 characters), `name`
(1–128), `subscriptions` (`[{event_type}]`, at least one on create, each a
catalog type), `destination` (`{type, configuration}`), `status`
(`enabled`/`disabled`, default `enabled`), `created_at`, `updated_at`.

**Destinations:**

| Type | Configuration | Secret (write-only) |
| --- | --- | --- |
| `webhook` | `webhook_endpoint` (`^https://`), `webhook_authorization` `{method: basic, username}` / `{method: bearer}` / `{method: custom_header, header_key}` | `password` / `token` / `header_value` |
| `action` | `action_id`: an Action in this tenant whose supported trigger is `event-stream` | — |
| `eventbridge` | `aws_account_id` (12 digits), `aws_region` (Auth0's enum), read-only `aws_partner_event_source` | — |

Secrets are required on create for their method, encrypted with the master
key, never returned, and kept when a PATCH omits them. Changing the method
requires the new method's secret. PATCH may replace a `webhook` or `action`
destination as the OpenAPI document allows, but never changes the
destination type and never touches `eventbridge` configuration (E6 may
narrow this). Unknown fields, unsubscribable types and malformed values are
400. The 409 cases are a duplicate name and the stream limit:
`events.max_streams`, default 10 per tenant (local ruling pending E6).

`webhook_endpoint` must be HTTPS. Deliveries use Plan 31's guarded dialer:
private, loopback and link-local addresses are refused after DNS
resolution, unless `events.allow_private_networks` (or, for local testing,
`events.allow_insecure_http`) is set. The test environment uses these flags;
production defaults are off.

## 5. Delivery

### Worker

Delivery reuses Plan 31's machinery: a per-stream checkpoint over the event
sequence, a lease (lease-until column plus conditional update), the guarded
HTTP client and the same settle window (events at least 2 s old) so a late
commit is never skipped. A worker leases an enabled stream, reads events
after its checkpoint filtered by subscription, delivers each, and advances
the checkpoint. A stream created now starts at the latest event; it does not
replay history.

Each event gets **four attempts**: the first and three retries after 1 s,
2 s and 4 s. A 2xx is success. A 4xx fails immediately without retry. A
timeout (10 s, local pending E1), connection error or 5xx is retried. After
the last attempt the event is recorded as a **failed delivery** and the
worker moves on; the stream does not block on it. Duplicates are possible
(at-least-once around restarts); ordering is not guaranteed, as Auth0 states.

### Webhook request

`POST webhook_endpoint` with the event JSON as the body,
`Content-Type: application/json` and the configured authorization:
`Authorization: Basic base64(username:password)`, `Authorization: Bearer
token`, or `header_key: header_value`. Any further headers follow E1. No
signature header is sent unless E1 shows one; Auth0 documents only these
authorization methods.

### Action destination

The `event-stream` trigger joins the Actions runtime; it moves out of
`deferred_triggers` in `internal/actionsrules/inventory.json`, where Plan 28
assigned it to this plan. Its handler is
`exports.onExecuteEventStream = async (event, api) => {}` with
`event.message` (the CloudEvent, including `a0stream` and, for tests,
`a0purpose`) and `event.secrets`. `api` provides `api.cache` as documented.
Returning normally is success; throwing is a failure that follows the same
four-attempt schedule. Runs are asynchronous through the Plan 28 durable
job queue, never block the originating request, and write an Action
execution that Plan 31's logs and console already show. `api.message.fail`
appears in Auth0's guide but not in the API object reference; it is
implemented only if Task 1 finds it documented.

### Failure records

A delivery object is `{id, event_stream_id, status: "failed", event_type,
attempts: [{status, timestamp, error_message, duration}], event}`. Only
failed deliveries are listed, as Auth0's status enum (`failed` only) and
guide state; `event` carries the event content. `error_message` is a short
class (`timeout`, `connection_error`, `blocked_address`, `http_4xx: 404`,
`http_5xx: 503`, `action_error: <message masked by the Plan 31 redactor>`);
response bodies are never stored.

`GET /deliveries` filters by `statuses`, `event_types` (comma-separated),
`date_from` (inclusive) and `date_to` (exclusive, RFC 3339, no sub-second
precision), pages with `from`/`take` (default 50, max 100) and returns
`next`. `GET /deliveries/{event_id}` returns one record or 404.

### Redelivery

`POST /redeliver/{event_id}` queues one failed event; `POST /redeliver`
queues every failed event matching the optional `date_from`, `date_to`,
`statuses` and `event_types` body filters and echoes the filters. Both
return 202. 409 when the event is not failed or is already queued. The
worker sends queued redeliveries with the same four-attempt schedule; a
success removes the failure record (pending E3), a new failure updates it.
Redelivery works while a stream is disabled, as Auth0's recovery guide
requires after auto-disable.

### Test events

`POST /test` with `{event_type, data?}` builds an event of that type with
`a0purpose: "test"` and the given `data` (or a catalog example, pending
E4), delivers it immediately with the same rules, and returns 202 with the
delivery object and its attempts. Test events are not written to the
outbox, the Events API or the failure list (local pending E4). Disabled
streams follow E4; the local default is 400.

### Auto-disable

A stream is disabled automatically after **500 consecutive failed events**
or when it holds **5,000 failed deliveries**. Re-enabling with PATCH is 400
while it still holds 5,000 or more failed deliveries; redelivery reduces the
count. Disabled streams receive nothing new; events that occur while
disabled are not delivered later (Auth0: no sending to disabled streams),
so re-enabling resumes at the latest event. The third bullet in Auth0's list
("three consecutive delivery attempt failures") is read as describing a
single event's exhausted attempts, not a stream threshold, until E5 settles
it (local ruling).

## 6. Events API and EventBridge

**`GET /api/v2/events`** (scope `read:events`) answers `text/event-stream`:

```
:connected

event: user.created
id: <offset>
data: {"offset":"<offset>","event":{…CloudEvent without a0stream…}}

event: offset-only
id: <offset>
data: {"offset":"<offset>"}

: heartbeat
```

- `from` (opaque offset, max 1,024 characters) or the `Last-Event-ID`
  header (wins when both are present) resumes after that offset;
  `from_timestamp` (RFC 3339, max 20) starts at events at or after it; `from`
  and `from_timestamp` together are 400. With none, the stream starts at the
  latest events. `event_type` may repeat; unknown types are 400. A malformed
  offset is 400; an offset older than retention is 410.
- The offset encodes the event sequence (base64, opaque to callers). Events
  are sent only once settled (2 s), so a resume never skips one.
- A heartbeat comment every 15 s, an `offset-only` message every 30 s, a
  `retry: 2000` line on connect, and server-side close after 5 minutes so
  clients cycle (local values pending E7). A terminal `event: error` with
  Auth0's error codes (`invalid_cursor`, `cursor_expired`, `timeout`,
  `processing_error`) precedes an abnormal close.
- At most `events.max_connections` concurrent connections per tenant
  (default 4, local pending E7); the next is 403 with Auth0's message.
- The route lifts the server's 30 s write timeout per request
  (`http.ResponseController.SetWriteDeadline`) and is exempt from Plan 31's
  response-capturing Management log middleware (reads write no log event
  anyway).

**EventBridge** needs an Auth0-operated AWS partner source. `eventbridge`
streams are accepted, validated and stored, so Deploy CLI and Terraform
round trips work, but never delivered. They are created `disabled` whatever
the request says; enabling one is 400 and the console says why (local
ruling, matching Plan 31's cloud log streams).

## 7. Storage, console and provisioning

**Storage.** SQL migration `0031_event_streams.sql` in SQLite, PostgreSQL and MySQL adds `tenant_events` (tenant,
seq, event ID, type, time, body), `event_streams` (public fields, sealed
secrets, checkpoint, lease, consecutive and total failures, version) and
`event_deliveries` (stream, event, status, attempts JSON, queued flag,
times), with indexes for the worker, the deliveries filters and the purge.
Migration `0032_event_cursor_watermarks.sql` adds a durable tenant-local highest
purged sequence, including upgrades from an already applied 0031. Memory eviction
and all retention removals update this watermark atomically; SSE expires explicit
cursors only below it, including an entirely purged retained set. Existing purge
history before 0032 is unknown and starts at zero, never inferred from global gaps.
The memory store keeps a bounded ring of 10,000 events per tenant. A
separately negotiated **Events v1** gRPC capability carries the repository;
without it the routes in §4 return 501 `events_unavailable`, no events are
captured, the console shows the section as unavailable, and older plugins
keep working.

**Console.** A live **Event streams** page under Monitoring: list with status
and failed-delivery count; create/edit per destination type with secrets
write-only and an Action picker limited to `event-stream` Actions; enable and
disable; **Send test event** showing the attempts; a failed-deliveries table
with filters, event JSON and redeliver one/all. The Actions editor offers the
`event-stream` trigger. EventBridge forms explain that delivery is not
available. Requests capture the tenant and ignore stale replies after a
tenant switch. All strings go through the catalog.

**Seed and Deploy CLI.** Seed may declare event streams (create-only, secrets
from environment references as existing seed secrets do). The pinned Deploy
CLI's `eventStreams` handler round trips name, subscriptions, destination
and status in YAML and directory formats; secrets are excluded as the tool
excludes them. Events and deliveries are never exported.

## 8. Decisions this spec makes (local rulings)

1. Events are captured in the business transaction (outbox), by a store
   decorator.
2. Event retention is deployment configuration, default 7 days.
3. `user.updated` follows the §3 default until E2.
4. Webhook timeout 10 s; no signature header unless E1 shows one.
5. Test events are delivered synchronously and not stored.
6. The "three consecutive attempts" bullet is per event, not a stream
   threshold.
7. Stream limit 10 per tenant; SSE limit 4 connections per tenant; SSE
   heartbeat 15 s, offset-only 30 s, cycle 5 min.
8. `eventbridge` streams are stored and permanently disabled.
9. `context.request.geo` is an empty object.
10. Private-network webhook targets are refused unless configured.

Each is recorded in D-0058 and the compatibility matrix.

## 9. Acceptance and completion

- **Sync journey (first).** A webhook stream subscribed to `user.created`,
  `user.updated` and `user.deleted` receives, at a local HTTPS receiver with
  bearer authorization, one event each for a browser signup, a Management
  API metadata update and a delete, with the catalog shape (validated
  against the frozen catalog schema) and no password hash or token.
- An `event-stream` Action receives the same events; a throwing Action
  produces failed deliveries that redeliver after the fix, and its
  executions appear in Plan 31's Actions logs.
- `POST /test` returns attempts; a receiver answering 500 gets four
  attempts with 1/2/4 s spacing; 404 gets one. Failed deliveries list,
  filter and page; single and batch redelivery succeed and 409 when not
  failed. 500 consecutive failures disable the stream; re-enable rules hold.
- Organization and `oidc`/`waad` connection events fire from the
  Management API and from invitation acceptance; `samlp`-style strategies
  are absent until they exist; database and social connections emit nothing.
- A rolled-back transaction emits nothing; a committed change survives a
  server restart before delivery and is delivered once or more.
- `GET /events` streams live events, resumes with `Last-Event-ID` and
  `from` without gaps, honours `from_timestamp` and `event_type`, returns
  410 for an expired offset and 403 above the connection limit.
- node-auth0 `eventStreams.*`, the pinned auth0-cli event commands if it has
  them (Task 1 checks; otherwise raw `auth0 api`), and the Deploy CLI round
  trip agree with stored state across memory, SQLite, PostgreSQL and MySQL.
- Events v1 capability matrix: an old plugin keeps working with events
  unavailable.
- Run the focused tests, the full Go race suite, all three SQL drivers, the
  console tests and the affected E2E lanes. Report every actual result and
  every check not run. Plan 19's database hold applies only to Plan 19.

The implementation record maps each condition to evidence or an explicit
limitation. Writing this spec and its plan does not mean anything is
implemented or passing.
