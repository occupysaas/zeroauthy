# Event streams

Event streams synchronize tenant changes with an HTTPS webhook or an
`event-stream` Action. These are CloudEvents, separate from the operational
[logs](logs.md). The console's **Monitoring → Event streams** page manages
subscriptions, tests and failed deliveries. Management API routes are listed in
[management-api.md](management-api.md).

## Events and privacy

The frozen Auth0 event catalog 0.13.6 in `internal/eventrules` defines 25 event
types. zeroauthy emits user created/updated/deleted; organization CRUD, membership,
member-role and enabled-connection changes; and enterprise connection CRUD for
supported catalog strategies (`oidc` and `waad` today). Database and social
connection CRUD produces no connection events. Group and organization group-role
events await Plan 38; synthetic tests can use all catalog types.

Every event includes CloudEvents 1.0 `specversion`, `id` (`evt_` plus 22
alphanumeric characters), `type`, `source`, `time`, `a0tenant` and `data`.
`data.object` contains the current public resource, `previous_object` carries the
full prior resource for real updated events, and `context` carries tenant and
available request/client/connection details. Request geo is empty. Client metadata
is empty until client metadata storage exists. Stream deliveries add `a0stream`;
synthetic tests add `a0purpose: "test"`. SSE events have no `a0stream`.

Resource and nested identity fields use explicit allowlists. Password hashes,
imported hashes and provider tokens are excluded. Customer `app_metadata` and
`user_metadata` remain customer data, including keys such as `password`; avoid
putting credentials there. Webhook authorization secrets are encrypted at rest,
write-only in the API and absent from exported public configuration.

A store decorator captures the event in the same transaction as the resource
change. Rollbacks produce no event. Multiple changes to the same resource inside
one transaction collapse to its final state. User updates include Management API,
metadata, block, password, verification and identity changes; login counters and
password-hash upgrades do not produce updates. Observable cascade changes also
produce events. Dormant organization role assignments retained after membership
removal do not produce separate role-deleted events.

## Management API scopes

| Operation | Scope |
| --- | --- |
| List/get streams | `read:event_streams` |
| Create / update or test / delete | `create:event_streams` / `update:event_streams` / `delete:event_streams` |
| List deliveries | `read:event_streams` or `read:event_deliveries` |
| Get one delivery | `read:event_deliveries` |
| Redeliver one/all | `update:event_deliveries` |
| Read SSE | `read:events` |

## Webhooks and delivery

Create a stream with subscriptions such as `[{"event_type":"user.created"}]`
and a `webhook` destination:

```json
{
  "name": "User synchronization",
  "subscriptions": [{"event_type":"user.created"}],
  "destination": {
    "type": "webhook",
    "configuration": {
      "webhook_endpoint": "https://receiver.example/events",
      "webhook_authorization": {"method":"bearer", "token":"<secret>"}
    }
  }
}
```

Authorization supports `basic` (`username`, write-only `password`), `bearer`
(write-only `token`) and `custom_header` (`header_key`, write-only `header_value`).
PATCH preserves an omitted credential. Changing the method requires its new
credential. HTTPS URLs can include ordinary query strings; userinfo, fragments,
unsafe header names and redirects are refused. Private/loopback/link-local targets
are refused by default. `events.allow_private_networks` permits local targets;
`events.allow_insecure_http` is a separate test/development escape hatch.

The worker reads committed events after a two-second settle window. A new stream
starts at the latest event rather than replaying history. Delivery is at least
once: consumers should deduplicate by event ID and tolerate unordered delivery.
A response in the 2xx range succeeds; a 4xx fails immediately. Connection errors,
timeouts and 5xx responses receive three retries after 1, 2 and 4 seconds
(cumulative starts around 0, 1, 3 and 7 seconds for immediate responses). Each
attempt has a ten-second budget. A failed event does not block later events.
No webhook signature is added; authenticate with the configured authorization.

Only failed deliveries persist in the delivery list. Attempts contain status,
timestamp, duration and a short diagnostic class. Receiver response bodies are
never stored. Filter by event type, failed status and whole-second UTC date range
(inclusive start, exclusive end); paginate with `from` and `take` (default 50,
maximum 100). Redeliver a single event or every matching failed event. A successful
redelivery removes the failure record. Redelivery works while disabled. A 409
means the event is no longer failed or is already queued.

Streams auto-disable after 500 consecutive failed events or 5,000 retained failed
deliveries. Re-enabling fails until the retained count drops below 5,000. Events
created while disabled are not replayed when re-enabled. `total_failures` is a
read-only local extension reporting the current failed-delivery count.

**Send test event** delivers synchronously and returns attempts. Tests use supplied
catalog-valid data or a catalog example, work for enabled streams and never enter
the outbox, SSE or failed-delivery list. Synthetic updated data may omit
`previous_object`; real capture always supplies it.

## Actions

Choose a deployed Action with supported trigger `event-stream` (`v1`, a local
version default). Its handler receives the CloudEvent in `event.message` and
configured Action secrets in `event.secrets`:

```js
exports.onExecuteEventStream = async (event, api) => {
  await synchronize(event.message);
  api.cache.set('last-event', event.message.id);
};
```

Returning succeeds; throwing fails and follows the
same retries. `api.cache` persists across executions. Delivery runs through the
durable Actions queue and records executions visible in Actions logs. Diagnostic
secrets are masked. An isolated Node process per attempt is killed and reaped on
completion or timeout; per-tenant execution is serialized with a bounded pool.
Process globals do not persist. A request already sent by Action code cannot be
recalled. See [Actions](actions.md).

## Events API

`GET /api/v2/events` requires `read:events` and returns `text/event-stream`.
Each named event has `id: <opaque offset>` and JSON data
`{"offset":"…","event":{…}}`. Resume after an offset with `Last-Event-ID` or
`from`; the header wins. `from_timestamp` starts at a whole-second UTC timestamp
and cannot be combined with `from`. Repeat `event_type` to filter types. Do not
decode or construct offsets.

The stream sends `retry: 2000`, connected/heartbeat comments (15 seconds) and an
`offset-only` message every 30 seconds. Preserve offsets from both event and
`offset-only` messages. Connections cycle after five minutes. Invalid offsets
return 400, expired retained offsets 410 and excess connections 403. Terminal
`error` events carry the documented error codes. The default connection limit is
four per tenant. Retention and memory-ring eviction atomically record the highest
removed sequence for that tenant. A cursor before this watermark returns 410,
even when no events remain; gaps allocated to other tenants do not expire it.
Timestamp reads replay available retained events, including lower-sequence rows
when a newer sequence was already purged out of event-time order. Resuming a row
offset before that known purge gap can return 410; restart with a timestamp to
replay available history. Offset-only frames wait until that gap is crossed.

Synchronous test deliveries have a finite 60-second request and response budget,
covering the four ten-second attempts and 1/2/4-second retry delays. Client
cancellation stops delivery and interrupts blocked response writes. Ordinary
Management routes retain their existing server timeouts and response logging.

## Storage, provisioning and local differences

Memory, SQLite, PostgreSQL, MySQL and Events-v1 gRPC stores support events.
SQL requires migrations `0031_event_streams.sql` and
`0032_event_cursor_watermarks.sql`; 0032 upgrades databases already at version 31.
Pre-upgrade purge history cannot be inferred from global sequence gaps: the new
watermark starts at zero, so unknown earlier gaps may be accepted until a newly
recorded removal proves expiry. New purges are durable across reopening. Memory
keeps at most 10,000 events per tenant; configured retention defaults to seven days
(minimum one day), with hourly bounded purges. Tenant deletion removes events and
deliveries; user deletion preserves its event history. Older plugins without the
separate Events capability continue working and event routes return 501
`events_unavailable`. An Events-v1 plugin that lacks the additive
`PurgedEventSeq` RPC also fails closed with 501 on SSE instead of guessing history.

Seed is create-only and reads credentials from environment references. Startup,
the seed command and Management API creation use `events.max_streams` (default 10).
Reapplying existing streams preserves them even after lowering the limit, without
resolving their secret environment references again. The pinned
Deploy CLI exports/imports public `eventStreams` in YAML and directory format;
credentials must be supplied again on the target. Events and deliveries are never
exported. See [the implementation record](superpowers/2026-11-01-plan-32-implementation-record.md)
for actual acceptance coverage, completed validation and remaining limitations.

`eventbridge` configuration is accepted for tool round trips but always disabled:
zeroauthy cannot create Auth0's AWS partner source. Its partner-source string is a
local deterministic placeholder. Enabling or updating EventBridge configuration
is rejected.

[D-0058](compat/decisions.md) records local choices where public documentation
leaves behavior open: retention, update boundaries, timeouts, retry interpretation,
tests, quotas, SSE cadence, EventBridge and outbound guard. Separate Auth0 observer
evidence E1–E8 remains unavailable; local testing makes no upstream parity claim.
