# Logs search selector acceptance

- Observation date: 2026-11-01.
- Endpoint: `GET /api/v2/logs`.
- Public endpoint reference: <https://auth0.com/docs/api/management/v2/logs/get-logs>.
- Public query reference: <https://auth0.com/docs/deploy-monitor/logs/log-search-query-syntax>.
- Public token exchange reference: <https://auth0.com/docs/secure/tokens/access-tokens/management-api-access-tokens/get-management-api-access-tokens-for-production>.

## Method and separation

An independent observer used the maintainer-provided observation credentials for
the maintainer's own non-live development tenant, under the authorization recorded
in `CLEAN_ROOM.md`. The observer did not inspect Auth0 tool source or implement
this behavior. The requesting implementer supplied `search_engine=v3` as a
candidate reportedly sent by pinned Auth0 CLI 1.37; these notes independently
confirm acceptance of that candidate on the documented endpoint.

One documented client-credentials exchange at `POST /oauth/token` returned HTTP
200. The observer then made the three bounded, read-only requests below, in order.
Credentials and the resulting access token remained in process memory. Only
response status, JSON structure, and item counts were inspected for reporting;
no event values or response bodies were recorded.

## Observed responses

| Query parameters | HTTP status | Observed JSON structure |
| --- | --- | --- |
| `per_page=1` | 200 | Array containing one object. |
| `per_page=1&search_engine=v3` | 200 | Array containing one object. |
| `per_page=1&search_engine=v3&q=type:s&include_totals=true` | 200 | Object with numeric `length`, `limit`, `start`, and `total` fields, plus a `logs` array containing one object. |

The endpoint accepted `search_engine=v3` both with bounded pagination alone and
with a simple `q` filter and totals envelope. This observation establishes
acceptance of the supplied selector value in these requests. It does not establish
whether the selector is ignored, which search implementation it selects, whether
results differ without it, or how other selector values behave. Event contents
were not compared, and filter semantics were not independently verified.
