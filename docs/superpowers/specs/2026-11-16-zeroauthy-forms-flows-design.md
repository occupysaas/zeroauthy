# Plan 38b — Forms and Flows (and `api.prompt.render`)

**Date:** 2026-11-16. **Status:** design; not implemented; console scope
(§9.1) and vendor integrations (§9.2) need maintainer rulings.

**Roadmap entry:** [management roadmap, Plan 38](2026-10-19-zeroauthy-management-roadmap-design.md)
("Forms and Flows: `/api/v2/forms`, `/api/v2/flows`,
`/flows/{id}/executions`, `/flows/vault/connections`; `api.prompt.render`
in Actions … a visual flow builder is a large console project");
[parallel paths](2026-11-13-zeroauthy-parallel-paths-design.md) item **A2**
(track A, after A1 = Plan 40). Read the [clean-room policy](../../../CLEAN_ROOM.md),
`AGENTS.md`, the [Plan 40 spec](2026-11-16-zeroauthy-actions-iii-design.md),
D-0053/D-0054, the [branding guide](../../branding.md) (hosted page
security) and the memory note on the Actions tenant trust domain.

## 1. Outcome and scope

An operator builds a **form** (fields, blocks, widgets, steps, flow
nodes, routers) and **flows** (ordered actions: conditions, variables,
HTTP calls, user updates, OTP, JWT, email…). A post-login (or
password-reset-post-challenge) Action calls `api.prompt.render(formId)`;
zeroauthy renders the form inside Universal Login, runs its flows on
submit, stores collected values where the flows say, and resumes the
Action with `onContinuePostLogin` seeing `event.prompt.fields`.

**Rule:** strict 1:1 with Auth0's documented behaviour (memory: Auth0 parity
first), from the Management OpenAPI (the form/flow JSON is Auth0's
format, so Deploy CLI and exported JSON work unchanged). Local rulings
**LR38b-n**, observation points **FF-1…n** in **D-0200** (A2 block
D-0200–0209).

### In scope — Phase 1 (core)

1. **Forms API** `GET/POST /api/v2/forms`, `GET/PATCH/DELETE /api/v2/forms/{id}`:
   `name`, `messages`, `languages`, `translations`, `nodes`, `start`,
   `ending`, `style`; node types `STEP`, `FLOW`, `ROUTER` (FF-1 exact
   names); components: blocks (`DIVIDER`, `HTML`, `IMAGE`, `JUMP_BUTTON`,
   `NEXT_BUTTON`, `PREVIOUS_BUTTON`, `RESEND_BUTTON`, `RICH_TEXT` — the
   OpenAPI list read at build time), fields (`BOOLEAN`, `CARDS`, `CHOICE`,
   `CUSTOM`, `DATE`, `DROPDOWN`, `EMAIL`, `FILE`, `LEGAL`, `NUMBER`,
   `PASSWORD`, `SOCIAL`, `TEL`, `TEXT`, `URL`), widgets (`RECAPTCHA` via
   Plan 19 CAPTCHA providers).
2. **Flows API** `GET/POST /api/v2/flows`, `GET/PATCH/DELETE /api/v2/flows/{id}`
   (`name`, `actions[]`), executions `GET /flows/{id}/executions`,
   `GET/DELETE /flows/{id}/executions/{execution_id}` (`id`, `trace_id`,
   `journey_id`, `status`, `debug`, timestamps).
3. **Vault connections** `GET/POST /flows/vault/connections`,
   `GET/PATCH/DELETE /flows/vault/connections/{id}` for the three core
   apps only (LR38b-1): `HTTP` (bearer, basic, API key), `JWT` (signing
   secrets/keys) and `AUTH0` (Management API client credentials).
4. **Core flow actions:** `FLOW` (`BOOLEAN_CONDITION`, `DELAY_FLOW`,
   `DO_NOTHING`, `ERROR_MESSAGE`, `MAP_VALUE`, `RETURN_JSON`, `STORE_VARS`),
   `JSON` (`CREATE_JSON`, `PARSE_JSON`, `SERIALIZE_JSON`), `JWT`
   (`DECODE_JWT`, `SIGN_JWT`, `VERIFY_JWT`), `OTP` (`GENERATE_CODE`,
   `VERIFY_CODE`), `EMAIL` (`VERIFY_EMAIL`: syntax/MX-free checks as
   documented, FF-2), `HTTP` (`SEND_REQUEST` through the outbound policy),
   `AUTH0` (`CREATE_USER`, `GET_USER`, `UPDATE_USER`, `SEND_EMAIL`,
   `SEND_SMS`, `SEND_REQUEST` to the tenant's own Management API,
   `MAKE_CALL` via Plan 34 voice).
5. **Expressions:** Auth0's `{{ … }}` template references (`fields.*`,
   `vars.*`, `actions.<id>.*`, `user.*`, `context.*`) and the documented
   helper functions (FF-3: the function list read at build time), in a
   pure-Go evaluator (no JavaScript).
6. **Runtime:** `api.prompt.render(formId, {vars, fields})` in post-login
   and password-reset-post-challenge (fail closed since Plan 28) →
   hosted form page `/u/forms/<form id>?state=…` (FF-4 for Auth0's path)
   with steps, validation, translations, theming from Plan 22; FLOW nodes
   run server-side; ROUTER branches; ending resumes the Action
   (`event.prompt.fields`, `event.prompt.vars`, A1's `event.prompt`
   member).
7. **Console:** forms and flows as structured JSON editors with schema
   validation, a form preview (Plan 22 sandbox), execution list with debug
   (decision §9.1 on a visual builder).
8. Seed, Deploy CLI (`forms`, `flows`, `flowVaultConnections` handlers in
   9.1.0), docs, tests.

### Phase 2 (vendor integrations, ruling §9.2)

The remaining OpenAPI flow actions and vault apps (ActiveCampaign,
Airtable, BigQuery, Clearbit, DocuSign, Google Sheets, HubSpot, Mailchimp,
Mailjet, Pipedrive, Salesforce, SendGrid, Slack, Stripe, Telegram, Twilio,
WhatsApp, Zapier): accepted and stored by the API from Phase 1 (Deploy CLI
round trips keep working), executed in Phase 2 per vendor, each against
the vendor's public API. Until then such an action fails the execution
with a clear "integration not available" error (LR38b-2).

### Not in scope

- `FormFieldPayment` (Stripe Elements in the page) and
  `FormWidgetGMapsAddress` (Google Maps script): need third-party scripts
  in hosted pages (ACUL-style boundary, H1); stored, rendered as
  "unavailable" (LR38b-3).
- `FormWidgetAuth0VerifiableCredentials`: needs the verifiable credentials
  runtime (M1 decision: not planned).

### Anti-goals

- **Tenant code in the browser.** Form `HTML` blocks are sanitized with
  the Plan 22 HTML subset; no scripts, styles limited to the form `style`
  object.
- **SSRF and secret leakage in flows.** `HTTP` actions use the outbound
  policy; vault secrets are injected server-side and never appear in
  execution debug output, logs or form context.
- **Unbounded execution.** Per execution: 50 actions, 30 s wall time,
  `DELAY_FLOW` capped (FF-5), 1 MiB of variables; executions retained 7
  days (FF-6).
- **Privilege via `AUTH0` actions.** They act only on the tenant of the
  flow, with the scopes of the vault connection's client grant.
- **Secrets in logs** (memory: secrets never in logs): field values of
  `PASSWORD` fields, OTP codes, vault secrets never logged; debug output
  scrubs them.

## 2. Evidence

- Management OpenAPI (read 2026-11-16): the forms, flows, executions and
  vault-connections operations; `CreateFormRequestContent` (`name`,
  `messages`, `languages`, `translations`, `nodes`, `start`, `ending`,
  `style`); 33 `FormBlock*`/`FormField*`/`FormWidget*` schemas;
  `CreateFlowRequestContent` (`name`, `actions`); 90 `FlowAction*`
  schemas; 21 `FlowsVaultConnectionAppId*Enum`; `GetFlowExecutionResponseContent`.
- Auth0 Forms and Flows docs (`/docs/customize/forms`, `/docs/customize/forms/flows`,
  the `api.prompt.render` reference, the expressions/variables pages) —
  read at build time for node semantics and helper functions (FF-1…FF-4).
- Post-login API object (`api.prompt.render(promptId, promptOptions)`).
- Deploy CLI 9.1.0 handlers `forms`, `flows`, `flowVaultConnections`.

## 3. Storage

- `forms(tenant_id, id, name, definition JSON, created_at, updated_at)`,
  `flows(… actions JSON)`, `flow_vault_connections(… app_id, name,
  setup_sealed, fingerprint, ready)`, `flow_executions(tenant_id, id,
  flow_id, status, trace_id, journey_id, debug JSON scrubbed, timestamps)`,
  form sessions in the authorization transaction (bounded); one migration
  numbered at merge; gRPC capability `forms_flows.v1`.
- IDs: `ap_` forms, `af_` flows, `ac_` vault connections, `afe_`
  executions (FF-7).

## 4. Tests

- Schema validation per component and action (OpenAPI-derived fixtures).
- Expression evaluator table + fuzz.
- Flow engine: each core action with fixtures (HTTP server, mail sink,
  phone fixture), limits, error paths, debug scrubbing.
- Rendering: each field/block, validation, translations, steps, routers,
  CAPTCHA widget, HTML sanitizer.
- `api.prompt.render` round trip in post-login (continue with fields) and
  reset-password-post-challenge.
- Deploy CLI four-cell round trip (forms, flows, vault connections with
  secrets reinjected).
- E2E `make e2e-forms`: Playwright through a progressive-profiling form
  that runs a flow updating `user_metadata`, then completes login.

## 5. Local rulings and observation points

| ID | Ruling |
|---|---|
| LR38b-1 | Phase 1 vault apps: `HTTP`, `JWT`, `AUTH0`. |
| LR38b-2 | Vendor actions stored, failing at run time until Phase 2. |
| LR38b-3 | Payment and Maps widgets stored, rendered unavailable. |

Observe later: **FF-1** node type names; **FF-2** `VERIFY_EMAIL` checks;
**FF-3** expression helper functions; **FF-4** form page path; **FF-5**
delay cap; **FF-6** execution retention; **FF-7** ID prefixes.

## 6. Decisions needed from the maintainer

1. **Console:** structured JSON editors with preview (proposed for Phase 1)
   vs a visual drag-and-drop builder (a large separate console project).
2. **Vendor integrations:** which vendors in Phase 2, in what order, and
   who provides test accounts.
