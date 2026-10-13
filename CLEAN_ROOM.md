# Clean-Room Policy

zeroauthy is an independent, clean-room implementation of an identity server
that is wire-compatible with Auth0. It is not affiliated with, endorsed by, or
derived from Auth0 or Okta. Every contribution must follow this policy.

## Permitted sources

- Auth0's **public documentation** (https://auth0.com/docs), including the
  public API reference.
- The Apache-2.0 licensed OpenAPI description at
  https://github.com/aminya/auth0-openapi (see `NOTICE`).
- IETF RFCs, OpenID Foundation specifications, and other open standards.
- Auth0's **open-source SDKs**, used only as **black-box test clients**:
  we run them against zeroauthy and observe the requests they send to *our*
  server.
- **Firewalled Management API observation** (see below).

## Firewalled Management API observation

Observing the JSON behavior of Auth0's Management API is permitted only under
these conditions:

- **Scope:** only documented Management API endpoints, called against a
  tenant the observer owns, using normal API credentials. No dashboard UI
  capture, no hosted login pages, no undocumented or internal endpoints, no
  other people's tenants, and no load or fuzz testing.
- **Separate roles:** the *observer* runs the requests and writes behavioral
  notes. The *implementer* works only from public documentation and those
  notes. One person (or agent session) does not do both for the same area.
- **Notes, not copies:** observation notes describe behavior in the
  observer's own words: status codes, field names and types, defaults,
  validation rules, pagination, error codes. They must not include verbatim
  error messages or descriptions longer than a short identifier, and must not
  include any credentials, tenant identifiers, or personal data.
- **Location:** notes live in `docs/compat/observations/`, one file per
  endpoint group, each with date, endpoint, and the doc URL it complements.
- **Risk acceptance:** Auth0/Okta terms may restrict reverse engineering or
  competitive use of the service. The project maintainer has reviewed this
  and accepted the risk for firewalled API observation. Contributors must not
  perform observation unless the maintainer has authorized them to.

## Prohibited

- Decompiling, disassembling, or otherwise inspecting Auth0 server software,
  hosted pages, or other proprietary assets.
- Probing or scraping live Auth0 tenants, except for firewalled Management
  API observation as described above.
- Capturing the Auth0 dashboard or hosted pages (screenshots, DOM, assets,
  copy).
- Copying Auth0 UI templates, stylesheets, images, or product copy. All
  templates and text in this repository are original.
- Using Auth0 trademarks beyond nominative statements such as
  "Auth0-compatible".
- Contributing code or knowledge obtained under an Auth0/Okta NDA or from
  employment there that is not public.

## Provenance

- Every operation in `api/*.yaml` carries an `x-source` extension listing
  the public URL(s) it was derived from.
- When public sources leave behavior unspecified, resolve it using
  RFC/OpenID semantics and log the decision in `docs/compat/decisions.md`.
- Known differences from Auth0 are listed in `docs/compat/matrix.md`.

## Contributor attestation

By opening a pull request you confirm that your contribution was produced
under this policy. The pull request template contains the checklist.
