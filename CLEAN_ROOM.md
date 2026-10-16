# Clean-Room Policy

zeroauthy is an independent, clean-room implementation of an identity server
that is wire-compatible with Auth0. It is not affiliated with, endorsed by, or
derived from Auth0 or Okta. Every contribution must follow this policy.

## Permitted sources

- Auth0's **public documentation** (https://auth0.com/docs), including the
  public API reference.
- Auth0's **public changelog** (https://auth0.com/changelog), used to track
  new and changed features for parity planning. Entries are summarized in our
  own words in `docs/compat/changelog-review.md`, never copied.
- The Apache-2.0 licensed OpenAPI description at
  https://github.com/aminya/auth0-openapi (see `NOTICE`).
- IETF RFCs, OpenID Foundation specifications, and other open standards.
- Auth0's **open-source SDKs and tools** (for example the SDKs on
  https://github.com/auth0 and auth0-cli), under their open-source licenses
  (MIT, Apache-2.0):
  - as **test clients**, run against zeroauthy and against the maintainer's
    own tenant;
  - as a **source**: their source code may be read and studied (see
    "Open-source Auth0 code" below).
- **Firewalled Management API observation** (see below).
- **Behavior testing against the maintainer's own tenant** (see below).

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

## Behavior testing against the maintainer's own tenant

The maintainer has authorized (2026-10-16) observing and testing Auth0's
behavior on a tenant they own, so zeroauthy can be compared with it. This
extends the observation rules above to the documented Authentication API
and to Auth0's open-source tools such as auth0-cli
(https://github.com/auth0/auth0-cli, MIT):

- **Scope:** documented endpoints only (Authentication API and Management
  API), on a tenant the maintainer owns, with normal credentials. Run the
  same tools and requests against Auth0 and against zeroauthy.
  No other people's tenants, no undocumented or internal endpoints, and no
  load or fuzz testing.
- **Tools:** Auth0's SDKs and auth0-cli may be run through their commands
  and options, and their source may be read under "Open-source Auth0 code"
  below.
- **Results:** record behavior as observation notes in
  `docs/compat/observations/`, or as test assertions that encode facts:
  status codes, field names and types, error codes, redirects and
  parameters. The "notes, not copies" rule above applies: no verbatim error
  messages or descriptions longer than a short identifier, and no
  credentials, tenant identifiers, tokens, or personal data in the
  repository.
- **Still prohibited:** capturing hosted pages or the dashboard
  (screenshots, DOM, assets, copy), as listed below.

## Open-source Auth0 code

The maintainer has authorized (2026-10-16) reading and studying the source
of Auth0's open-source SDKs and tools, such as auth0-cli, because their
licenses (MIT, Apache-2.0) permit it. This covers only code Auth0 publishes
under an open-source license; Auth0's server software and hosted pages
remain off limits (see below).

- **Confirm before building:** a behavior learned only from SDK or tool
  code, such as an undocumented endpoint, parameter or field, is confirmed in
  the public documentation or by behavior testing against the maintainer's
  own tenant before zeroauthy implements it. Until then, it is at most a
  note in `docs/compat/decisions.md`.
- **Write our own code:** prefer original code. If code is copied or closely
  adapted, keep its copyright and license notice, add it to `NOTICE`, and
  make sure the license is compatible with zeroauthy's Apache-2.0 license.
- **Record provenance:** when SDK or tool code informed a behavior, name the
  repository, file and version (tag or commit) in the operation's
  `x-source` or in the decision log.

## Prohibited

- Decompiling, disassembling, or otherwise inspecting Auth0 server software,
  hosted pages, or other proprietary assets.
- Probing or scraping live Auth0 tenants, except for firewalled Management
  API observation and behavior testing against the maintainer's own tenant,
  as described above.
- Reverse engineering Auth0 software that is not published under an
  open-source license (for example binaries or obfuscated code without a
  source release).
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
  the public URL(s) it was derived from, including the repository, file and
  version of any open-source Auth0 code that informed it.
- When public sources leave behavior unspecified, resolve it using
  RFC/OpenID semantics and log the decision in `docs/compat/decisions.md`.
- Known differences from Auth0 are listed in `docs/compat/matrix.md`.

## Contributor attestation

By opening a pull request you confirm that your contribution was produced
under this policy. The pull request template contains the checklist.
