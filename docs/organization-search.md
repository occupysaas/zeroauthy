# Organization search

`GET /api/v2/organizations/search` requires both `read:organizations` and
`read:organizations_summary`. Operator grants use the existing management
policy. Storage plugins must support OrganizationsII and its additive Search
RPC; an unavailable operation fails with 501.

Parameters are `q`, `parser` (`lucene`, the default, or `scim`), `take` (1–100,
default 50), `sort` (`name`, `display_name`, or the default `created_at`), and
`from`. Unknown, repeated, null-like, malformed, and invalid parameters return
400. Empty or omitted `q` matches all organizations in the current tenant.
There are no offsets or totals. The response is `{organizations: [...], next?:
string}`; `next` appears only when more rows exist. Token quotas and speculative
policy filters are not implemented.

Search accepts at most 1000 Unicode characters, five predicates, and expression
or grouping depth 16. Supported fields are case-sensitive `id`, `name`,
`display_name`, `created_at`, and one-level `metadata.<key>`. Comparisons of names,
display names, and metadata strings are also case-sensitive. Metadata presence
includes existing empty strings; missing keys do not match inequality. Numeric
SCIM literals are compared as their string spelling on string fields. Dates
require RFC3339 timestamps; equivalent timezone offsets normalize to UTC.

Examples:

```text
parser=lucene  name:acme* AND metadata.team:*engineering*
parser=lucene  display_name:"Acme Europe"
parser=lucene  created_at:[2026-01-01T00:00:00Z TO 2026-12-31T23:59:59Z]
parser=scim    metadata.team pr and (name eq "acme" or name sw "demo")
parser=scim    created_at ge "2026-01-01T00:00:00Z"
```

Lucene supports field terms, quoted strings with escapes, uppercase AND/OR,
parentheses, leading/trailing wildcards, and inclusive `[]` or exclusive `{}`
date ranges (`*` is an unbounded endpoint). SCIM supports eq/ne/sw/ew/co/pr,
gt/ge/lt/le, lowercase and/or, and parentheses. AND binds more tightly than OR.
ID supports exact equality/inequality and presence; date fields do not support
string wildcards. Suffix and contains literals require at least three Unicode
characters. Regex, fuzzy matching, internal wildcards, arbitrary fields, arrays,
and nested metadata traversal return 400. Quoted wildcards and escaped Lucene
wildcards are literals.

All search ordering is ascending and case-sensitive, with an ascending ID tie
break. The older list endpoint retains its separate `field:1`/`field:-1` sort,
case-folded legacy ordering, offset/checkpoint modes, and response envelopes.
Search compares stored dates at the SQL stores' microsecond precision in every
driver, while preserving the exact inclusivity of finer-precision query bounds.

Cursors encrypt and authenticate the last sort-value/ID tuple under the existing
server key wrapper, binding tenant, normalized query, parser, and sort. The same
configured master key accepts cursors after a server restart. Changing any bound
input or altering a cursor returns 400. A cursor is not a snapshot: concurrent
writes can change membership and ordering in subsequent pages. Local reads are
immediately consistent, a stronger guarantee than upstream eventual consistency.

SQL binds all values and metadata paths, escapes LIKE literals, limits hydrated
organization/connection rows to the requested page (plus one search/checkpoint
lookahead), and batches page summaries. Substring predicates can still scan
rows; no index or latency guarantee is claimed. No external search service is
required.
