# Searching users

The `q` parameter of `GET /api/v2/users` and the console's search box on the
Users page take the same query language, Auth0's "v3" user search syntax.
This guide describes what zeroauthy accepts. The parser is `internal/usersearch`
and its tests are the final word; the choices Auth0 does not document are in
decision D-0043 of [compat/decisions.md](compat/decisions.md).

`search_engine` may be left out, or be `v2` or `v3`; all mean v3. `v1` is
refused with `400 operation_not_supported`; any other value is
`400 invalid_query_string`.

```bash
curl -G "https://login.acme.example/api/v2/users" \
  -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'q=email_verified:true AND NOT blocked:true' \
  --data-urlencode 'sort=created_at:-1' -d per_page=20 -d include_totals=true
```

## Terms

A term is a field, a colon and a value: `name:"Ada Lovelace"`, `blocked:true`.
Quote a value that has spaces or other punctuation; inside quotes, `\"` is a
quote and `\\` a backslash. Outside quotes, escape `|` and the like with a
backslash (`user_id:auth0\|abc123`; `user_id:"auth0|abc123"` is the same).

Combine terms with `AND`, `OR` and `NOT` (upper case), or write `-term` or
`!term` for `NOT`. Group with parentheses. Two terms written next to each
other, without an operator, are joined with `OR`. A group can follow a field:
`email:(ada@example.com OR grace@example.com)`.

`*` on its own matches every user.

## Fields you can search

| Field | Kind | Notes |
|---|---|---|
| `user_id`, `email`, `name`, `given_name`, `family_name`, `nickname`, `username`, `phone_number`, `last_ip` | text | |
| `email_verified`, `phone_verified`, `blocked` | boolean | `true`, in any case, is true; any other value is false |
| `logins_count` | number | A value that is not a number counts as 0 |
| `created_at`, `updated_at`, `last_login` | date | `2026-10-19` or `2026-10-19T21:22:30` |
| `identities.connection`, `identities.provider`, `identities.user_id` | text | |
| `app_metadata.<path>`, `user_metadata.<path>` | any | Path segments are joined with dots: `app_metadata.billing.plan` |

An unknown field is `400` with `invalid query: field 'x' is not searchable`.
The metadata fields need a key: `app_metadata:pro` is
`invalid query: operator 'equals' requires a key on field 'app_metadata'`.

## Case

- Text on the root fields and on `identities.*` is matched **ignoring case**:
  `email:ADA@Example.com` finds `ada@example.com`.
- Metadata values are matched **exactly, with case**: `app_metadata.plan:Pro`
  does not find `pro`.
- A date term with only a day, `created_at:2026-10-19`, means the whole day in
  UTC.
- Case folding in PostgreSQL needs a UTF-8 locale; see the last section.

## Words without a field

A bare word, `ada` or `"ada lovelace"`, is looked for in `name`, `given_name`,
`family_name`, `nickname` and in the email's local part (before the `@`) and
domain. An address works too: `ada@example.com`. Two bare words are `OR`.
`NOT ada` leaves out every user that matches the word anywhere.

## Wildcards

A `*` in an unquoted root text value stands for any run of characters, at the
start, the end or both: `email:*@example.com`, `name:Ad*`, `family_name:*vela*`.
`email:*` means "has an email" (the same as `_exists_:email`). A bare word with
a `*` is a wildcard over the same fields as above.

To match a literal star, quote the value (`name:"a*"`) or escape it (`a\*`).

Wildcards are not allowed on numbers, dates, `identities.*` or metadata:
`invalid query: operator 'wildcard' is not supported on field 'user_metadata.color'`.

## Ranges

Only `logins_count` and the three date fields take ranges. Square brackets
include an end, braces exclude it, and `*` leaves an end open:

```
logins_count:[1 TO 5]
logins_count:{1 TO 5]
last_login:[2026-01-01 TO *]
created_at:>=2026-10-01
updated_at:<2026-10-19
```

`>`, `>=`, `<` and `<=` also work. A range on any other field, metadata
included, is refused: `invalid query: operator 'greater or equal' is not
supported on field 'email'` (the operator named is the one the range starts
with).

## Metadata

The type of the value in the query decides how it is compared:

| Query | Matches |
|---|---|
| `app_metadata.tier:2` | the number 2 |
| `app_metadata.tier:"2"` | the string `"2"` |
| `user_metadata.ok:true` | the boolean true (lower case only) |
| `user_metadata.ok:"true"` or `TRUE` | the string |
| `app_metadata.plan:pro` | the string `pro` |

A key path goes through nested objects (`app_metadata.obj.k:v`), not through
arrays. `NOT` on metadata is a plain negation: users without the key match.

## Existence

`_exists_:phone_number` finds users that have a phone number, and
`_exists_:app_metadata.plan` those with that metadata key. `_exists_` on a
boolean, number or date field (`blocked`, `email_verified`, `logins_count`,
`created_at`, …) is true for every user.

## NOT and users without the field

`NOT` on a term, a wildcard or a group that all concern one root text field
(`user_id`, `email`, `name`, `given_name`, `family_name`, `nickname`,
`username`, `phone_number`, `last_ip`) also drops users that do not have the
field: `NOT family_name:Smith` and `NOT email:*@example.com` leave out users
without a family name or an email as well as the matches. Everywhere else
`NOT` is a plain negation, so users without the field are included: booleans,
numbers, dates, `identities.*`, metadata, groups that mix several fields, and
bare words (which span several fields).

## Sorting and paging

`sort=field:1` is ascending and `field:-1` descending, for the root fields in
the table above (`email`, `created_at`, `last_login`, `logins_count`, …).
Metadata, `identities.*` and unknown fields are ignored. Anything not of the
form `field:1` or `field:-1` is `400 invalid_query_string`. Without `sort`,
users are ordered by `last_login`, newest first, and users who never signed in
come last.

Paging is `page` (from 0) and `per_page` (1 to 100, default 50). Only the
first 1000 results can be reached: when `(page + 1) × per_page` is above 1000
the request is `400 invalid_paging`. Narrow the query to reach the rest.
`include_totals=true` returns `{start, limit, length, total, users}`.

Search sees a write immediately; there is no delay before a new user is found.

## Errors

Search errors are `400` without an `errorCode`, and their messages begin
`invalid query: `. A malformed query is mostly `invalid query: undefined`.
Two are more specific:

- A dangling `AND` (`name:a AND`, or `AND name:a`):
  `invalid query: 'AND' requires at least one operand on each side`.
- The field and operator messages above.

## PostgreSQL and Unicode

On PostgreSQL, ignoring case for accented and other non-ASCII letters depends
on the database's `LC_CTYPE`. Create the database with a UTF-8 one (for example
`C.UTF-8` or `en_US.UTF-8`). With any other, search and sort fold ASCII
letters only, and zeroauthy logs a warning at startup. SQLite and the memory
driver fold Unicode letters; MySQL uses its `utf8mb4` collation.
