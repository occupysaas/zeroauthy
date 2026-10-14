# zeroauthy — Design: Internationalization of Hosted Pages (Plan 4)

- **Status:** Draft, awaiting review
- **Date:** 2026-10-14
- **Scope:** hosted pages of sub-project 1. This work runs before milestone 6 so that later screens are built localized from the start.

## 1. Goal

Hosted pages render in the language the application or browser asks for, if the tenant enables it. Operators customize text per tenant and language in the same shape Auth0 documents, so that existing custom-text configuration and the future Management API endpoint work unchanged. Plan 4 ships only English text; the system lets contributors add languages without code changes.

**Success:** an unmodified auth0-spa-js app passing `authorizationParams: { ui_locales: 'fr' }`, against a tenant with French custom text, sees a French login page with `lang="fr"` and completes login. Any key that has no French text shows in English.

## 2. Sources (clean room)

- https://auth0.com/docs/customize/internationalization-and-localization/universal-login-internationalization: `enabled_locales` (the first entry is the default), `ui_locales` (its first entry must be enabled), the `Accept-Language` fallback, and RTL via `dir`.
- https://auth0.com/docs/customize/login-pages/universal-login/customize-text-elements: custom text keyed prompt → screen → key → language, and `${variable}` placeholders.
- BCP 47 (RFC 5646) for language tags, and RFC 9110 §12.5.4 for `Accept-Language`.

Only **identifiers** are taken from Auth0: prompt, screen and key names, and the variable syntax. All default wording is original.

## 3. Language selection

Selection happens once per render. Pages with a login transaction use the `ui_locales` value stored in that transaction. `/oidc/logout` uses its own `ui_locales` parameter. Other pages have no `ui_locales`.

1. **`ui_locales`:** only its first entry is considered. It is used if the tenant enables it.
2. **`Accept-Language`:** entries are taken in q-value order. The first one the tenant enables is used. Matching uses `golang.org/x/text/language`.
3. Otherwise, the tenant default: the first entry of `enabled_locales`. If `enabled_locales` is unset, it is treated as `[en]`.

`/authorize` adds `ui_locales` to the parameters it keeps in the transaction. The page sets `<html lang="…">`, and sets `dir="rtl"` for a fixed list of RTL base languages (ar, he, fa, ur). The CSS uses logical properties.

## 4. Text lookup

A key is `prompt.screen.key`. The lookup for the chosen language L tries these in order:

1. the tenant's custom text for L;
2. the built-in catalog for L;
3. the built-in catalog for L's base language, e.g. `fr-CA` → `fr`;
4. the built-in English text.

A page therefore never shows a raw key or empty text. Variables `${companyName}` (the tenant's friendly name) and `${clientName}` (the application name) are substituted after lookup. All text is HTML-escaped by the templates.

## 5. Catalogs

`internal/i18n/locales/<tag>.json` files are embedded in the binary. Their shape matches custom text: `{ "<prompt>": { "<screen>": { "<key>": "text" } } }`. Plan 4 ships `en.json` only.

Key mapping uses Auth0's documented identifiers where a matching screen exists:

- **`login` / `login`:** `title`, `description`, `usernamePlaceholder`, `passwordPlaceholder`, `buttonText`, `signupActionText`, `signupActionLinkText`, `logoAltText`, `wrong-credentials`, `user-blocked`
- **`signup` / `signup`:** `title`, `description`, `emailPlaceholder`, `usernamePlaceholder`, `passwordPlaceholder`, `buttonText`, `loginActionText`, `loginActionLinkText`, `logoAltText`, `email-in-use`, `username-taken`, `password-policy-not-conformant`, `invalid-username`
- **`logout` / `logout`** (the confirmation page): `pageTitle`, `title`, `description`, `acceptButtonText`
- **zeroauthy screens with no documented counterpart** use the prompt `zeroauthy`, with screens `error`, `logged-out` and `form-post`. The same prompt holds extra login keys such as `too-many-attempts`, `session-expired`, `no-connection`, `signup-disabled` and `server-error`.

The plan's first task maps every current string to a key.

## 6. Tenant settings

- `Tenant.EnabledLocales []string`
- `Tenant.CustomText map[prompt]map[language]map[screen]map[key]string`

Both are seedable:

```yaml
enabled_locales: [en, fr]
custom_text:
  login:            # prompt
    fr:             # language
      login:        # screen
        title: "Connexion à ${companyName}"
```

Seed validation rejects these:
- invalid BCP 47 tags;
- custom text for a language that is not enabled;
- prompt, screen or key names that are not in `en.json`;
- unknown variables;
- placeholders that differ from the English string.

Sub-project 3 will expose `PUT /prompts/{prompt}/custom-text/{language}` on this storage. Calling it replaces all text for that prompt and language.

## 7. Code changes

- **New package `internal/i18n`:**
  - `Negotiate(t *store.Tenant, uiLocales, acceptLanguage string) language.Tag`
  - `Localizer{T(key string, vars map[string]string) string; Lang; Dir}`
  - catalog loading and validation helpers that the seed package reuses
- **`ui`:** render functions take a `*i18n.Localizer`. Templates use `{{t "login.login.title"}}`. `RenderError` takes a key instead of English text.
- **`login`, `oidc`:** the `msg*` constants become keys.
- **`authz`:** `ui_locales` joins the transaction parameters.
- **`seed`, `store`, `storetest`:** the new tenant fields, with copy and round-trip tests.

## 8. Testing

- **Unit:**
  - a table of language-negotiation cases;
  - the four-step fallback;
  - variables and escaping;
  - seed validation errors.
- **Catalog test:** every key used by templates or Go code exists in `en.json`, there are no unused keys, and other catalogs have the same keys and placeholders.
- **Handlers:** `/authorize?ui_locales=fr` leads to a French `/u/login` with `lang="fr"`. A failed login re-renders the page in French. An untranslated key shows English. An unenabled language falls back to the tenant default.
- **E2E:** an auth0-spa-js test with `ui_locales: 'fr'` against an e2e tenant that has French custom text.

## 9. Documentation

- D-0016: the selection rules, including the assumption that `fr-CA` falls back to `fr` (the docs are silent on this), and the variables.
- A new row in the compatibility matrix.
- `docs/i18n.md`: a guide to adding a language (copy `en.json`, translate, run the catalog test).

## 10. Out of scope

- Shipping non-English catalogs.
- Emails (milestone 6).
- The custom-text Management API (sub-project 3).
- RTL styling beyond `dir` and logical CSS properties.
