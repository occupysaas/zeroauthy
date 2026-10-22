# Management API tenant settings — T1–T3

- Research and observation date: 2026-10-22 UTC (work began in the 2026-10-21 session).
- Separate observer session; no implementation code was read or changed for these resources. Sources are public documentation and authorized documented API requests under `CLEAN_ROOM.md`.
- Credentials remained in the observer process environment. Token acquisition succeeded; required tenant read/update scopes were granted. Scope isolation was not tested: a successful broad token does not prove minimal scopes.

## Reference operations

| Method/path | Scope | Public source | Success |
|---|---|---|---|
| GET `/api/v2/tenants/settings` | `read:tenant_settings` | https://auth0.com/docs/api/management/v2/tenants/tenant-settings-route | 200 object |
| PATCH `/api/v2/tenants/settings` | `update:tenant_settings` | https://auth0.com/docs/api/management/v2/tenants/patch-settings | 200 object |

The earlier draft's GET source slug `get-settings` is not the current public page. Both schemas were reviewed, including nested constraints. GET supports comma-separated `fields` and boolean `include_fields`; empty fields means all. Unknown query behavior and nested projection are not observed; fallback: validate boolean syntax, apply top-level projection, ignore unknown field names. This is a local choice, not an observed claim.

## T1: wire and patch observations

GET returned a sparse object: absent presentation/session fields are not evidence of zero/default values. The observed keys were `authorization_response_iss_parameter_supported`, `client_id_metadata_document_dynamic_registration_supported`, `client_id_metadata_document_supported`, `dpop_strict_refresh_token_binding`, `enabled_locales`, `flags`, `oidc_logout`, `pushed_authorization_requests_supported`, `resource_parameter_profile`, `sandbox_version`, `sandbox_versions_available`. No tenant-specific values are recorded.

A same-value PAR PATCH succeeded with 200; omitted settings were preserved. Its response omitted the GET-only `sandbox_versions_available` and two metadata-document flags, so PATCH need not exactly equal GET. `fields=flags&include_fields=true` returned `flags` plus `sandbox_version`, `sandbox_versions_available`, `resource_parameter_profile` and both metadata-document flags. Those forced projection fields are an observed service behavior; zeroauthy may omit inert forced fields and must document that difference rather than manufacture versions.

Observed PATCH refusals: `{}`, an unknown property, null `session_lifetime`, fractional `session_lifetime` 1.5, zero `session_lifetime`, hours and minutes together, and empty `enabled_locales` each returned 400 `invalid_body`. A same-value single flag PATCH also returned 400; it does not prove general flag merge behavior or flag writability. No verbatim error messages are retained.

Documented contract: nonempty root object, no unknown root/nested properties except explicitly open maps below; validate full patch before commit. Unobserved reset/merge fallback: recursively merge object properties, replace arrays, preserve omitted fields and explicit false; null is legal only where schema admits it and resets that field to its local default/absence. Do not accept null as a universal delete operator. `{}` nested objects preserve siblings; root `{}` is invalid. Unknown fields and read-only fields are 400 `invalid_body`. These fallback choices require tests and a compatibility note; they were not inferred from successful same-value writes.

## T2: duration and cookie contract

PATCH hours and all four minute aliases are **integers >=1**. Supplying an hours field with its minute alias is invalid even when equal. GET hours are numbers and can represent minute-backed fractions; minute aliases are write-only in the GET schema. Canonical local representation is hours: 90 minutes returns 1.5 hours. This representation is documented-schema fallback, not a live duration mutation. Convert exactly to internal seconds; seed seconds remain separate. Fractional API hours and zero fail; existing seed seconds need not be whole hours.

Documented persistent defaults: absolute 168 hours, idle 72 hours; ephemeral defaults: absolute 72 hours, idle 24 hours. Cookie setting is **`session_cookie.mode`**, enum `persistent` (default) / `non-persistent`; `sessions` contains logout/anonymous options and does not select cookie persistence. No upper bound appears on the duration fields in this API schema: apply checked integer-second arithmetic and refuse overflow; do not invent a documented maximum. Anonymous-session lifetime's description supplies a separate maximum of 525600 minutes.

Duration defaults were not present in the observed sparse GET. No existing session was created or captured. Existing-session local policy: new settings affect new sessions; never extend an existing absolute expiry; touches may shorten idle expiry. Non-persistent cookies omit browser persistence attributes while server lifetimes still apply. A local default representation is an explicit difference from the observed sparse GET, not an observation.

## T3: validation and inventory ownership

Use the exact enums, formats and limits in the inventory. Directory description permits database, LDAP/AD, passwordless, Azure AD and ADFS names. Whether unknown audience/directory names are accepted was not observed; local fallback: nonempty values must resolve within the tenant to a supported configured resource server/connection. Reject unsupported locales according to the API enum, then show which of those have a local hosted translation; storing a documented locale need not fabricate a translation. Empty optional URLs/email clear; logout URLs retain existing safe redirect validation; default redirection must be HTTPS or empty.

`use_scope_descriptions_for_consent` is **not** a field in the retrieved public PATCH schema. Its existing seed interface remains; do not invent a Management API property or flag. `authorization_response_iss_parameter_supported` is stored, but this milestone does not weaken existing issuer-response behavior. New or legacy flag semantics are not automatically runtime enforcement.

The inventory below is a factual constraint transcription (field names, types, enumerations and numeric bounds), with original ownership labels. `default` means the public schema annotation; example presentation URLs/names are not tenant values and must not be installed as real contact details. Missing constraints mean unspecified, not unlimited resource consumption. All writable fields are stored/validated by Tasks 2–3; “inert” means round-trip only, with the named later owner. Every `flags.*` entry is inert in this milestone except explicitly read-only entries; do not imply that accepting it changes authentication. The existing seed/PAR/device/session consumers are the enforced mappings.

| PATCH field path | Schema constraints | Runtime owner |
|---|---|---|
| `change_password` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 22 / MFA |
| `change_password.enabled` | `{"type":"boolean","default":false}` | inert; Plan 22 / MFA |
| `change_password.html` | `{"type":"string","default":""}` | inert; Plan 22 / MFA |
| `device_flow` | `{"type":["object","null"],"additionalProperties":false}` | enforced; Task 5 |
| `device_flow.charset` | `{"type":"string","default":"base20","enum":["base20","digits"]}` | enforced; Task 5 |
| `device_flow.mask` | `{"type":"string","default":"****-****","maxLength":20}` | enforced; Task 5 |
| `guardian_mfa_page` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 22 / MFA |
| `guardian_mfa_page.enabled` | `{"type":"boolean","default":false}` | inert; Plan 22 / MFA |
| `guardian_mfa_page.html` | `{"type":"string","default":""}` | inert; Plan 22 / MFA |
| `default_audience` | `{"type":"string","default":""}` | enforced; Task 5 |
| `default_directory` | `{"type":"string","default":""}` | enforced; Task 5 |
| `error_page` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 22 / MFA |
| `error_page.html` | `{"type":"string","default":""}` | inert; Plan 22 / MFA |
| `error_page.show_log_link` | `{"type":"boolean","default":false}` | inert; Plan 22 / MFA |
| `error_page.url` | `{"type":"string","default":"https://mycompany.org/error","format":"absolute-uri-or-empty"}` | inert; Plan 22 / MFA |
| `default_token_quota` | `{"type":["object","null"],"additionalProperties":false,"minProperties":1}` | inert; tenant-feature follow-up |
| `default_token_quota.clients` | `{"type":"object","additionalProperties":true,"required":["client_credentials"]}` | inert; tenant-feature follow-up |
| `default_token_quota.clients.client_credentials` | `{"type":"object","additionalProperties":false,"minProperties":1}` | inert; tenant-feature follow-up |
| `default_token_quota.clients.client_credentials.enforce` | `{"type":"boolean"}` | inert; tenant-feature follow-up |
| `default_token_quota.clients.client_credentials.per_day` | `{"type":"integer","minimum":1,"maximum":2147483647}` | inert; tenant-feature follow-up |
| `default_token_quota.clients.client_credentials.per_hour` | `{"type":"integer","minimum":1,"maximum":2147483647}` | inert; tenant-feature follow-up |
| `default_token_quota.organizations` | `{"type":"object","additionalProperties":true,"required":["client_credentials"]}` | inert; tenant-feature follow-up |
| `default_token_quota.organizations.client_credentials` | `{"type":"object","additionalProperties":false,"minProperties":1}` | inert; tenant-feature follow-up |
| `default_token_quota.organizations.client_credentials.enforce` | `{"type":"boolean"}` | inert; tenant-feature follow-up |
| `default_token_quota.organizations.client_credentials.per_day` | `{"type":"integer","minimum":1,"maximum":2147483647}` | inert; tenant-feature follow-up |
| `default_token_quota.organizations.client_credentials.per_hour` | `{"type":"integer","minimum":1,"maximum":2147483647}` | inert; tenant-feature follow-up |
| `flags` | `{"type":"object","additionalProperties":false}` | inert; follow-up owner table below |
| `flags.change_pwd_flow_v1` | `{"type":"boolean","default":false}` | inert; follow-up owner table below |
| `flags.enable_apis_section` | `{"type":"boolean","default":false}` | inert; follow-up owner table below |
| `flags.disable_impersonation` | `{"type":"boolean","default":false}` | read-only; legacy identity UI |
| `flags.enable_client_connections` | `{"type":"boolean","default":true}` | inert; follow-up owner table below |
| `flags.enable_pipeline2` | `{"type":"boolean","default":true}` | inert; follow-up owner table below |
| `flags.allow_legacy_delegation_grant_types` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.allow_legacy_ro_grant_types` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.allow_legacy_tokeninfo_endpoint` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.enable_legacy_profile` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.enable_idtoken_api2` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.enable_public_signup_user_exists_error` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.enable_sso` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.allow_changing_enable_sso` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.disable_clickjack_protection_headers` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.no_disclose_enterprise_connections` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.enforce_client_authentication_on_passwordless_start` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.enable_adfs_waad_email_verification` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.revoke_refresh_token_grant` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.dashboard_log_streams_next` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.dashboard_insights_view` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.disable_fields_map_fix` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.mfa_show_factor_list_on_enrollment` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.remove_alg_from_jwks` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.improved_signup_bot_detection_in_classic` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.genai_trial` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.local_resource_discovery` | `{"type":"boolean"}` | inert; follow-up owner table below |
| `flags.enable_dynamic_client_registration` | `{"type":"boolean","default":false}` | inert; follow-up owner table below |
| `flags.disable_management_api_sms_obfuscation` | `{"type":"boolean","default":true}` | inert; follow-up owner table below |
| `flags.trust_azure_adfs_email_verified_connection_property` | `{"type":"boolean","default":false}` | inert; follow-up owner table below |
| `flags.custom_domains_provisioning` | `{"type":"boolean","default":false}` | inert; follow-up owner table below |
| `friendly_name` | `{"type":"string","default":"My Company"}` | enforced; Task 5 |
| `picture_url` | `{"type":"string","default":"https://mycompany.org/logo.png","format":"absolute-uri-or-empty"}` | enforced; Task 5 |
| `support_email` | `{"type":"string","default":"support@mycompany.org","format":"email-or-empty"}` | enforced; Task 5 |
| `support_url` | `{"type":"string","default":"https://mycompany.org/support","format":"absolute-uri-or-empty"}` | enforced; Task 5 |
| `allowed_logout_urls` | `{"type":"array","items":{"type":"string","format":"url-with-placeholders"}}` | enforced; Task 5 |
| `session_lifetime` | `{"type":"integer","default":168,"minimum":1}` | enforced; Task 5 |
| `session_lifetime_in_minutes` | `{"type":"integer","minimum":1}` | enforced; Task 5 |
| `idle_session_lifetime` | `{"type":"integer","default":72,"minimum":1}` | enforced; Task 5 |
| `idle_session_lifetime_in_minutes` | `{"type":"integer","minimum":1}` | enforced; Task 5 |
| `ephemeral_session_lifetime` | `{"type":"integer","default":72,"minimum":1}` | enforced; Task 5 |
| `idle_ephemeral_session_lifetime` | `{"type":"integer","default":24,"minimum":1}` | enforced; Task 5 |
| `ephemeral_session_lifetime_in_minutes` | `{"type":"integer","minimum":1}` | enforced; Task 5 |
| `idle_ephemeral_session_lifetime_in_minutes` | `{"type":"integer","minimum":1}` | enforced; Task 5 |
| `sandbox_version` | `{"type":"string","default":"22","maxLength":8}` | inert; custom-script version follow-up |
| `legacy_sandbox_version` | `{"type":"string","maxLength":8}` | inert; custom-script version follow-up |
| `default_redirection_uri` | `{"type":"string","format":"absolute-https-uri-or-empty"}` | inert; tenant-feature follow-up |
| `enabled_locales` | `{"type":"array","minItems":1,"items":{"type":"string","enum":["am","ar","ar-EG","ar-SA","az","bg","bn","bs","ca-ES","cnr","cs","cy","da","de","el","en","en-CA","es","es-419","es-AR","es-MX","et","eu-ES","fa","fi","fr","fr-CA","fr-FR","gl-ES","gu","he","hi","hr","hu","hy","id","is","it","ja","ka","kk","kn","ko","lt","lv","mk","ml","mn","mr","ms","my","nb","nl","nn","no","pa","pl","pt","pt-BR","pt-PT","ro","ru","sk","sl","so","sq","sr","sv","sw","ta","te","th","tl","tr","uk","ur","vi","zgh","zh-CN","zh-HK","zh-MO","zh-TW"]}}` | enforced; Task 5 |
| `access_token` | `{"type":["object","null"],"additionalProperties":false}` | inert; session/logout follow-up |
| `access_token.claims_mapping` | `{"type":"object","additionalProperties":false}` | inert; session/logout follow-up |
| `access_token.claims_mapping.custom_claims` | `{"type":"array","items":{"type":"object","additionalProperties":false,"required":["name","expression"]}}` | inert; session/logout follow-up |
| `access_token.claims_mapping.custom_claims[].name` | `{"type":"string","minLength":1,"maxLength":255}` | inert; session/logout follow-up |
| `access_token.claims_mapping.custom_claims[].expression` | `{"type":"string","minLength":1,"maxLength":255,"pattern":"^[A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*(?:\\.[A-Za-z_][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)*)+$"}` | inert; session/logout follow-up |
| `security_headers` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.enabled` | `{"type":"boolean"}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.policies` | `{"type":"array","items":{"type":"object","additionalProperties":false}}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.policies[].mode` | `{"type":"string","enum":["enforcing","reporting"]}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.policies[].directives` | `{"type":"object","additionalProperties":{"type":"array"},"maxProperties":30}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.policies[].flags` | `{"type":"array","items":{"type":"string","enum":["upgrade-insecure-requests","block-all-mixed-content"]}}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.policies[].reporting` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.policies[].reporting.report_uri` | `{"type":"string"}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.policies[].reporting.report_to_group` | `{"type":"string"}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.reporting_infrastructure` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.reporting_infrastructure.report_to` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.reporting_infrastructure.report_to.group` | `{"type":"string"}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.reporting_infrastructure.report_to.max_age` | `{"type":"integer"}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.reporting_infrastructure.report_to.endpoints` | `{"type":"array","items":{"type":"object","additionalProperties":false}}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.reporting_infrastructure.report_to.endpoints[].url` | `{"type":"string"}` | inert; Plan 22 / MFA |
| `security_headers.content_security_policy.reporting_infrastructure.reporting_endpoints` | `{"type":"object","additionalProperties":{"type":"string"}}` | inert; Plan 22 / MFA |
| `security_headers.x_xss_protection` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 22 / MFA |
| `security_headers.x_xss_protection.enabled` | `{"type":"boolean"}` | inert; Plan 22 / MFA |
| `security_headers.x_xss_protection.mode` | `{"type":"string","enum":["block"]}` | inert; Plan 22 / MFA |
| `security_headers.x_xss_protection.report_uri` | `{"type":"string"}` | inert; Plan 22 / MFA |
| `session_cookie` | `{"type":["object","null"],"additionalProperties":false,"required":["mode"]}` | enforced; Task 5 |
| `session_cookie.mode` | `{"type":"string","default":"persistent","enum":["persistent","non-persistent"]}` | enforced; Task 5 |
| `sessions` | `{"type":["object","null"],"additionalProperties":false}` | inert; session/logout follow-up |
| `sessions.oidc_logout_prompt_enabled` | `{"type":"boolean","default":true}` | inert; session/logout follow-up |
| `sessions.anonymous` | `{"type":["object","null"],"additionalProperties":false}` | inert; session/logout follow-up |
| `sessions.anonymous.lifetime_in_minutes` | `{"type":"integer","default":43200}` | inert; session/logout follow-up |
| `sessions.anonymous.activate_cookie` | `{"type":"boolean","default":true}` | inert; session/logout follow-up |
| `oidc_logout` | `{"type":"object","additionalProperties":false}` | inert; session/logout follow-up |
| `oidc_logout.rp_logout_end_session_endpoint_discovery` | `{"type":"boolean","default":true}` | inert; session/logout follow-up |
| `customize_mfa_in_postlogin_action` | `{"type":["boolean","null"],"default":false}` | inert; organizations / MFA follow-up |
| `allow_organization_name_in_authentication_api` | `{"type":["boolean","null"],"default":false}` | inert; organizations / MFA follow-up |
| `acr_values_supported` | `{"type":["array","null"],"minItems":0,"items":{"type":"string","format":"acr"}}` | inert; sender-constraining / MFA follow-up |
| `mtls` | `{"type":["object","null"],"additionalProperties":false}` | inert; sender-constraining / MFA follow-up |
| `mtls.enable_endpoint_aliases` | `{"type":"boolean","default":false}` | inert; sender-constraining / MFA follow-up |
| `pushed_authorization_requests_supported` | `{"type":["boolean","null"],"default":false}` | enforced; Task 5 |
| `authorization_response_iss_parameter_supported` | `{"type":["boolean","null"],"default":false}` | inert toggle; existing issuer parameter behavior retained |
| `dpop_strict_refresh_token_binding` | `{"type":["boolean","null"],"default":false}` | inert; sender-constraining / MFA follow-up |
| `skip_non_verifiable_callback_uri_confirmation_prompt` | `{"type":["boolean","null"]}` | enforced; Task 5 |
| `resource_parameter_profile` | `{"type":"string","default":"audience","enum":["audience","compatibility"]}` | inert; OAuth resource-indicator follow-up |
| `client_id_metadata_document_supported` | `{"type":"boolean","default":false}` | inert; client-registration follow-up |
| `client_id_metadata_document_dynamic_registration_supported` | `{"type":"boolean","default":false}` | inert; client-registration follow-up |
| `enable_ai_guide` | `{"type":"boolean"}` | inert; tenant-feature follow-up |
| `phone_consolidated_experience` | `{"type":"boolean"}` | inert; Plan 34 |
| `include_session_metadata_in_tenant_logs` | `{"type":"boolean","default":false}` | inert; session/logout follow-up |
| `dynamic_client_registration_security_mode` | `{"type":"string","enum":["strict","permissive"]}` | inert; client-registration follow-up |
| `country_codes` | `{"type":["object","null"],"additionalProperties":false}` | inert; Plan 34 |
| `country_codes.list` | `{"type":"array","items":{"type":"string","minLength":2,"maxLength":2,"pattern":"^[A-Z]{2}$"}}` | inert; Plan 34 |
| `country_codes.mode` | `{"type":"string","enum":["allow","deny"]}` | inert; Plan 34 |

GET-only field: `sandbox_versions_available` is an array of strings, read-only (custom-script runtime follow-up). Minute aliases are PATCH-only. GET duration types are number rather than PATCH integer; GET organization/MFA/PAR booleans are not nullable where PATCH permits reset. GET logout URLs use `url` format; PATCH uses `url-with-placeholders`. The write schema is authoritative for validation. The following flag owner groups cover every flag above:

| Flags | Deferred consumer |
|---|---|
| `change_pwd_flow_v1`, `enable_public_signup_user_exists_error`, `enable_sso`, `allow_changing_enable_sso`, `disable_clickjack_protection_headers`, `improved_signup_bot_detection_in_classic` | legacy/classic hosted flow follow-up; no relaxation of current safe flow |
| `enable_client_connections`, `enable_pipeline2`, `allow_legacy_delegation_grant_types`, `allow_legacy_ro_grant_types`, `allow_legacy_tokeninfo_endpoint`, `enable_legacy_profile`, `enable_idtoken_api2`, `enable_dynamic_client_registration` | application/legacy OAuth registration follow-up |
| `revoke_refresh_token_grant` | refresh-token grant-revocation follow-up |
| `no_disclose_enterprise_connections`, `enable_adfs_waad_email_verification`, `trust_azure_adfs_email_verified_connection_property`, `disable_fields_map_fix` | enterprise/SAML follow-up |
| `enforce_client_authentication_on_passwordless_start`, `disable_management_api_sms_obfuscation` | Plan 34 |
| `mfa_show_factor_list_on_enrollment` | MFA follow-up |
| `remove_alg_from_jwks` | Plan 20 |
| `custom_domains_provisioning` | custom domains follow-up |
| `enable_apis_section`, `dashboard_log_streams_next`, `dashboard_insights_view`, `genai_trial`, `local_resource_discovery` | vendor UI/resource-discovery features; inert, no proprietary UI emulation |
| `disable_impersonation` | documented read-only; refuse write |

## Restoration and test ownership

All tenant reads/writes were paced at least one second apart, with snapshots held only in process memory. Only same-value existing settings were submitted successfully; invalid duration/locale/unknown/empty requests made no changes. Cleanup re-read and compared the full tenant snapshot: equality true after both sessions. No hosted pages/dashboard, login session capture, temporary real identities, load or fuzz traffic was used. Duration/device/null-reset mutations were deliberately avoided because absent original fields cannot be reliably restored without assuming reset semantics.

Tasks 2 and 5 must assert T1 unknown/null/root-empty/array/deep-merge rules; T2 integer writes, minute conversion/conflicts, cookie path and defaults; T3 all nested schema constraints and each inert/read-only flag. Task 10 labels stored-only fields. Task 11 uses pinned clients below. Unobserved semantics above remain explicit local fallback; no source/entitlement failure prevented read access.
