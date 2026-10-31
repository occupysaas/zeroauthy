# Task 16a2 emitted-code source → event-test audit

All 60 frozen `emitted=true` rows are mapped below to business outcome source
and real emitted-event assertions. This revises Task16a's six absent/partial
rows. Reviewed source decision/commit boundaries and event-test bodies, including
table-driven code assertions; inventory membership and string-literal tests are
not runtime evidence. Unchanged rows retain their Task16a source/test mapping
(the corresponding production sources are unchanged from c6284b8); this is
not a fresh run of every named test. Actual focused/race runs are recorded in
the implementation record and Task16a2 report. Catalog claims and full branch
acceptance remain separate.

| Emitted code | Actual production decision/write boundary | Real event test evidence / scope |
| --- | --- | --- |
| `actions_execution_failed` | internal/actions/engine.go: Engine.run → executionFailureEvent (synchronous only); internal/actions/jobs.go: Worker.Run after successful terminal FinishJob | internal/actions/failure_events_test.go: TestSynchronousActionFailureEvents (post-login throw/timeout, pre-registration throw, metadata/record failures; deny/validation/success negatives); internal/actions/console_test.go: TestAsyncJobFailureLogged (exact terminal count), TestAsyncJobFailureNotLoggedWhenFinishRollsBack; mounted TestHostedLoginOutcomeEvents; login TestActionThrowLogged, TestActionExecutionLinksOnSignupEvents |
| `api_limit` | internal/mgmt/logmiddleware.go | internal/mgmt/logmiddleware_test.go: TestManagementRateLimitLogged |
| `custom_domain_verification_failed` | internal/mgmt/custom_domains.go | internal/mgmt/logmiddleware_test.go: TestManagementDomainVerificationLogged |
| `f` | internal/authz/actions.go; internal/login/login.go; internal/login/login.go; internal/login/social.go; internal/oauth/grant_password.go; internal/oauth/grant_password.go | internal/login/events_test.go: TestAuthenticationEvents, TestActionDenyLogged, TestActionThrowLogged, TestSocialCallbackFailureEventAttribution; internal/server/login_outcomes_test.go: TestHostedLoginOutcomeEvents |
| `fapi` | internal/mgmt/logmiddleware.go | internal/mgmt/logmiddleware_test.go: TestManagementWriteLogged, TestManagementFailedWriteLogged, TestManagementReadNotLogged, TestManagementSecretReadLogged |
| `fce` | internal/mgmt/users.go | internal/mgmt/logmiddleware_test.go: TestManagementUserDomainLogged; internal/login/events_test.go: TestHostedOutcomeEvents (fcp/scp) |
| `fcp` | internal/login/reset.go; internal/mgmt/users.go | internal/mgmt/logmiddleware_test.go: TestManagementUserDomainLogged; internal/login/events_test.go: TestHostedOutcomeEvents (fcp/scp) |
| `fcpr` | internal/dbconn/change_password.go; internal/login/reset.go | internal/dbconn/events_test.go: TestPasswordResetInitiationEvents; internal/login/events_test.go: TestHostedOutcomeEvents |
| `fcu` | internal/mgmt/users.go | internal/mgmt/logmiddleware_test.go: TestManagementUserDomainLogged; internal/login/events_test.go: TestHostedOutcomeEvents (fcp/scp) |
| `fdeac` | internal/login/device.go | internal/login/events_test.go: TestDeviceActivationEvents |
| `fdeaz` | internal/oauth/device.go | internal/oauth/events_test.go: TestAuthorizationRequestFailureEvents |
| `fdecc` | internal/login/device.go | internal/login/events_test.go: TestDeviceActivationEvents |
| `fdu` | internal/mgmt/users.go | internal/mgmt/logmiddleware_test.go: TestManagementDeleteFailureDomainLogged |
| `feacft` | internal/oauth/grant_authorization_code.go | internal/oauth/events_test.go: TestTokenExchangeOutcomeEvents |
| `feccft` | internal/oauth/grant_client_credentials.go | internal/oauth/events_test.go: TestGrantEvents; TestActionExecutionLinksOnGrantEvents (fepft) |
| `fede` | internal/oauth/grant_device_code.go | internal/oauth/events_test.go: TestTokenExchangeOutcomeEvents |
| `fepft` | internal/oauth/grant_password.go | internal/oauth/events_test.go: TestGrantEvents; TestActionExecutionLinksOnGrantEvents (fepft) |
| `ferrt` | internal/oauth/grant_refresh_token.go | internal/oauth/events_test.go: TestRefreshReuseAndRevokeEvents |
| `fertft` | internal/oauth/grant_refresh_token.go | internal/oauth/events_test.go: TestTokenExchangeOutcomeEvents |
| `fi` | internal/orglogin/invitations.go | internal/orglogin/events_test.go: TestInvitationEvents; internal/orglogin/attribution_events_test.go: TestInvitationFailureEventAttribution |
| `flo` | internal/oidc/logout.go: endSession failed End; internal/oidc/rp_logout.go: OidcLogout failed Lookup after target validation | internal/oidc/logout_events_test.go: TestLogoutOutcomeEvents (v2/RP lookup and deletion-write failure; invalid/pending negatives); existing logout behavior suites preserved |
| `fn` | internal/email/service.go: Service.deliver named-return observer shared by Send and legacy SendMessage; Service.Recorder wired in app.New/server.New | internal/email/notification_events_test.go: TestNotificationFailureEvents (stored/legacy × fallback/native failures, exact one; native/context short secrets; success, disabled, verification, synthetic, enqueue negatives); mounted internal/server/notification_outcomes_test.go: TestMountedNotificationFailureEvent |
| `fp` | internal/login/login.go; internal/oauth/grant_password.go | internal/login/events_test.go: TestAuthenticationEvents; internal/oauth/events_test.go: TestPasswordFailureClassificationEvents |
| `fpar` | internal/oauth/par.go | internal/oauth/events_test.go: TestAuthorizationRequestFailureEvents |
| `fs` | internal/dbconn/signup.go; internal/login/login.go | internal/dbconn/events_test.go: TestDatabaseConnectionEvents; internal/login/events_test.go: TestHostedOutcomeEvents, TestActionExecutionLinksOnSignupEvents; mounted TestHostedLoginOutcomeEvents |
| `fsa` | internal/authz/handlers.go: Authorize outcome observer after resolved/PAR request validation; completed only by flow.go: loginSucceeded after issuance | internal/authz/silent_events_test.go: TestSilentAuthorizationOutcomeEvents (login/consent/interaction, redirect/deny/throw, invalid session/disabled connection, issuance failure, PAR, cookie masks; ssa/ordinary/malformed negatives); mounted internal/server/flow_test.go: TestEndToEndRefreshAndLogout |
| `fu` | internal/login/login.go; internal/oauth/grant_password.go | internal/login/events_test.go: TestAuthenticationEvents; internal/oauth/events_test.go: TestPasswordFailureClassificationEvents |
| `fui` | internal/jobs/runner.go; internal/jobs/sweep.go | internal/jobs/outcome_test.go: TestImportJobOutcomeLogged; internal/app/job_outcomes_test.go: TestSweepRecordsAbandonedImportsAfterWrite (fui sweep); storetest.JobSweepOutcomes native+grpc |
| `fv` | internal/login/verify.go | internal/login/events_test.go: TestHostedOutcomeEvents |
| `fvr` | internal/mgmt/jobs.go | internal/mgmt/logmiddleware_test.go: TestManagementVerificationDomainLogged |
| `limit_mu` | internal/protection/service.go | internal/protection/events_test.go: TestProtectionDecisionEvents, TestDeniedEventDoesNotReadForLogging, TestLegacyAdmissionOmitsUncertainEvent |
| `limit_sul` | internal/protection/service.go | internal/protection/events_test.go: TestProtectionDecisionEvents, TestDeniedEventDoesNotReadForLogging, TestLegacyAdmissionOmitsUncertainEvent |
| `limit_wc` | internal/protection/service.go | internal/protection/events_test.go: TestProtectionDecisionEvents, TestDeniedEventDoesNotReadForLogging, TestLegacyAdmissionOmitsUncertainEvent |
| `mgmt_api_read` | internal/mgmt/logmiddleware.go | internal/mgmt/logmiddleware_test.go: TestManagementWriteLogged, TestManagementFailedWriteLogged, TestManagementReadNotLogged, TestManagementSecretReadLogged |
| `organization_access_denied` | internal/authz/organization.go: ResolveOrganization resolved third-party/member-client policy denial (only ErrNotMember for membership; backend/missing errors stay distinct) | internal/authz/organization_events_test.go: TestOrganizationAccessDeniedEvents (third-party/member-client refusal; allowed/missing/foreign/usage/lookup/unavailable negatives); mounted internal/server/organization_outcomes_test.go: TestMountedOrganizationDenialEvents (authorize one; PAR denial+fpar, credential masks) |
| `organization_member_added` | internal/mgmt/organization_members.go; internal/orglogin/invitations.go; internal/orglogin/organization.go | internal/orglogin/events_test.go: TestMembershipEventsCommitAndRollback, TestExistingInvitationMemberHasNoAddedEvent; internal/mgmt/logmiddleware_test.go: TestManagementMembershipDomainLogged; internal/login/attribution_events_test.go |
| `pwd_leak` | internal/login/login.go; internal/oauth/grant_password.go | internal/login/events_test.go: TestBreachOutcomeEvents, TestBreachMonitoringEvents; internal/dbconn/events_test.go: TestSignupBreachEvents; internal/mgmt/logmiddleware_test.go: TestManagementBreachDomainLogged (reset_pwd_leak) |
| `reset_pwd_leak` | internal/login/reset.go; internal/mgmt/users.go | internal/login/events_test.go: TestBreachOutcomeEvents, TestBreachMonitoringEvents; internal/dbconn/events_test.go: TestSignupBreachEvents; internal/mgmt/logmiddleware_test.go: TestManagementBreachDomainLogged (reset_pwd_leak) |
| `s` | internal/authz/flow.go | internal/server/login_outcomes_test.go: TestHostedLoginOutcomeEvents (mounted HTTP/TLS forms, issuance, session reuse, silent, signup/deny, exact counts/stats/short credential); internal/login/events_test.go: TestLoginLogCarriesExecutionIDs |
| `sapi` | internal/mgmt/logmiddleware.go | internal/mgmt/logmiddleware_test.go: TestManagementWriteLogged, TestManagementFailedWriteLogged, TestManagementReadNotLogged, TestManagementSecretReadLogged |
| `sce` | internal/mgmt/users.go | internal/mgmt/logmiddleware_test.go: TestManagementUserDomainLogged; internal/login/events_test.go: TestHostedOutcomeEvents (fcp/scp) |
| `scp` | internal/login/reset.go; internal/mgmt/users.go | internal/mgmt/logmiddleware_test.go: TestManagementUserDomainLogged; internal/login/events_test.go: TestHostedOutcomeEvents (fcp/scp) |
| `scpr` | internal/dbconn/change_password.go; internal/login/reset.go; internal/login/reset.go | internal/dbconn/events_test.go: TestPasswordResetInitiationEvents; internal/login/events_test.go: TestHostedOutcomeEvents |
| `scu` | internal/mgmt/users.go | internal/mgmt/logmiddleware_test.go: TestManagementUsernameDomainLogged |
| `sdu` | internal/mgmt/users.go | internal/mgmt/logmiddleware_test.go: TestManagementUserNoopAndDeleteLogged |
| `seacft` | internal/oauth/grant_authorization_code.go | internal/oauth/events_test.go: TestTokenExchangeOutcomeEvents |
| `seccft` | internal/oauth/grant_client_credentials.go | internal/oauth/events_test.go: TestGrantEvents; TestActionExecutionLinksOnGrantEvents (fepft) |
| `sede` | internal/oauth/grant_device_code.go | internal/oauth/events_test.go: TestTokenExchangeOutcomeEvents |
| `sepft` | internal/oauth/grant_password.go | internal/oauth/events_test.go: TestTokenExchangeOutcomeEvents |
| `sertft` | internal/oauth/grant_refresh_token.go | internal/oauth/events_test.go: TestTokenExchangeOutcomeEvents |
| `si` | internal/orglogin/invitations.go | internal/orglogin/events_test.go: TestInvitationEvents; internal/orglogin/attribution_events_test.go: TestInvitationFailureEventAttribution |
| `signup_pwd_leak` | internal/dbconn/signup.go; internal/login/login.go | internal/login/events_test.go: TestBreachOutcomeEvents, TestBreachMonitoringEvents; internal/dbconn/events_test.go: TestSignupBreachEvents; internal/mgmt/logmiddleware_test.go: TestManagementBreachDomainLogged (reset_pwd_leak) |
| `slo` | internal/oidc/logout.go: endSession after successful End (shared v2/RP; idempotent no-session included) | internal/oidc/logout_events_test.go: TestLogoutOutcomeEvents, TestLogoutRequestCredentialMasks; mounted internal/server/flow_test.go: TestEndToEndRefreshAndLogout; pending/invalid/write-failure negatives |
| `srrt` | internal/oauth/revoke.go | internal/oauth/events_test.go: TestRefreshReuseAndRevokeEvents |
| `ss` | internal/dbconn/signup.go; internal/login/login.go | internal/dbconn/events_test.go: TestDatabaseConnectionEvents; internal/login/events_test.go: TestHostedOutcomeEvents, TestActionExecutionLinksOnSignupEvents; mounted TestHostedLoginOutcomeEvents |
| `ssa` | internal/authz/flow.go | internal/server/login_outcomes_test.go: TestHostedLoginOutcomeEvents (mounted HTTP/TLS forms, issuance, session reuse, silent, signup/deny, exact counts/stats/short credential); internal/login/events_test.go: TestLoginLogCarriesExecutionIDs |
| `sui` | internal/jobs/runner.go | internal/jobs/outcome_test.go: TestImportJobOutcomeLogged; internal/app/job_outcomes_test.go: TestSweepRecordsAbandonedImportsAfterWrite (fui sweep); storetest.JobSweepOutcomes native+grpc |
| `sv` | internal/login/verify.go | internal/login/events_test.go: TestHostedOutcomeEvents |
| `svr` | internal/mgmt/jobs.go | internal/mgmt/logmiddleware_test.go: TestManagementVerificationDomainLogged |
| `ublkdu` | internal/mgmt/user_blocks.go | internal/mgmt/logmiddleware_test.go: TestManagementUnblockDomainLogged |

## Boundary rulings and remaining acceptance

- `fsa` starts only after real request/PAR resolution and successful request
  validation. Malformed/unresolved authorization requests are outside this
  outcome observer; organization entitlement denial during request validation
  owns `organization_access_denied` (and `fpar` for PAR). A valid silent request
  emits one `fsa` on returned refusal, including failed final issuance; `ssa`
  is marked only after completed issuance. No `s`+`ssa` overlap. Authenticated
  attribution comes from ActiveSession and resolved connections, never the
  browser's login_hint/user/organization_name.
- Exact silent sequences: no-session/consent/interaction/disabled/issuance
  failure → `fsa`; explicit Action deny → `f,fsa`; thrown Action →
  `actions_execution_failed,f,fsa`; prohibited redirect Action →
  `actions_execution_failed,fsa` because the engine's redirect command fails
  and authz translates it to interaction_required without ordinary login `f`.
  Ordinary hosted throw → `actions_execution_failed,f`; pre-registration
  throw → `actions_execution_failed,fs`. Deny/validation/success never produces
  `actions_execution_failed` unless an actual later metadata/record write fails.
- Async Engine.run is suppressed using its existing durable job ID. Only the
  existing successful terminal FinishJob boundary emits the async Action
  failure. Six custom-email attempts still yield one terminal event; rollback
  yields zero. No guessed `fn` is added from sealed async notification jobs.
- `slo` counts validated idempotent no-session completion, since the local
  logout operation has completed. Pending RP confirmation and invalid target
  validation produce neither logout event; actual lookup/end failures produce
  one `flo`. End's returned session supplies user/connection on success; RP's
  already-resolved session is available on end-write failure. No logging read.
- `fn` observes the common actual dispatch boundary. It covers native/fallback
  transport, provider configuration and enqueue failure reached in deliver,
  once across stored and legacy APIs. It does not claim template lookup/render
  failures before dispatch. Empty/synthetic and verify_email message types are
  excluded; fv continues to own verification. Successful custom enqueue is not
  notification delivery. Async terminal Action failure remains its existing
  Action event; no message-type/user attribution is guessed for another fn.
- Only actual member-client ErrNotMember is a policy refusal. A vanished
  organization is invalid_request; unavailable/backend errors are server_error.
  Failed policy validation returns immediately, so revalidation/issuance does
  not duplicate the denied decision; allowed validation emits nothing.
- No source-only logging DB lookup, store/SQL/protobuf/API/schema change, new
  dependency, or generated artifact change. Recorder defaults to context/Nop;
  background email has the app-injected recorder. Opened native provider and
  Action/Module secrets register masks before outcomes; cookies/logout hints/
  authorization credentials register before free-text metadata can be logged.
  Fixed type/date/schema and server-generated execution links retain meaning.
- Task16 remains incomplete. Browser/CLI/console acceptance, docs, broad final
  regression, whole-branch review, and prior carry-forward minors remain.
  Dedicated event coverage for every consent/device/redirect continuation and
  every unchanged inventory trigger is not claimed by this 60-row audit.
