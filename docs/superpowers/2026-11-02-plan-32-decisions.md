# Plan 32 decisions and deferred findings

This is the complete controller decision ledger in chronological order. Historical rulings superseded by later fixes remain visible. The durable purge-watermark fix supersedes the earlier empty-ring expiry limitation. Repeated rulings describe the same decision as it was refined. Costs and limitations are retained with each entry.

## Rulings I made

1. Ruling: absent observer notes leave E1–E8 as gaps under spec §2 and §8, without tenant observation — explicitly allowed fallback — cost if wrong: later compatibility adjustment.

2. Ruling: express catalog organization-name negative lookahead as equivalent pattern plus not for Go regex support; allow documented test-purpose extension — retains constraints and documented tests — cost if wrong: validator correction.

3. Ruling: SQL event sequence must serialize append commits, beyond the 2s settle window — required for no loss under delayed commits — cost if wrong: contention; benchmark and concurrency tests required.

4. Ruling: workers must renew or bound lease work so retries cannot outlive ownership unnoticed — 100 events at up to 47 seconds each exceeds 60 seconds — cost if wrong: duplicate delivery or checkpoint contention.

5. Ruling: enforce anchored 26-character IDs and reject extra object/previous_object root keys while retaining open customer metadata — spec privacy/ID contract — cost if wrong: stricter validation than upstream catalog.

6. Ruling: separate secret-bearing create/PATCH schemas from secret-free response schemas; permit alternate delivery read scopes — documented authorization and spec — cost if wrong: client generation adjustment.

7. Ruling: retain invalid deferred group examples with strict schemas, validate all 16 emitted examples — no weakening to match broken documentation — cost if wrong: Plan38 fixture corrections.

8. Ruling: expose raw CloudEvent objects at Management API model boundary and retain canonical eventrules validator — avoids repeated full catalog models across API responses — cost if wrong: less generated static payload typing.

9. Ruling: strict validation must also reject extra identity profileData fields against recursive allowlist — published schema is open but spec privacy is binding — cost if wrong: stricter event validator than upstream schema.

10. Ruling: add minimal TenantEvent model in Task2 so required Build signature compiles, Task3 extends file — dependency prerequisite — cost if wrong: file ownership adjustment only.

11. Ruling: replace the plan's 10% relative latency gate with recorded benchmark and coarse 5s/1,000-create regression guard; explicitly report 10% NOT met — mandatory tx/outbox cannot fit a 1.4us raw memory create baseline, while ~0.5ms per captured write is consistent with normal signup latency — cost if wrong: noticeable memory demo-store overhead at high throughput; Task7 must still prove hanging receivers do not block signups. No broad memory transaction redesign authorized by this ruling.

12. Ruling: emit catalog events for observable user/membership/connection cascade changes inside decorated delete operations, including users deleted by noncatalog connection deletes and surviving users losing linked identities — spec says user.deleted when deleted and subscribers must not retain stale state — cost if wrong: more catalog events than upstream cascade semantics; separate observer evidence remains absent. Use same-tx pre-read and actual post-write comparison, avoid full-tenant snapshots on ordinary writes. Tenant deletion purges rather than recreates tenant events.

13. Ruling: cascade role events cover observable active member-role edges; dormant role rows retained after RemoveMembers are not exposed by MemberRoles/RoleMembers and produce no later separate role.deleted event when user/org deletion removes them — avoid invented events/new Store APIs, membership.deleted already communicates removal — cost if wrong: consumers retaining dormant assignment state must reconcile; future result API or observer evidence may refine this limitation. RemoveMembers must not emit role.deleted for deliberately retained rows.

14. Ruling: latency regression guard remains5s normally and allows30s under race instrumentation via test-only build-tag constants — measured race4.249s already close to5s before full-suite CPU contention, so identical timing gate would be flaky — cost if wrong: weaker timing regression sensitivity under race; normal performance measurement remains recorded, no test skipped and no claimed10% target.

15. Ruling: retry timed-out SQLite conformance alone at -timeout=90m, same snapshot/assertions/race; run focused Events race separately, do not repeat completed memory conformance — recorded default10m timeout and priorPlan31SQLite~14min justify longer deadline — cost if wrong: longer wait for actual deadlock; preserve originalfailure and actualretryresult.

16. Ruling: retry schedule means delays [0,1s,2s,4s] between attempts (instant requests start at cumulative0/1/3/7s), per spec's first plus retries after1/2/4 — Task7 test text 'at0/1/2/4' is shorthand/conflicts with exponential interval semantics — cost if wrong: upstream timing compatibility adjustment, still exactly four attempts and documented delays. Task7 must pin inter-attempt delays and early4xx/2xx stop.

17. Ruling: serialize CountEventStreams inside SQL transactions with existing tenant lock before API create quota check — COUNT followed by INSERT otherwise races on PostgreSQL/MySQL — cost if wrong: extra per-tenant contention; focused3driver concurrentquota regression authorized inTask6, no broadSQLrerun.

18. Ruling: Task6 positive event-stream Action validation uses tenant-scoped test-only Action Get adapter untilTask8 enables deferredtrigger — existing action normalization intentionally rejects it now — cost if wrong: Task8 must verify real end-to-end Action path; no early inventory activation.

19. Ruling: stream create/enable transaction locks tenant before stream/config/latest-sequence reads (tx.Tenants.Get existing SQL FOR UPDATE) — append could otherwise commit between LatestEventSeq and later update lock, replaying disabled history — cost if wrong: extra tenant-row serialization; focused concurrent enable/append SQL regression required, no new Store interface.

20. Ruling: expose read-only nonnegative total_failures on stream responses as explicit local console extension — Task12 needs extant failure count and frozen upstream response lacks one — cost if wrong: extra response field versus observed parity, documented in matrix/D0058; reject clientwrites, no lease/checkpoint/version/secrets exposed.

21. Ruling: permit ordinary HTTPS webhook query strings, retain userinfo/fragments/control/port/headertransport protections — frozenendpointcontractpermitsqueries and blanketbanhadnosecuritybasis — cost if wrong: endpointpublicconfigmayincludeuser-suppliedquerydata, aspathmay; configuredauthsecretsremainseparatesealedwriteonlyfields.

22. Ruling: PurgeEvents must update cached TotalFailures when deleting failed delivery rows (memory+SQL); narrow shared/backend regression authorized — extant-countsummary and5000reenableotherwiseincorrect — cost if wrong: extra transactionalpurgecontention; workeroutcome/purgecountersmustserializeavoidstalewriteback, testsboundedpurge/isolation/rollback.

23. Ruling: Task 7 bounds each lease iteration to one event, reacquiring before the next; four attempts take at most 47s, with a 5s record margin and 52s minimum remaining budget before send; preprocessing shares the shortened deadline and both pre-send/transactional owner+version checks fence stale work — avoids the unsafe 100-event drain under one 60s lease — cost if wrong: more reads/lower throughput than a batched renewal design.

24. Ruling: Task 7 refuses every webhook redirect and classifies 3xx as connection_error under the frozen safe diagnostic classes — prevents custom-header credential forwarding and redirect SSRF — cost if wrong: configure the receiver's final endpoint directly.

25. Ruling: oneeventperlease iteration plus persistedfairscheduling required, notstableownerlexicographicreacquire — no streammaystarvewhileanotherhascontinuouswork — cost if wrong: alteredleaseordering/extraquerywork; precise policy/testevidence followsfixreport.

26. Ruling: fair eligible stream selection orders persisted LeaseUntil then tenant/ID; renewal persists max(requestedUntil, previousLeaseUntil+1ns), with year9999 overflow rejection before mutation — controller-approved reuse of existing nanosecond text timestamps avoids schema/interface additions and frozen-clock starvation; memory and all three SQL backends assert exact returned/stored increments — cost if wrong: frozen/backward-clock or shorter renewal can retain/slightly extend a prior deadline instead of shortening it.

27. Ruling: fairleasepolicy ascendingLeaseUntil then tenant/id;persistmax(requestedUntil,oldUntil+1ns),overflowErrInvalid — frozenclocktiesotherwise stillstarve — cost if wrong: frozen/backwardsclockshorterrenewals preserve/slightlyextendoldlease;normalclock60sunchanged;exactnsall3DBtested.

28. Ruling: add narrow Actions job GetJob/CancelJob repositorymethods and memorySQL/plugin additiveRPC asTask8prerequisite — existingqueueonlyenqueue/claim/finish/purge cannotcrossprocesswaitorcancel — cost if wrong: protocol/APIextensionandoldpluginmissingmethodsneedfailclosedonlynewevent-stream path; preservepriorActionscompatibility,tenant-scopedatomiccancelfencesstaleFinish,focusedshared3DB/pluginregressionsrequired.

29. Ruling: event-stream executions use dedicated one-call Node process tracked/bounded by existingPool, kill+waitbeforeallreturns including success tostopdetachedtimers; sharedCallWithsemanticsunchanged — GoctxcannotabortarbitraryasyncJS, killing sharedtenantprocesswouldbreakothercalls — cost if wrong: processstartupperattempt/lossJSprocessglobals;hostapi.cachepersists,resourcebounds/shutdown/concurrencyregressionsrequired.

30. Ruling: isolatedevent-streamruntime admitsoneactivecall/tenant andmax64isolatedprocesses/Pool, waitershonorctx/shutdown;killreapbeforeallreturns — boundedresource/cancelisolation — cost if wrong: serializedpertenantActiondelivery andprocessstartup;hostcachepersists,norealtimeOSkillguarantee,already-sentrequestscannotrecalled.

31. Ruling: event-streamtrigger v1 islocaldefaultbecauseTask1omittedversionandconsulteddocsdidn'tdeclareone — cache/message/secrets/handlerdocumented,v1notclaimedevidence — cost if wrong: advertisedversionadjustment.

32. Ruling: reserveupto100msinside10sdeliverybudgetforCancelJobcleanup — cleanupmustnotextendattempt1s — cost if wrong: slightlylessActionruntime;sealeddeadlineindependentlyblocksnewlateexecution.

33. Ruling: separate failed|success enum for testresponse/attemptstatus from failed-onlypersistedfailure/filterenum — Task1schema reusedfailed-onlywhere successfuldeliverymustrepresentable — cost if wrong: generatedclienttypesadjust;APIresponsevalidationregressionandmakegenerate required.

34. Ruling: repairinvalidpublisheddeferredgroupIDs onlywhileconstructingdefault/testexamplepayloads, retainfrozenschema/rawexamplesandstrictcaller-IDvalidation — all25documentedtesteventtypesneedvaliddefaultdata — cost if wrong: localtestfixtureIDs differupstreamexamples,nochangeemittedgroupavailability.

35. Ruling: testeventenvelopesacceptcatalog-validprovidedupdateddatawithoutprevious_object; realcaptureBuildstillrequiresfullprior — syntheticdatareferenceallowspreviousomission,realupdateauditneedsprior — cost if wrong: testeventshapeoptionalhistorydifferscapturedrealupdates;do notinventpriorfromnewobject.

36. Ruling: SSEemptyretainedringOldestSeq0 cannotdistinguishvirgin/allpurgedwithoutnewhighwatermarkAPI;retainvalidcursoruntilnewoldestprovescursor<oldest-1 — existinginterfaceinsufficientforemptyringexpiryproof — cost if wrong:410delayeduntilnewretainedevent,documentlimitation,nohistoryfabricated.

37. Ruling: extract lightweight eventcontextcarrier toavoid events→connrules→identity→orglogin importcycle; preserveeventsContext/WithContext/FromRequestpublicaliaseswrappers — orgloginmustattachcontextwithoutheavybuilderdependencies — cost if wrong: smallinternalpackageindirection, nobehaviorchange.

38. Ruling: repairTask8staleexacttriggerassertions/sourceYAMLdiscoveryenum inTask11 afterrequiredsuiteexposedintegrationfailure — 8supportedtriggersmustconsistentacrossAPI — cost if wrong: test/schemaexpectationadjustment, makegenerate+focusedandshortsuitedue; readinesscausalitymustinvestigatebeforefix.

39. CorrectionTask11originalshort:5testfailures+4packagefailures (not6tests). Readinesscause: testhelperstoreplugin.KillForTest typeasserts*opened andsilentlydoesnothingnowAppstorewrapped*events.capture;Pingdelegationcorrect. Ruling: standardcapture.UnwrapStoreaccess andKillForTeststructuralunwraptraversalrepairtesthelper, notproductionreadinesspolicy — cost if wrong: helperwrappertraversalcyclehandlingneeded;focusedwrappedplugincrash+appreadinessregressionsrequired.

40. Ruling: clientcontextmetadata{}matchesexistingD0039ignoreclient_metadata/no persistedfield — cannotinventmetadata — cost if wrong: eventmetadataunavailableuntilclientstoragefeatureimplemented.

41. Ruling: recognizeonlythreeexactpinnedDeployCLI nonsecret##EVENT_STREAM_WEBHOOK_*##placeholders inexportcomparison, preserveliteralfieldcomparisonandrejectarbitrarysecrets/markers — pinnedexporteraddstheseevenwritesecretabsent — cost if wrong: clientversion-specificcomparisonneedsupdate;runtimecredentialreinjectionproofrequiredandpassed.

42. Ruling: splitTask14 implementationacceptance/docs andfixed-snapshotfullvalidationintoexplicitsequentialphases;oneacceptanceimplementerthenonesolevalidationmonitor,reviewafterfullchecks — keep runtime sourcefixedandlongsuiteprotocol,avoidduplicatefullruns — cost if wrong: additionalhandoff/report;Task14notcompleteuntilallphases+wholebranchreview.

43. Ruling: privacyDBdumpnegativegrep coversALLcolumns ofevent-specifictenant_events/event_streams/event_deliveries,notlegitimateusercredentialstoragetable; independentlyextract/verifyactualstoredhashpositivecontrol andproveabsencefromeventartifacts+receiver/serverlog/consoleresponses — fullrawDBmustlegitimatelycontainuserhashsooriginalunqualifiednegativegrepcontradictsauthstorage — cost if wrong: auditdoesnotclaimhashabsentfromprotectedsourcecredentialstorage,whichisintentional; table/columnselectionmustrecordprecise.

44. Ruling: fullSQLfinalmatrix uses -timeout=90m insteadplan30m — priorPlan31fullSQLraceactual34.17min+recorded30mtimeoutmakes30knowninsufficient, currentTask5SQLitegrpcneeded15.7min — cost if wrong: longerhangdetection;sameassertions/race/all3drivers/no skip,actualcommandmustrecord.

45. Ruling: durablehighest-purgedtenantsequence replacesSSEoldest-1globalgapexpiryinference;newEventsfloorquerymemorySQLgrpc andmigration0032foractualupgradefrom31 — oldinterfacecannotdistinguishretainedgapsvsremovedhistory,serverissuedcursorMUSTresume — cost if wrong: newRPC/table/migrationandappendpurgebookkeeping; preserveoldernonEventsplugins,failclosedhistoryunavailableSSE,all3backendrollback/isolation/upgrade/reopentestsrequired. Removesemptyringexpirydeferralfornewrecordedpurges;unknownpreexistingpurgehistorycannotinvent.

46. Ruling: POSTtestgetsfinite60sresponse/requestbudget accommodating47s+overhead,throughnormalcapturewrapper — usersneedattemptresultsfromhangingreceiver — cost if wrong: longerresourceoccupancyonlytestendpoint; clientcancellation/finitewritesrequired.

47. Ruling: passconfiguredmax_streamsintoseedusingexplicitoptions/default10 — startupmustobeysameeffectivequotaasAPI — cost if wrong: seedcallsitecompat/defaultingadjustments;existingresourcesremaincreate-onlyunderloweredquota.

48. Final: Ruling: declined upstream E1 webhookheaders/timeout parity remains observation gap; use approved documented local defaults and judge local correctness (I1-I3 fixed independently) — separate observer evidence unavailable — cost if wrong: compatibility adjustment after observation.

49. Final: Ruling: declined upstream E2 updatetriggers/priorobjects parity remains observation gap; use approved documented local defaults and judge local correctness (I1-I3 fixed independently) — separate observer evidence unavailable — cost if wrong: compatibility adjustment after observation.

50. Final: Ruling: declined upstream E3 deliveryIDs/lifecycle parity remains observation gap; use approved documented local defaults and judge local correctness (I1-I3 fixed independently) — separate observer evidence unavailable — cost if wrong: compatibility adjustment after observation.

51. Final: Ruling: declined upstream E4 testdefaults/disabledbehavior parity remains observation gap; use approved documented local defaults and judge local correctness (I1-I3 fixed independently) — separate observer evidence unavailable — cost if wrong: compatibility adjustment after observation.

52. Final: Ruling: declined upstream E5 disableambiguity parity remains observation gap; use approved documented local defaults and judge local correctness (I1-I3 fixed independently) — separate observer evidence unavailable — cost if wrong: compatibility adjustment after observation.

53. Final: Ruling: declined upstream E6 upstreamquotas/name/PATCH parity remains observation gap; use approved documented local defaults and judge local correctness (I1-I3 fixed independently) — separate observer evidence unavailable — cost if wrong: compatibility adjustment after observation.

54. Final: Ruling: declined upstream E7 upstreamSSEcadence/expiry/limits parity remains observation gap; use approved documented local defaults and judge local correctness (I1-I3 fixed independently) — separate observer evidence unavailable — cost if wrong: compatibility adjustment after observation.

55. Final: Ruling: declined E8 AWS partner source remains disabled local placeholder; no real AWS delivery — explicitly excluded cloud-operated service, no evidence — cost if wrong: users need another destination until provider integration exists.

56. Final: Ruling: declined future group capture stays Plan38 deferred; catalog subscription/test support does not emit nonexistent group mutations — underlying feature absent — cost if wrong: group subscribers receive no mutation events until feature lands.

57. Final: Ruling: declined GeoIP/client_metadata enrichment stays empty per existing data sources/D0039 — no fabricated context — cost if wrong: reduced context richness until data/storage support.

58. Final: Ruling: declined new production cluster benchmarks/hard realtime kill SLO; measured memory overhead, single-worker delays and isolated-process costs remain disclosed, no passing performance claim — no supplied load environment/SLO — cost if wrong: throughput/latency needs later tuning.

59. Final: Ruling: declined new Auth0/provider observation; keep clean-room separate observer roles and local-only acceptance qualification — implementer may not observe same area — cost if wrong: upstream parity gaps remain unverified.

60. Ruling: timestampSSEstartsoldestretained-1andfiltersrequestedtime,mayreplayretainedlowerseqevenwhenolder-event-timepurgecreatedhigherseqfloor; baselinepurgefloorisnotinitialopaque-cursorexpiry, newpurgesduringconnectionmustdetected — do notskipavailablehistory — cost if wrong: resuminganissuedlowerseqoffsetmaylegitimately410atknownremovedhigherseqgap;documentgap/restartfromtimestamp, explicitoffsetremainsseq<floor410. Suppressoffset-onlybelowknownflooruntilcrossedwherepractical;eventIDsstillactualsequence.

61. Rulingtimestampfollowup: from_timestamp startsoldestretained-1, allowspersistedpreexistingpurgegapsoallavailablelowerseqrowsreplay;newlyadvancingfloorcanterminate. Offset-onlysuppressedwhilebelowinitialfloor;rowoffsetbelowknownhigherpurgecanlegitimately410onreconnect,documentfallbacktimestamp. Opaqueformatunchanged.

62. Final: Ruling: accept unknownpre0032purgehistoryfloor0untilnewremoval, timestampreplaybelowknownhigherpurgegapmay410onrowresume, finite60stestresponseoccupancy — impossibletoinferlosthistory/replayavailabledata/return47sretryresult — cost if wrong: upgradecursoracceptancewindow, timestampfallbackneededatgaps,longertestrequestresourceuse; focusedregressions+docsreviewed.

## Deferred minors

- Task 1: minor (deferred): aws_partner_event_source response lacks readOnly API annotation (runtime must still keep client writes forbidden).

- Task 2: minor (deferred): test import grouping in build_test.go.

- Task 3: minor (deferred): gofmt formatting of added declarations in store/store.go and store/events.go.

- Task 4: minor (deferred): explicit interrupted MySQL0031-resume test (upgrade/schemaequivalence and resumable DDL reviewed).

- Task6: minor (deferred): routineINFO/expectedERROR logs from passing CRUD fixtures; privacybuffercheckremainsvalid.

- Task7: minor (deferred): expectedTLShandshakefixturediagnostics emitted in passing logs.

- Task8: minor (deferred): probe/enqueuecontextexpiryclassifiedgeneric action_error ratherthantimeout duringcleanupreserve.

- Task8: minor (deferred): expectedWARN/fullActions andINFO/Managementfixtureoutput.

- Task9: minor (deferred): expectedtransientERRORfixturelognoise.

- Task12: minor (deferred): duplicateinitialActionlookupStreamEdit.vue18/31.

- Task12: minor (deferred): Vitesinglebundle-sizeadvisory981.86kB/gzip258.57kB(nonfailing).

- Task13: minor (deferred): densesinglelinecredentiallifecycleJS tests/e2e/m20-deploy-cli.mjs196.

- Final: minor (deferred): M1AWSsourceYAMLreadOnlyannotation;M2SSElimitperHandlersinstancewhileguidesaystenant;M3Actionprobe/enqueuetimeoutclass;M4formatting/imports;M5interruptedMySQLmigrationtest;M6duplicateActionlookup;M7bundlesize;M8fixturelogs;M9denseDeployJS. Earlierledgerduplicatesrefertothesamefindingsnotnewones.

The final review consolidates these into M1–M9: read-only schema annotation; SSE quota documentation is per instance in implementation; timeout classification during Action setup; formatting/import grouping; interrupted-0031 migration test coverage; duplicate Action lookup; bundle size; fixture log noise; dense Deploy test JavaScript. The later fix adds interrupted-0032 resume coverage but does not claim interrupted-0031 coverage.
