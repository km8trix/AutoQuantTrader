# A3: genuine forward-capture source bridge

Read-only source investigation, 2026-09-26, against the `autonomous-development` checkout based on `b1156ba`. This is a concrete implementation proposal, not an admission record, provider authorization or claim that its interfaces exist. No credentials, private evidence, provider services or host time services were read or invoked.

## Finding

The missing boundary is a concrete owner that binds the **original** reviewed source evidence, calendar, genuine measured clock and fixed HTTPS transport to one collector episode. It is not an absent HTTP client or a missing matching hash. Current components deliberately stop short of that authority:

- `packages/application/personal_forward_capture.py:550` reads an already committed capture first, then denies every fresh non-synthetic request with `CAPTURE_GENUINE_SOURCE_BRIDGE_REQUIRED`. Existing committed receipts remain replayable after expiry without a new clock, source grant or HTTP call.
- `ForwardSource` and `CaptureVerification` are ordinary immutable declarations. `CaptureVerification.check` validates matching fields/class and allowed/realtime declarations; it does not authenticate the referenced rights, entitlement, currency, identity or clock records. `ForwardCaptureVerifier` and `ForwardCaptureClock` have no concrete genuine producer today; current implementations used by collector tests are fixtures.
- Concrete `TiingoForwardHTTPSGetTransport` and `EtradeForwardCaptureTransport` already bind one exact request, a fixed endpoint, absolute deadline, byte limit and single use. Their `require_original_capture_binding` and `recheck_original_capture` methods add no I/O or authority. The collector does not currently call these additional methods. A result labeled `provider_https_read` alone is not sufficient: constructor/transport identity and the actual source owner must be checked.
- `require_capture_research_calendar_binding` verifies the Tiingo-import `ResearchCalendar` digest convention and selected session. Its tests deliberately show equal copied content passing. Provenance and original-object ownership remain someone else's responsibility.
- `StandardClock` handles offset/uncertainty, UTC/monotonic/epoch, recovery and freshness mathematics. `ChronyStandardTimeSource` is a mechanical adapter over the existing bounded Chrony reader. Its source ID hashes authority configuration, **not** the individual reading's `source_evidence_sha256`; `test_source_identity_binds_authority_configuration_not_per_reading_digest` makes that distinction explicit. There is no concrete capture-clock owner retaining and authenticating that reading.
- `SqlForwardCapturePublication` owns the exact SQL journal graph, original episode and final readback/deadline checks. It does **not** own provider rights, time-source qualification, account risk or an account lease. `SqlContinuousForwardSources` later resolves the fixed-through capture rows/objects outside SQL and rechecks their original rows inside the account transaction. The account coordinator/fence belongs to that downstream boundary. Do not invent a new account lease requirement for standalone raw capture merely because capture uses SQL.

## Existing precedents to retain

| Concern | Current owner/record | Reuse and limitation |
|---|---|---|
| Reviewed Tiingo scope/retention | `TiingoEodAcquisitionProfile`, `TiingoEodCaptureAuthorization.authorize`, owner-import declaration | Bind exact reviewed terms/profile, reviewer/time, instruments/date scope and retention permission. An arbitrary caller setting `rights_status='allowed'` is not equivalent. Existing prior authorization need not be requested again when its actual scope remains valid. |
| E*TRADE environment and session | `EtradeReadOnlySession`, versioned `EtradeSecretReference`, concrete `EtradeHTTPSGetTransport` | Keep scoped store/session/transport and original token issuance/expiry, request budget, nonce and private raw journal behavior. Quote entitlement/account selection is separately established evidence; successful OAuth is not entitlement. No Preview/Place/Cancel calls. |
| HTTP request lifetime | `_BoundRequest`, Tiingo/E*TRADE capture transports | One request, absolute original deadline (maximum three seconds), fixed URL, bounded DNS/TLS/headers/body/cleanup and no automatic retry. Every new attempt gets a new identity; an existing receipt gets no new request. |
| Calendar | `ExchangeCalendar`, `TiingoEodPinnedCalendarArtifact`, import research-calendar projection | Select one already established producer convention; keep complete calendar identity/provenance and original selected/unselected session graph. Matching bytes alone cannot identify the original owner. |
| Health mathematics | `StandardClock`, `ChronyNtsTrustedTimeSource`, `ChronyStandardTimeSource` | Keep current strict equality policies and real measurement identity. Construction must not query/start/configure a service. Chrony uses an ordinary bounded no-shell subprocess runner; no native enrollment needs to be restored for this work. Actual runner/host qualification is still an external gate. |
| In-process ownership | `_CaptureEpisode`/registry, `RuntimeClockSampler` sampled token, SQL resolver owned-result registries | Original object, original graph/methods, bounded input traversal, per-owner registration and rejection of copied/reconstructed tokens. This is an owner-controlled Python-process contract, not a hostile-code sandbox or remote cryptographic attestation. |
| Durable publication | `SqlForwardCapturePublication`, `SqlDurableJournal` | Encode/read raw objects outside SQL; final original-field/scalar-denial and exact prepared-row checks before COMMIT. Keep documented time/COMMIT non-atomicity and lost-acknowledgement recovery. |
| Downstream consumer | `SqlContinuousForwardSources`, continuous closures/account publication | Preserve evidence class, exact fixed-through receipt, original quote side timestamps, close frontier and account fence. New captures cannot refresh prior selected data or unblock old decisions. |

## Proposed narrow contract

Use a new personal capture source-owner adapter/application component under the existing layering. Suggested interface names are descriptive placeholders; do not expose a new launcher or public effecting command as part of the first implementation.

1. **Bind the selection without effects.** A source owner receives the exact `ForwardCaptureRequest`, original `ExchangeCalendar`, read-only retained source-evidence references, a genuine clock owner, the concrete fixed HTTPS transport and existing original SQL publisher/journal/artifact/codec owners. It validates provider/environment/account/instrument/currency/scope and the selected calendar convention before secrets or network. Reference loaders must retain the actual reviewed record and source binding, not accept text references or booleans as proof. Use existing reviewed records where their scope fits; add versioned additive record types for missing quote/clock evidence rather than modifying historical schema meanings.
2. **Keep immutable provenance separate from mutable session operation.** Retain and recheck original request/calendar/source records and behavior-bearing objects/methods. For E*TRADE this includes secret-reference identity, store, concrete transport, journal, clock/monotonic/nonce callbacks and read method ownership. Do not freeze expected mutable session accounting (`_last_activity`, consumed request slots, nonce history) or revert it after GET; explicitly allow only the existing owner-controlled progress. Never put a secret/reference URI or raw provider body in public diagnostics.
3. **Retain a genuine measured-clock observation.** A capture-clock adapter owns the actual local UTC/monotonic/epoch functions and one previously acquired, current `StandardClock` health observation derived from the original qualified source reading. Retain the original per-reading evidence identity and authority separately; do not derive it from the bridge's source ID. Require measured evidence, healthy/recovery-ready state, same epoch/clock domain, source identity and original age/uncertainty bounds. `simulated_health=True`, arbitrary healthy records and `host_unqualified` runtime declarations cannot qualify capture. Warmup/60-second recovery happens before the three-second capture episode. Sampling within the episode may read local scalars; it cannot start a new health warmup, renew the measurement or move the original expiry.
4. **Issue one process-local source token.** The owner registers an uncopyable, nonserializable token tied to that complete original selection and a single episode. Construction and binding are not provider access. The collector may replace its unconditional genuine-class rejection only by consuming a token from the exact concrete owner, preserving absent/forged-token rejection before clock/credentials/HTTP/raw storage. Keep the synthetic path's existing semantics and tests intact. A source token is permission for that bounded read capture, never risk approval, account activation or trade permission.
5. **Use the earliest original expiry throughout.** Eligibility is bounded by the request window, absolute HTTP/process deadline, retained source/rights/entitlement/calendar validity where applicable, clock observation age and existing session token lifecycle. Later rechecks may only narrow those deadlines. The three `CaptureVerification` records refer to the same original source evidence; new sample time never resets evidence age. Resolve/encode/decode/hashes outside SQL. The existing `current_sample` port remains local UTC/monotonic/epoch only, as its protocol requires.
6. **Recheck every handoff without new effects.** Call the transport's original-binding check before dispatch and its consumed-attempt recheck after GET and immediately before publication. Recheck the original source/clock/calendar owners before/after callback boundaries. Integrate a bounded source-owner denial check into the collector's existing final episode recheck so it also runs after SQL lock wait/readback and before COMMIT. No secret resolution, provider call, clock-source subprocess, artifact read or full hash traversal may occur under SQL or after a successful COMMIT.
7. **Preserve existing receipt/replay semantics.** Raw provider bytes remain private and content-addressed; returned success requires exact HTTP identity/class/status/body, normalization, exact retained record and journal readback. Retain `NO_EXECUTION_AUTHORITY`, missing provider sequence/revision and historical-publication limitations. After any ambiguous COMMIT, only the existing exact receipt lookup determines whether publication occurred. Do not rerun HTTP merely because acknowledgment was lost.

The narrow first bridge can collect genuine observations for **offline replay** without changing `ClockProfile`. Current `RuntimeClockSampler.require_current` and operating-evidence projection intentionally admit only `explicit_simulation_time_model`; `host_unqualified` cannot be promoted by the new capture code. A later continuously operating measured-host runtime needs its own additive profile/consumer migration and fault evidence. That is separate from preserving genuine observation times in replay, and from live execution.

## Independently verifiable implementation slices

These are unblocked credential-free engineering tasks under the user's current instruction; no extra permission is needed to implement and test them with synthetic inputs while fresh genuine publication remains denied.

| Slice | Deliverable and acceptance |
|---|---|
| A3.1 — source selection records/validation | Additive bounded reference records and a pure matcher to existing source/calendar/profile/account evidence; explicit missing/unqualified outcomes; constructor effects and secret reads forbidden. Do not manufacture actual qualification fixtures as real evidence. |
| A3.2 — clock evidence ownership | Mechanical capture-clock adapter with retained original measurement and local-only current sampling; test measured-vs-simulated distinction and original expiry. Use injected fixture observations, labeled as tests. Genuine constructor stays unavailable unless qualified concrete source identity exists. |
| A3.3 — original source owner/transport binding | Inert owner/registered-token and callback binding code; tests over original concrete HTTP classes with mocked sockets/secret stores prove mechanics only. Copy, reconstruction, mutation and provider-class promotion reject. |
| A3.4 — collector/publication integration | Replace the genuine guard only for the exact accepted bridge, add final denial checks and preserve all historical retries/synthetic guards. Run existing SQLite and disposable PostgreSQL publication races. No launcher/scheduler, no account initializer and no effecting operation is added. |
| A3.5 — actual qualification | Separately blocked on current reviewed access/window, authentic source/rights/account/quote inputs and qualified host clock environment. Run only after applicable inputs and authorized scope exist; actual captured-session/replay evidence is A4. |

If a previous slice cannot safely produce a genuine owner yet, retain an explicit unavailable result and continue its offline negative/compatibility work; do not pretend the whole bridge is accepted because inert types compile. Update PLAN to distinguish component implementation from actual qualification.

## Acceptance tests

Positive mechanical tests:

- An original fixture-owned selection binds one daily symbol or the exact sorted quote universe and correct environment/account, calendar projection, concrete HTTP request digest and original source evidence. The test never claims a genuine provider qualification.
- One successful mocked concrete request consumes one transport/source token, records actual requested/received/validated clock samples, persists exact raw bytes once and publishes one exact journal record; repeated original lookup returns it with zero new clock/secret/network calls.
- A retained capture reconstructs the same observations and closed-frontier decisions under replay, while keeping provider/fixture class, quoted side times, raw versus adjusted prices and unresolved provenance limitations.
- Existing latest-source selection and exact original-row rechecks pass on SQLite and PostgreSQL, including account-side downstream replay/publication, with no financial/risk/control mutation from capture alone.

Adverse cases (assert zero downstream effects at the appropriate boundary):

1. Missing owner; forged/copy/pickle/reconstructed token; same content from a different publisher/clock/source; foreign thread/owner; reused or consumed token.
2. Mutation/rebinding of request, nested `VersionPin`, selected or unselected calendar session, source reference, underlying concrete transport, Tiingo loader, E*TRADE session/store/journal/reference/clock/nonce/method; equal copies do not restore identity.
3. Missing/denied/expired/wrong-scope rights; no actual quote entitlement; delayed or unknown quote status; wrong environment/account/currency/instrument identity; reviewed record from the future; unsupported calendar convention.
4. Simulated/unavailable/unqualified clock; substituted identical reading; authority ID match with different per-reading evidence; warning/block equality; future/stale measurement; UTC or monotonic regression; boot/epoch change; suspend/wake; loss of original healthy interval. Sampling cannot reset expiry or trigger another source subprocess during publication.
5. First validation, credentials, DNS, TLS, signing, headers/body, normalization, raw publication or SQL lock wait consumes the original bound; equality at deadline/window/proof expiry rejects; later valid proof cannot extend the earliest one.
6. Unreviewed endpoint/redirect, altered digest/body/class, patched injected transport promoted as genuine, oversize/dripping response, malformed quote/product/action, failed cleanup; no successful capture publication.
7. Final-readback mutation, changed journal head, original row tamper, lost COMMIT acknowledgment and rollback. Never repair evidence by overwriting old rows, issue a second GET for the original identity or label an ambiguous result success.
8. Assert no broker order API, risk assignment/control mutation, native service/enrollment, external notification, `.env` discovery or implicit credential lookup from construction/import/replay.

Existing tests to retain and extend include `tests/unit/test_personal_forward_capture.py`, `test_personal_capture_calendar_binding.py`, `test_forward_capture_http.py`, `test_personal_standard_clock_chrony.py`, `test_standard_clock.py`, and `tests/integration/test_personal_forward_capture_publication.py`, `test_personal_forward_capture_journal.py`, `test_continuous_capture_class.py`, plus `tests/unit/test_continuous_capture_data.py`. Confirm exact new test selection in `scripts/run_personal_tests.py`; `test_personal_*` additions are already selected. Use TESTING's sanitized environment and explicit disposable PostgreSQL URL. No test may contact a provider or run a host time service.

## Actual blockers versus decisions

No unresolved product direction or substantial new architecture decision is required to begin A3.1–A3.3: source-owned explicit ports, bounded original lifetimes, owner-reviewed records, standard time health and offline-first integration are already established precedents. Implementing that contract does not require the user to repeat earlier valid permissions.

Actual missing inputs are authentic source/retention/entitlement/account references for the requested capture scope, fresh supervised OAuth/current request window where applicable, and an actually qualified measured-clock/runner/host environment. The read-only audit did not inspect private stores or prove that those inputs are unavailable; the latest status records them as open qualification gates. Resolving them may require owner participation or scoped access, but they do not block pure implementation.

Ask for a consequential choice only if implementation would require departing from precedent—for example accepting local-clock agreement without a measured source, weakening original expiry/identity checks, introducing a new remote signing trust service, changing runtime profile/ownership semantics or deploying an unselected time service/host. None is proposed here. A3's contract can be reviewed and decomposed now; full genuine-source acceptance and A4 remain incomplete until actual evidence exists.

## Implementation findings after the initial proposal

A3.1 now supplies the pure Tiingo selection check, and A3.2a retains the original
Chrony conversion. A3.2b adds historical measured-health ownership under review.
These are mechanical components; none consumes an authentic host qualification or
turns the collector's genuine-class guard into admission.

Further inspection found that a standalone selection/transport owner would mostly
duplicate the existing binding checks before a qualified source producer exists.
Instead, A3.3a repairs a concrete existing transport gap: loader replacement during
callbacks and request/loader/deadline changes during cleanup could still return a
successful Tiingo result. Mock-only adverse tests reproduce those failures.

Scalar currentness rules already have a precedent in `RuntimeClockSampler` (epoch,
one-second sample duration, original snapshot/source age below 30 seconds and
UTC/monotonic agreement). Duplicating those rules in an unused helper would not
complete capture. The next genuine integration needs an identified measured-host
qualification producer and authentic reviewed rights/calendar/source records
resolved from the request's references. No personal measured-host qualification
record/producer or genuine `ForwardCaptureVerifier` exists yet. Historical native
proofs cannot be reinterpreted as that authority.

A3's reviewed-contract/offline-guard scope can therefore close after its focused
regressions and reviews; actual source integration and qualification stay open
under A4. The slices above are a dependency map, not a requirement to create unused
authority classes. Keep genuine admission denied until its actual inputs and
producer contract can be reviewed together.
