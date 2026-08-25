# AutoQuantTrader implementation plan

## Current implementation status

Current gate view: the substantial Phase 0 foundation/walking thread is
implemented locally, but the plan does not mark its complete exit gate passed;
Phase 1's local ingestion and admission mechanics, including the pure fail-closed
production-evidence prerequisite gate, exist while licensed vendor admission
remains open; Phase 2 is the only phase whose exit gate is explicitly passed
locally; Phases 3-6 have bounded local implementations but remain open; and
Phases 7-8 have not started operationally. The runnable product remains a local,
simulation-only browser application. Production Auth0/OIDC server sessions and
an enabled server SSE stream remain Phase 6 hardening work; their contracts and
browser client seams exist, but this status does not claim those production
controls are complete. In addition to the walking thread and safety controls, a
worker-driven recorded JSONL adapter now
publishes deterministic content-addressed raw/normalized Parquet, PostgreSQL
catalog metadata, causal revision selection, security lifecycle, corporate
actions, data quality, quarantine, and functional browser views.

Phase 1B now provides the provider-neutral source seam, strict evidence evaluator,
durable admission reports, and browser visibility. It is **implemented locally
against synthetic contract fixtures; licensed vendor admission remains pending**.
ADR 0011 now narrows the first external implementation to session-defined daily
data because the 2026-07-16 probe found Sharadar SFP and Tiingo EOD sample rows
for DIA, IWM, QQQ, and SPY while Massive raw trades and quotes returned HTTP 403.
The canonical model now supports exchange-session `1d` bars, and the first
strict SFP capture/parser archives provider bytes and preserves their explicit
adjustment bases. Because SFP supplies adjusted OHLCV and only one unadjusted
close, it deliberately cannot emit canonical raw execution bars. Future exact-
page capture requires a reviewed, date-effective authorization artifact with a
terms digest; output is fixed beneath the ignored `.local` tree. Capture
manifests bind the observed response-column schema, and offline datasets bind
the exact bytes to pinned calendar semantics. ADR 0012's safe Tiingo slice is
now implemented as strict offline qualification against repository-owned
synthetic EOD fixtures. It uses a Tiingo-specific raw-candidate basis, binds
provider, dataset, scope, schema, calendar, receipt, and synthetic evidence kind
into deterministic identity, and refuses canonical-bar or admission-evidence
conversion. It deliberately precedes and does not authorize exact-page capture
or supply a production `HistoricalBarSource`. The later exact scope-specific
retention/research approval is recorded below; publication/vintage semantics
and production market-provenance, identity, lifecycle, corporate-action, and
admission qualification remain open.
ADRs 0013-0015 add a Tiingo-specific authorization-gated acquisition seam,
portable pinned-calendar approval, immutable publication, and descriptor-safe
offline verification. Their mechanics remain extensively synthetic-tested. On
2026-07-17, one bounded provider-backed operation passed the exact profile,
retention/research authorization, and calendar gates and captured the completed
2026-01-02 session for DIA, IWM, QQQ, and SPY. The credential-free verifier then
validated the immutable tree, manifest and object hashes, strict schema, exact
session coverage, and four research rows. The ignored owner-only capture is a
research baseline only; no response bytes are checked into Git, and admission
and trading effects remain `none`.

ADR 0016 now implements receipt-time local delivery lineage for two or more
complete independently verified captures. Synthetic repeated-capture tests prove
first observation, presentation-insensitive unchanged delivery, row-local
economic change, A -> B -> A reversion, chronology, exact profile/calendar
compatibility, and incomplete-capture rejection. The proof-constructed result
does not invent vendor publication or revision time and refuses canonical bars,
admission evidence, and `HistoricalBarSource`. Only one actual capture exists, so
genuine provider repeat behavior remains unobserved until a fresh external
operator decision permits a second capture under the same exact still-applicable
profile, authorization, and calendar artifacts and that capture is performed
and verified. V1 lineage does not support artifact rotation.

ADR 0017 now implements a separate single-snapshot exact-retained field-contract
qualification. It independently replays strict source field names against
frozen row targets and roles, then returns only a value-free proof with kind
`exact_retained_field_contract_only`. The existing actual baseline has
completed that boundary for four rows across one session and fifty-two field
occurrences; ADR 0017 records the value-free contract and qualification digests.
Unprefixed OHLCV remains
`documented_raw_candidate`; the result refuses genuine-raw, canonical,
corporate-action, source, admission, and trading authority.
Emitted `source_schema_constraint_id` values are frozen source-schema policy
labels; their raw, adjusted, or ex-date wording is not semantics inferred from
observed values.

ADR 0018 now defines and implements a separate offline security-identity and
lifecycle contract-only boundary. It binds one exact verified snapshot, its
exact ADR 0017 proof, and a strict canonical identity/lifecycle artifact. The
trade-enabled scope is exactly DIA, IWM, QQQ, and SPY; a separate synthetic,
non-trade-enabled corpus exercises a ticker change and delisting. The profile's
identifier-authority string remains a label rather than evidence, and lifecycle
instants do not confer calendar authority. The bounded contract permits exactly
four trade IDs and two pairwise-isolated lifecycle IDs, rejects cross-aliasing,
and requires identifier and included-universe continuity across each exact
pinned session through the downstream close-time resolution instant. The
implemented fail-closed artifact template and credential-free operator command
make no provider request or write and emit one generic value-free failure
message. No production identity/lifecycle artifact has passed, so every
production-identity, raw, corporate-action, source, admission, and trading
effect remains `none`.

ADR 0019 now defines and implements the next offline market-semantics and
action-candidate contract-only boundary. It revalidates the exact verified
snapshot, ADR 0017 retained-field proof, ADR 0018 identity/lifecycle proof, and
canonical semantics artifact. The contract freezes structured provenance, the
exact one-plus-five-plus-five-plus-two partition of all thirteen fields, and
fixed `divCash` and `splitFactor` candidate conventions. Five isolated synthetic
cases cover neutral, dividend, forward split, reverse split, and simultaneous
candidates without inferring an event, event absence, or unavailable timestamps.
The template and operator path make no provider request or write. Its
adjustment-methodology, admission, canonical-bar, corporate-action, correction,
genuine-raw, historical-source, market-provenance, trading, and
vendor-publication effects all remain `none`, and the actual baseline has not
passed this boundary.

ADR 0020 now begins Phase 2A without declaring the externally gated Phase 1
admission work complete. The pure domain core has a UTC monotonic simulated
clock, a documented availability-first total order, and explicit watermarks
that cannot regress in event time when read in canonical closed order. Replay
proof-constructs complete MarketBatch values, globally binds source/observation
identities to revision chains, and uses compact context-independent decimal
semantics and typed Phase 2 identifiers. Strategy contexts bind an exact batch
identity and digest, target tuples are immutable/sorted/unique, and
`ReplayResult.complete_batch_ids` names strategy-eligible proofs. The Phase 0
walking thread now uses that canonical batch callback. ADR 0021 connects
repository-owned fixture manifests through a content-verified all-revision
tape and can atomically seal successful reducer evidence with exact dataset,
plan, engine, and runtime pins. This still does not create a production
`HistoricalBarSource`, usable economic backtest, mutable job, API command/read
model, browser workflow, or reference benchmark. ADR 0022 completes the planned
synthetic Phase 2A callback/state boundary with explicit UTC clock schedules,
typed market/clock triggers, bounded immutable digest-chained strategy state,
captured strategy configuration/runtime pins, fully hashed targets, and an
in-memory deterministic strategy transcript. It
does not reinterpret ADR 0021 evidence or add durable strategy jobs, and
admission and trading readiness remain unchanged. ADR 0023 begins Phase 2B with
causal portfolio snapshots and canonical target-to-intent batches while
preserving complete strategy configuration, trigger, target, and price evidence.
ADR 0024 adds the canonical submission/cancel/broker-event/execution-correction
lifecycle reducer without adding effects or authority. ADR 0025 adds balanced
append-only cash-flow and execution/correction postings with exact cash,
security-unit, trade-value, and fee projections. ADR 0026 selects long-only FIFO
trade-date lots, immediate fee expense, and explicit
causal marks to project cost basis, realized/unrealized P&L, exposure, and equity.
ADR 0027 adds source-bound execution settlement instructions and confirmations,
explicit receivables/payables, and conservative settled/available cash.
ADR 0028 adds stable source-bound split/dividend facts, dual entitlement
reconciliation, whole-share FIFO basis preservation, post-split mark gating,
and separate dividend accrual/payment postings. ADR 0029 adds a provider-neutral
`BrokerPort` and a conservative source-bound simulator for explicit regular-
hours sessions, including shortened half-days, and whole-share DAY market
orders: it consumes an exact current single-use approval,
accepts deterministically, and considers only the first sealed slice strictly
after activation. That slice can full-fill only when complete and is never
skipped for a later complete slice. Pricing uses explicit adverse price and fee
inputs. ADR 0030 adds process-local atomic intent-batch decisions and conservative cash,
share, notional, and exposure reservations against exact causal portfolio,
account, settlement, session, policy, and control evidence. Approved nonempty
batches create one parent decision and sorted one-shot child authorizations;
rejected batches create no hold, and exact retries cannot reserve twice.
ADR 0031 adds the process-local account coordinator boundary: authority-owned
time and policy, renewable exact leases, monotonically increasing fencing
generations, clean-release evidence, fail-closed abandoned expiry, and a broker
wrapper that holds the account transition lock across the exact submission
call. ADR 0032 completes the local Phase 2B durable execution boundary with SQL
lease revisions and heads, gap-free predecessor-bound renewal history, trusted-
clock transaction-time fence rechecks, atomic batch-risk
facts bound to the exact authenticated remaining-capacity universe,
deterministic logical orders and one-shot authorization consumption,
append-only submission attempts, proven-unsent stale-`PENDING` abandonment,
UNKNOWN recovery-to-freeze, predecessor-ordered canonical-ledger accounting,
sticky non-monotone correction freezes, and the durable expiry/rejection/
accounted-execution plus typed simulation-horizon release paths. Every persisted
`RESOLVED` attempt and generic reconciled-terminal fact
remains fail closed pending the real Phase 4 reconciliation producer. ADR 0033
completes the local Phase 2C research workflow with an immutable strategy/
configuration/fixture catalog, idempotent audited jobs, bounded recoverable
worker claims with rotating exact tokens, a process-unique golden fixture
worker, immutable reports and manifests, a
loopback-scoped signed launch capability plus CSRF, and browser
Strategies/Backtests views.

Phase 2 is therefore **complete locally against repository-owned deterministic
fixtures**. Its golden run proves raw-price buy/split/dividend/sell economics,
same-bar exclusion, future-correction causality, and exact repeated identity;
SQL integration tests cover parallel reservation and job-claim exclusion,
gap-free lease renewal and legacy-safe upgrade, atomic preparation and rollback,
exact remaining-capacity projection, stale-`PENDING` abandonment, UNKNOWN
recovery, lifecycle freeze/release conservation, predecessor-ordered
canonical-ledger binding, authenticated local
simulation-horizon finality, rejection of unsupported external finality facts,
correction freezes, and corruption fail-closed reads.
This completion does not qualify a vendor feed or enable broker execution.

ADR 0034 begins Phase 3A without claiming the broader Phase 3 gate. The bounded
domain slice defines one `rolling_close_mean` artifact whose repository adapter
authenticates the source tape, dataset manifest, and sealed replay-run manifest.
It fixes `lookback=2`, explicit publication lag, and `SKIP_AND_RESET` gap
semantics. Causal feature snapshots bind their complete market batches and
ordered source observations. Full-sequence batch selection and incremental
per-instrument state must produce exactly the same canonical snapshot sequence
before a parity receipt can be proof-constructed. At that Phase 3A boundary,
persistence, decision-time availability enforcement, API/CLI and browser
integration, experiment and holdout governance, captured live tapes, shadow
replay, fitted features, and target parity remained pending.

ADR 0035 implements the bounded Phase 3B consumer boundary against the same
certified feature evidence. Complete batch decisions see only the latest
post-reset snapshot per expected instrument with
`snapshot.available_at <= trigger.as_of`;
incomplete batches clear visible and delayed pending state. A versioned
close-versus-mean reference rule emits no target while evidence is incomplete.
Independent full-sequence-index and incremental visibility reducers must agree
on every reset, waiting context, feature identity, and target before a manifest-,
artifact-, feature-receipt-, and strategy-bound target-parity receipt can exist.
The exercised tape remains a repository-owned synthetic fixture, so parity on
a captured tape and the broader Phase 3 gates remain pending.

ADR 0036 implements the bounded Phase 3C governance boundary without treating
the Phase 2 fixture runner as a segment-aware experiment engine. Experiment
families declare non-overlapping train, validation, and final-test segments;
train and validation evidence is segment-scoped, while the final test remains
an opaque commitment before an audited reveal. Stable attempts retain
append-only lifecycle events, unsuccessful attempts still consume the frozen
pre-holdout budget, and only an exact completed validation configuration may be
selected. A typed reveal authorization binds the family, holdout commitment,
criteria, selected configuration, and exact pre-reveal registry head; the
audited reveal is the first object allowed to retain the exact
certificate-derived test-evidence receipt. A global tape-role ledger permits
exploratory reuse while preventing exploratory/holdout crossover. The pure
registry is retained in authenticated SQL facts and exposed for read-only
inspection. It adds no experiment mutation API or segment execution path.

ADR 0037 implements the bounded Phase 3D reference evaluation boundary. Segment
and final-holdout inputs now bind configuration-neutral feature certification;
an exact attempt configuration must reproduce the target policy in a
parity-certified target replay before the same recorded running-worker actor
can complete the attempt. The durable completion receipt binds the
configuration, source evidence, runtime, target transcript digest, counts, and
recorded actor-identifier continuity, and is exposed only as allowlisted
read-only proof. It is not
a P&L report, promotion decision, general segment runner, or trading authority.

ADR 0117 implements the bounded Phase 3F durable fixture-segment worker. One
exact queued governed attempt can retain its content-addressed feature
transcript, acquire a rotating bounded physical-worker claim, reproduce the
attempt configuration's target parity, and atomically publish the target
transcript with the existing Phase 3D completion receipt. A deterministic
logical governed actor preserves receipt continuity while expired physical
claims can be replaced without allowing stale publication. Exact retries are
idempotent; changed attempt, actor, configuration, segment, certification, or
terminal evidence conflicts. Final-test input remains inaccessible before the
audited reveal. This repository-fixture path adds no economic report,
captured-tape eligibility, provider I/O, promotion, deployment, source,
admission, or trading authority.

ADR 0038 begins Phase 4A with an offline, non-authorizing Alpaca paper
capability contract. The reviewed contract freezes the paper endpoint and
authentication-header names, provider breadth, a narrow local request shape,
client-ID and pagination constraints, a closed lifecycle classification, and
the currently documented request ceiling. It deterministically describes
whole-share simple market `DAY` buy/sell shapes for candidate DIA, IWM, QQQ, and
SPY mappings with `extended_hours=false`. It does not prove asset tradability,
the exact exchange session, or that a sell is reduce-only; it reads no
credential, performs no network I/O, consumes no broker state, and grants no
paper authority.

ADR 0039 implements Phase 4B as a bounded offline client-order lookup
observation contract. A lookup description is bound to the exact Phase 4A
submission description and deterministic client order ID. Bounded retained 200
and 404 bytes are decoded through a versioned local accepted wire profile with
duplicate-key rejection, nanosecond-preserving timestamps, raw digests, and a
provider request ID. A 200 is either a request-economics match or a retained
reconciliation mismatch; neither validates asset identity or tradability. A 404
is always temporarily not visible and inconclusive regardless of its bounded
code/message values. The found fixture is documentation-derived synthetic
evidence, while the 404 body is explicitly unqualified synthetic evidence;
neither is an authenticated provider capture. No outcome resolves an `UNKNOWN`
attempt, creates an execution, performs I/O, or grants broker authority.

ADR 0040 implements Phase 4C as a bounded durable pre-decode broker-ingress
slice. Exact response bytes, byte count, digest, and allowlisted versioned
transport metadata commit before any provider decoding, with a 1 MiB body
bound. A stable delivery idempotency key makes exact retry safe and
changed-content reuse a conflict. New receipts form an independent contiguous
account-local predecessor-digest chain under the existing account transition
lock and atomically advance a durable terminal head, without a local-order or
submission-attempt foreign key. The Alpaca lookup wrapper persists first and
decodes second, so malformed, empty, and schema-drift responses remain durable.
This slice intentionally defines no
normalized fact, quarantine receipt, application receipt, lifecycle mutation,
`UNKNOWN` resolution, reconciliation, transport, credential, or trading
authority.

ADR 0041 implements Phase 4D as bounded durable broker-request admission.
Every immutable permit burns one slot in an inclusive account-local rolling
window before a future request, uses exact-retry demand idempotency, joins a
predecessor-linked sequence, and advances a terminal head under the existing
account transition lock. The initial Alpaca paper policy stops submissions at
160 permits, UNKNOWN lookup at 180, and preserves the reviewed 200-per-minute
ceiling for cancellation/reconciliation; permits are fresh for three seconds
and remain accounted through expiry plus the 60-second provider window, for a
63-second local horizon. Expiry never refunds capacity. The policy is local
fail-closed configuration, not a claim about undocumented provider reset
semantics. No network path is yet forced through a permit, so runtime budget
enforcement, transport, credentials, reconciliation, and trading authority
remain disabled.

Exact retry remains a lookup/idempotency operation; a network-capable path must
use the repository's new-only issuance operation and reject an already
admitted demand before transport. A crash after allocation therefore loses
capacity conservatively, and retry consumes a new demand identity unless a
later durable effect protocol can prove a prior outcome safe to reuse.

ADR 0042 implements Phase 4E as bounded offline Alpaca account and candidate
asset observations. Deterministic `GET /v2/account` and
`GET /v2/assets/{symbol}` descriptions bind the Phase 4A capability digest,
paper provenance, local account alias, and exact fixed candidate mapping.
Strict bounded response profiles retain exact bytes, digests, provider request
IDs, provider UUIDs, account status/blockers, and asset identity/tradability
while rejecting duplicate keys, schema drift, malformed types, and mismatches.
The current model/enums are pinned to an exact official SDK commit; retired
PDT/day-trade fields remain legacy-only, and unknown exchanges/attributes fail
closed. The Phase 4C wrappers commit raw bytes before decoding. Balances and
options fields are not canonical economics, synthetic examples bind no
authenticated account or security master, and even a locally usable
account/asset outcome is neither fresh runtime evidence nor authority. No
normalized fact or migration is added; transport, credentials, reconciliation,
dispatch, and every readiness gate remain disabled.

ADR 0043 implements Phase 4F as a bounded offline dispatch-preflight evidence
binder. One immutable assessment cross-binds the canonical attempt and supplied
parent snapshot, exact Alpaca request, risk session, remaining child
reservation, stable fence receipt, raw-first account/asset observations, and
exact submission demand and request permit. The budget correlation is derived
from the preparation and request-description digests instead of accepting a
caller-selected readiness claim. Immutable conflicts reject; expected temporal
or operational defects remain ordered fail-closed findings. The assessment
cannot authenticate its pure snapshots as current durable state and exposes the
entire frozen runtime-gate set as unresolved. It performs no persistence,
credential resolution, lifecycle transition, or transport, and grants no
mark-in-flight, coordinator-dispatch, paper-startup, or trading authority.

ADR 0044 implements Phase 4G as a bounded authenticated account-read runtime.
Nonsecret configuration pins a local alias to an expected provider UUID and
immutable paper secret reference/version. An injected trusted resolver supplies
an opaque credential envelope; internal closable redacted bytes are consumed
only by the exact account-read boundary. The `observe_account` demand consumes
protected reconciliation capacity through new-only issuance and receives a
durable freshness receipt before strict TLS/no-redirect/no-proxy
`GET /v2/account` transport. An exact admitted demand is rejected before a
second send. HTTPX
connect, pool, read, and write inactivity waits are each bounded at two seconds
without claiming an end-to-end deadline. The same stable fence is validated
before and after the request. Completed in-bound raw entity bytes with trusted
receive/record times and representable metadata are persisted before decoding;
invalid optional metadata becomes absent. Only a usable, timely response with a
matching provider UUID appends the secret-free account-local binding chain. No
concrete secret-store deployment or API/worker/trader/startup composition is
enabled, and the binding grants no account-economics, security, reconciliation,
submission, or trading authority.

ADR 0045 implements Phase 4H as one authenticated exact-candidate asset read.
The fixed instrument/symbol is independently pinned to an expected provider
asset UUID and the exact current Phase 4G account binding. A newly admitted
reconciliation request, stable fence, bounded raw-first transport, strict
decoder, and shared-lock source recheck produce a five-second append-only asset
binding only for an eligible matching response. It is receipt-scoped security
identity and tradability evidence, not a general security master, quote,
position, reduce-only, reconciliation, or order authority.

ADR 0046 implements Phase 4I as one authenticated historical client-order
lookup for an exact durable UNKNOWN attempt. The request consumes protected
UNKNOWN capacity and rechecks the UNKNOWN head, terminal provider-account
identity continuity, and current recovery fence before and after raw-first
transport. A matching provider asset UUID preserves the strict observation
outcome; a null or different UUID is a typed reconciliation-blocking mismatch.
The durable receipt cannot resolve, resubmit, mutate, or release the attempt.

ADR 0047 implements Phase 4J as a bounded durable schedule around Phase 4I.
One plan binds the exact `IN_FLIGHT` and terminal `UNKNOWN` events and the
original dispatch-plus-60-second deadline. Six one-shot local eligibility
offsets follow the UNKNOWN commit; late polls coalesce older due slots, every
issued slot derives new request/delivery identities, and crash or raw-only
failure burns that slot. Match, mismatch, 404, and deadline exhaustion change
only the scheduler classification. Every path leaves the submission UNKNOWN
and all trading and reconciliation authority disabled.

ADR 0048 implements Phase 4K as durable normalized historical reconciliation
evidence for an exact Phase 4I lookup. The workflow reauthenticates the Phase
4I receipt and its Phase 4C raw source, re-decodes the retained bytes, and
appends a predecessor-linked fact with one candidate, quarantine, or
inconclusive disposition. It preserves precise provider Order values while
refusing to infer provider revision order, executions, fees, lifecycle
application, UNKNOWN resolution, or reconciliation completion.

ADR 0049 implements Phase 4L as source-scoped broker-inbox admission for one
exact Phase 4K fact. A frozen identity profile preserves the complete Phase 4K
payload/digest and raw/lookup lineage without collapsing separate lookup
sources. Durable normalized requests and predecessor-linked account-local
source links are paired with an explicit fixed-policy non-application receipt:
matched evidence is withheld for an unqualified revision identity, mismatches
remain quarantined, and a qualified 404 remains inconclusive. No disposition
can create or apply an order event, execution, correction, reconciliation
result, readiness state, or trading effect.

ADR 0050 implements Phase 4M as a bounded, raw-first Alpaca order-page
contract. One immutable non-I/O plan describes at most eight descending
`GET /v2/orders` pages. Each later `before_order_id` is derived from the exact
preceding full page, each page derives a distinct reconciliation demand, and
representable bytes enter the Phase 4C journal before strict decoding. A short
page proves only non-isolated cursor exhaustion; a full eighth page is bounded
truncation. The slice allocates no permit, performs no transport, and grants no
snapshot, revision, deduplication, execution, lifecycle, reconciliation,
readiness, or trading authority.

ADR 0051 implements Phase 4N as a bounded pure comparison of two exact Phase
4M captures. It accepts only distinct ended sources with the same account and
traversal profile, disjoint ingress receipts, and strict source sequence. A
fixed two-second observed UTC interval qualifies the pair for a difference or
match disposition. Page-boundary-independent sorted provider-order ID and
order-digest views yield exact added, removed, and changed IDs.
Safety-truncated inputs remain incomplete, too-close inputs remain waiting, and
an exact match remains explicitly unqualified with `converged=false`. The slice
adds no persistence, runtime, request, permit, transport, readiness,
reconciliation, or trading authority.

Massive remains the deferred intraday data candidate, and Phase 1 vendor
admission remains open. The pure production-evidence prerequisite gate can reach
only `ready_for_admission_evaluation`; it creates neither a production
`HistoricalBarSource` nor admission evidence. No licensed production feed,
admitted production source, or paper/live trading authority exists; the trader
remains `not_ready`.

Phases 3A-3D provide bounded local feature, target, governance, and
configuration-bound evaluation evidence. Phase 3E implements a separate pure
fail-closed captured-tape validity gate, but v1 has no external provenance trust
root or verifier, so no bundle can become eligible. Captured live-tape,
reconnect, shadow, economic segment-execution/isolation, end-to-end traceability,
and reporting gates remain open.

Phases 4A-4AI are implemented as bounded local historical Alpaca contracts,
persistence, authenticated read runtimes, comparisons, and restart-safe
supervision. They remain non-authorizing: authoritative broker-fact application,
reconciliation, coordinator dispatch, paper startup, and the Phase 4 fault gates
are incomplete. E\*TRADE is the selected live target. Phase 4AJ adds only its
typed environment, scope, account-identifier, and deterministic non-I/O Accounts
List request-description foundation; Phase 4AK adds only bounded in-memory
raw-first caller-declared response evidence and a strict historical decoder.
Those bindings prove internal consistency only: provider origin is
unauthenticated, fixture relabeling cannot be detected, and no authenticated
provider-evidence consumer exists. Phase 4AL adds only deterministic OAuth
1.0a/HMAC-SHA1 signing and a secret-free pure supervised-session reducer over
typed nonsecret reference revisions and caller-injected timestamp/nonce values.
It adds no resolver, durable replay guard, authenticated token response,
browser/OOB runtime, provider transport or call, or authority. Authenticated
capture/admission and account binding, Balance, Portfolio, Orders, and
Transactions reads, Preview, Place, Cancel, recovery, qualification, and every
authority remain pending.

Phase 5A-5I provide local operational-control, advanced-risk,
supervised-strategy, critical-alert, authenticated-operations, dashboard,
drill-evidence, and historical enrollment-attestation slices;
OpenTelemetry/Sentry composition remains partial. Phase 5 stays open because
authoritative deployment producers, account assignment, broker control,
external alert routes, telemetry ingestion, runtime sandboxing, and timed
deployed drills remain absent.

Phase 6A and 6B provide local trusted-time persistence and browser bundle
admission. Phase 6C has one qualified point-in-time Cloudflare/System76 window.
Phase 6D has confirmed the separately approved sequence-1 external-head
enrollment and implements the post-enrollment start controller/orchestrator in
code, but no start has been operationally admitted. ADR 0111/0112 now
reauthenticate and cross-bind the exact decision-artifact receipt and historical
start chain into the dormant operation-bound clean-stop supervisor bridge, but
its host/core private entry points still have zero callers. ADR 0116 freezes only
the design-only transport → same-lock admission → lifecycle-v2 composition and
its distinct pre-effect and post-teardown reauthentication order; none of that
chain is implemented or authorized. Current-topology and stop-authority
admission, durability, outcomes, and all effects remain absent;
`trusted-time-stop` remains hard closed. Phase 6E is only a dormant watchdog-
state reducer. The Phase 6 paper-MVP gate remains unmet, and the Phase 7
supervised paper soak and Phase 8 human-approved minimum-size live canary remain
entirely ahead. No paper or live order authority is enabled.

## Delivery strategy

Build a narrow, safety-complete vertical slice before adding breadth. Each phase
ends with an executable artifact and a hard acceptance gate. The first execution
slice is intentionally limited to one operator, one trade-enabled strategy, one
brokerage account, a small liquid ETF allow-list, regular market hours, whole
shares, and DAY market orders.

Calendar estimate: 16-20 weeks for one experienced full-time engineer to reach a
credible paper-trading MVP, assuming vendor/broker onboarding is straightforward.
This is followed by an evidence-based paper soak with a minimum 4-8 week calendar
window. Strategy profitability is not schedulable and is never inferred from
paper fills.

Four evidence layers remain distinct:

1. **Backtest:** research robustness and economic plausibility under declared
   assumptions.
2. **Replay/shadow:** causal correctness and offline/online decision parity.
3. **Paper:** broker workflow, recovery, reconciliation, controls, and operations.
4. **Minimum-size live canary:** actual routing, liquidity, latency, and execution
   behavior.

Passing one layer cannot substitute for another.

## Phase 0 - decisions, skeleton, walking thread, and browser shell (week 1)

### Build

- Confirm the ETF universe, 1-minute-or-slower frequency, regular-hours session,
  long-only/whole-share/DAY-market-order scope, broker, data entitlement, account
  type, and deployment environment.
- Record ADRs for temporal semantics, raw/adjusted data, security identity,
  ledger/accounting, engine build-versus-adopt, broker capability/recovery,
  account lease/fencing, experiment governance, and live authority.
- Create the Python and React/Vite workspaces, PostgreSQL migrations,
  configuration, structured logs, health endpoints, quality tooling, Docker
  Compose, and CI.
- Scaffold the desktop-browser shell, permanent environment banner, routing,
  Auth0/session contracts, generated API types, resumable SSE client, error
  boundaries, and deterministic development fixtures.
- Establish dependency rules: synchronous pure domain core, application ports,
  infrastructure adapters, and thin composition roots.
- Implement a one-symbol walking thread from a fixed market tape through a no-op
  or buy-and-hold strategy, mandatory risk decision, simulated submission, fill,
  balanced ledger entry, position projection, and browser overview trace.
- Define measurable budgets for data age, strategy deadline, approval TTL, clock
  drift, submission uncertainty, reconciliation, alert delivery, and a reference
  backtest workload. The initial conservative values and change controls are in
  [Operational budgets](OPERATIONAL_BUDGETS.md). Values may be tuned later, but
  they cannot be undefined.

### Exit gate

- A clean checkout runs formatting, typing, unit tests, migration checks, API,
  worker, trader stub, and browser application with one documented command.
- The walking thread is visible and causally traceable in the browser.
- The walking thread proves the planned dependency direction and event shape.
- Execution has no code path that omits a persisted risk decision.
- Paper and live configuration/credential schemas are structurally distinct.
- Open architectural decisions that affect Phase 1 are resolved, not deferred.

## Phase 1 - point-in-time data plane (weeks 2-3)

### Current Phase 1A implementation

- Complete locally: provider-neutral recorded source, canonical raw bars,
  availability-time revisions, stable fixture security IDs, effective-dated
  ticker/tradability/universe facts, pinned DST/half-day calendar fixtures,
  strict corporate actions, deterministic Parquet, atomic manifests, quality
  quarantine, manifest-pinned causal reads, APIs, worker, and browser views.
- Proven locally: identical re-ingestion is idempotent; shuffled rows produce
  identical checksums; a correction available at 09:32 is invisible at 09:31;
  adjusted values cannot satisfy the raw execution bar; ticker change,
  delisting, DST, half-day, missing-session, split, and dividend fixtures are
  covered by tests.
- Newly complete: session-defined daily interval validation, immutable bounded
  SFP page/manifest capture behind reviewed storage authorization, fixed local
  output, cursor and digest verification, observed response-column schema
  binding, pinned-calendar semantic binding, per-symbol/session coverage,
  explicit adjusted field semantics, and a hard block against mapping mixed SFP
  fields to raw execution bars.
- Newly complete: an offline Tiingo EOD contract parser and synthetic
  qualification corpus covering strict schema and numeric bounds, documented-
  raw-candidate versus adjusted separation, split/dividend fields, exact
  symbol/session coverage, receipt-time knowledge, and scope/calendar-bound
  deterministic identity. Results are permanently `synthetic_contract_only`
  and fail closed on canonical-bar and admission-evidence conversion. This
  slice performs no network capture, makes no live-payload claim, and cannot
  implement or satisfy the production `HistoricalBarSource` contract.
- Newly complete: an authorization-gated Tiingo acquisition seam whose explicit
  profile approval, matching rights authorization, bounded request count and
  response size, finite per-request socket-I/O timeout, secret-safe metadata,
  owner-only staging, exclusive final-name reservation, and atomic publication
  are synthetic-tested and have been exercised by one bounded authorized
  provider-backed capture. Every later request remains independently gated. The
  operation makes no admission, trading, publication-time, historical-vintage,
  or vendor-correction claim.
- Newly complete: a separate offline Tiingo final-capture verifier that accepts
  only a strict final name beneath the fixed repository root, uses no-follow
  descriptor traversal, binds the name to the full canonical manifest, requires
  the exact reviewed authorization and expected acquisition profile, checks and
  finally revalidates the exact immutable root/name/inode/tree and content digests,
  revalidates schema and coverage against the exact reviewed portable
  pinned-calendar artifact, and proof-constructs a deterministic research-only
  snapshot. It is synthetic-tested and has verified the one actual retained
  capture. A single-snapshot result still refuses lineage, canonical conversion,
  admission evidence, and source integration.
- Newly complete: a strict portable pinned-calendar artifact whose reviewed
  scope, profile digest, authority, attested tzdata-version label, per-symbol calendar
  identity, and explicit UTC sessions are causally validated before capture.
  Its exact digest is committed to the v2 manifest and required by the v2
  research proof. A credential-free operator verifier reads owner-only local
  artifacts, emits only secret-free proof metadata, and has no write, admission,
  or trading effect. The checked-in template remains non-authorizing; the actual
  approved artifact is bounded to the one captured scope and remains ignored.
- Newly complete: an in-memory, credential-free receipt-lineage boundary and
  operator command for two or more exact final captures. It preserves every
  occurrence, creates a new linked local version only when one row's normalized
  economics change, and rejects missing/extra coverage without carry-forward or
  tombstones. The first actual capture is only a baseline; repeated behavior is
  currently proven with synthetic complete captures.
- Newly complete: a separate in-memory, credential-free retained-field boundary
  and operator command for one exact verified capture. It replays all thirteen
  frozen source fields into their explicit session-identity, documented-raw-
  candidate, adjusted-research, or corporate-action-candidate roles and emits a
  value-free `exact_retained_field_contract_only` proof. The existing actual
  baseline has completed the boundary for four observations and rows, one
  session, and fifty-two field occurrences with all effects `none`; ADR 0017
  records the exact public digests.
- Newly complete: a strict offline identity/lifecycle contract-only boundary
  that revalidates one exact snapshot and its ADR 0017 retained-field proof
  against canonical artifact bytes. It requires the exact DIA, IWM, QQQ, and SPY
  trade scope and keeps a synthetic ticker-change/delisting corpus separately
  non-trade-enabled. It tests stable identity, effective-dated aliases, causal
  knowledge, ambiguity rejection, and delisting behavior without treating the
  profile authority label or lifecycle instants as evidence. No production
  identity/lifecycle artifact has passed, and the boundary cannot produce a
  production security master, source, admission evidence, or trading effect.
- Newly complete: a strict offline market-semantics and action-candidate
  contract-only boundary that revalidates the exact snapshot, retained-field
  proof, and identity/lifecycle proof against canonical artifact bytes. It
  freezes structured provenance, the exact thirteen-field role partition, and
  fixed cash-dividend and split-candidate conventions. Five repository-owned
  cases exercise neutral, dividend, forward-split, reverse-split, and combined
  candidates without inferring action existence, absence, announcement,
  publication, availability, payable, or revision timestamps. No production
  semantics/action artifact has passed, and the boundary cannot produce raw or
  canonical bars, corporate-action records, a source, admission evidence, or a
  trading effect. Adjustment-methodology, admission, canonical-bar,
  corporate-action, correction, genuine-raw, historical-source,
  market-provenance, trading, and vendor-publication effects all remain `none`.
- Still required for the Phase 1 exit gate: obtain a fresh external operator
  decision for any second provider capture needed for real repeat evidence,
  perform it under the same exact still-applicable profile, authorization, and
  calendar artifacts required by the v1 lineage command, and verify it. V1 does
  not support artifact rotation. Also verify the frozen DIA, IWM, QQQ, and SPY
  allow-list plus an independently authorized non-tradable lifecycle corpus,
  finish production identifier/lifecycle, calendar, and action authority
  qualification, and obtain independent evidence that the documented raw
  candidates are genuinely unadjusted and
  execution-safe or validate a reconstruction, and implement the resulting
  `HistoricalBarSource`, and run the admission suite against licensed payloads.
  Synthetic tests and research captures cannot satisfy this gate.

### Current Phase 1B admission implementation

- Complete locally: provider-neutral historical-source bundles, strict source-ID
  isolation, adapter/profile metadata, frozen coverage and symbol requirements,
  deterministic admission specifications and evidence, independent-review
  semantics, immutable PostgreSQL reports/checks, and browser admission status.
- Newly complete: a pure pre-source production-evidence prerequisite gate that
  inventories exact production identity/lifecycle, calendar, corporate-action,
  genuine-raw/provenance, license/use-rights/current-entitlement, and independent
  exact-bundle-review references. It rejects missing or duplicate roles,
  synthetic/research/fixture/contract-only classifications, source/profile/scope
  mismatches, rejected, future, or expired evidence, stale or substituted
  reviews, and review by the executor or any evidence producer. Its strongest
  result is only `ready_for_admission_evaluation`; historical-source,
  canonical-data, admission, and trading effects remain `none`. It performs no
  I/O, authenticates no external actor, creates no source or admission evidence,
  and adds no persistent state or migration.
- Proven locally: mixed-source rows fail before storage; fixture profiles cannot
  claim a license; synthetic and recorded fixtures remain `blocked` regardless
  of their technical results; source/specification/evidence/report digests are
  deterministic; missing, duplicate, unknown, temporally impossible, or
  self-approved evidence fails closed.
- Still external: choose and license the actual vendor product, freeze the
  production ETF allow-list and identifier/calendar authorities, implement its
  adapter, supply legally usable payloads, and obtain an independent approval.
  Until then no admission report can be `admitted` and Phase 1 remains open.

### Build

- Stable security IDs with effective-dated ticker, venue, tradability, listing,
  delisting, and point-in-time universe membership.
- Canonical market event fields: event/interval time, vendor publication,
  receipt, availability, ingestion, source sequence, schema, and revision.
- Immutable raw and normalized Parquet partitions in content-addressed local
  storage; PostgreSQL stores ordered manifests, metadata, jobs, and quality
  results. Cloud object storage is an adapter, not a Phase 1 dependency.
- Historical vendor adapter, exchange calendars, session labels, watermark and
  late-event policy, corrections, quarantine, and idempotent publication.
- Explicit split, dividend, merger, symbol-change, and delisting events. Keep raw
  execution series separate from adjusted research views.
- Data contracts and checks for gaps, duplicates, OHLC validity, staleness,
  extreme returns, inconsistent revisions, and timezone/session errors.
- Browser views for ingestion jobs, manifests, security lifecycle, corporate
  actions, feed entitlement, quarantine, and data-quality issues.

### Exit gate

- Re-ingesting identical input produces the same partition checksums and no
  duplicate facts; a revised vendor record creates a new revision.
- A correction available at 09:32 is invisible to a 09:31 simulated decision.
- Dataset manifests reproduce the exact ordered partitions, calendar, universe,
  corporate-action version, schema, and first-seen/revised policy.
- Fixtures cover DST, half days, missing sessions, split/dividend accounting,
  ticker changes, and at least one delisted security.
- Adjusted values cannot flow into execution or ledger APIs by construction.

## Phase 2 - canonical engine, ledger, order reducer, and minimum risk (locally complete)

### Sequencing and current status

- **Phase 2A replay core — locally complete:** deterministic simulated time,
  availability ordering, watermark-complete batches, causal revision selection,
  exact decimal and identifier contracts, immutable target tuples, manifest-
  pinned all-revision replay, sealed run evidence, explicit market/clock
  callbacks, and predecessor-linked strategy state are implemented and tested
  against repository fixtures. SQL-bound decimals must be exactly representable
  as `NUMERIC(28,10)`; Phase 2 ledger postings additionally must round-trip
  exactly through SQLite's ten-place numeric transport so fixture and PostgreSQL
  persistence authenticate identical economics. This phase does not claim a
  licensed production source.
- **Phase 2B execution state — locally complete:** causal portfolio snapshots,
  canonical intent batches, order/execution/correction and balanced-ledger
  reducers, FIFO account economics, settlement, split/dividend accounting, and
  the conservative next-event simulated broker compose one deterministic
  execution path. ADR 0032 adds durable SQL coordinator leases/fences,
  all-or-none batch-risk publication, exact logical-order and authorization
  consumption, append-only submission attempts, stale `PENDING` abandonment,
  stale in-flight recovery, UNKNOWN parent freezes, monotone expiry/rejection/
  accounted-execution releases, typed deterministic simulation-horizon finality,
  and non-monotone correction freezes. Each batch decision binds the exact
  authenticated remaining-capacity universe: partial and frozen children
  retain only their remaining holds, while fully released children are omitted.
  A gap-free per-account observation sequence orders approved, rejected, and
  no-action decisions so equal timestamps cannot make historical capacity
  completeness ambiguous. Every capacity-affecting submission, order, and
  release fact serializes on the same account head and authenticates the
  observation watermark after which it is visible, so release and observation
  reconstruction uses the same prefix as the writer rather than timestamp
  tie-breaking. The additive upgrade retains v3 decisions and marker-zero legacy
  mutations while all new facts use the v4 ordering contract. Lease generations
  and renewal revisions are both gap-free, every renewal names its exact
  predecessor digest, and
  transaction-time revalidation samples the trusted coordinator clock under the
  SQL lock. The additive schema upgrade preserves authenticated legacy lease
  identities while every new lease revision uses the chained contract.
  Stale `PENDING` recovery records proven-unsent `ABANDONED`; dispatch requires
  a fresh receipt for the prepared stable fence and current lease revision.
  Expiry release reauthenticates the complete causally visible attempt snapshot,
  requires every target attempt to be abandoned, and rejects any visible
  `UNKNOWN` sibling without treating later sibling activity as historical.
  UNKNOWN remains frozen. Every persisted `RESOLVED` attempt and generic
  reconciled-terminal fact deliberately fails closed until Phase 4 supplies a
  real broker reconciliation producer. Exact retries and relational conflicts
  fail closed. Execution corrections require exact cumulative predecessor
  coverage before a positive delta can release; any canonical historical
  downward or equal-quantity correction makes the freeze sticky. Stale or
  skipped revision chains are rejected as malformed and fail readiness if
  injected below the relational boundary. Exact correction economics complete
  the append-only execution-revision ledger chain, but unresolved correction
  provenance quarantines new batch authorization for the account. A correction
  discovered after terminal release preserves the authenticated released
  projection while the same quarantine remains in force. Simulation dispatch
  commits the exact replay manifest, calendar, instrument universe, model,
  request, and attempt chain before `IN_FLIGHT`, and typed horizon
  reconstruction authenticates all of them plus the proof/release recording
  instant.
- **Phase 2C durable research workflow — locally complete:** ADR 0033 adds the
  immutable golden strategy/configuration/fixture catalog, idempotent audited
  launches, append-only jobs with bounded and recoverable worker claims, exact
  rotating claim tokens bound to the latest `RUNNING` event, process-unique
  worker identities, the continuously polling fixture worker, immutable
  report/run-manifest storage, loopback-scoped signed API launch capability,
  durable query views, and the browser Strategies and Backtests workspaces.
  Arbitrary strategy code, parameters,
  datasets, date ranges, and licensed vendor history remain out of scope.

### Build

- Simulated clock and deterministic ordering over availability-time events are
  implemented.
- Proof-constructed watermark-complete `MarketBatch`, exact batch-bound
  read-only causal strategy context, immutable canonical target tuples, clock
  callbacks, versioned strategy state, target portfolio, and target expiry are
  implemented.
- Append-only balanced ledger for fills, fees, cash flows, dividends, splits,
  settlement, marks, and realized P&L is implemented; cash/position/P&L remain
  projections.
- Portfolio valuation and full target-to-intent-batch conversion for one active
  strategy are implemented.
- Canonical intent, risk, submission, broker-order, cancel, execution, and
  correction reducers are implemented. The simulated broker is the first
  `BrokerPort`; a future live adapter must reuse these reducers.
- Conservative next-event DAY market-order simulation is implemented for
  close-only, full-fill-or-working evidence. Add bar-based limit scenarios later
  only as explicitly ambiguous stress models.
- Atomic risk decision/reservation is implemented in memory and SQL for
  instrument/session, stale price, quantity, notional, conservative cash,
  long-only shares, account exposure, duplicates, pending order exposure, pause,
  and halt. A nonempty approval is versioned, all-or-none, and bound to the
  exact authenticated active-capacity payload and digest; each exact member
  authorization is single-use and expires. Partially released and frozen
  children reserve their exact remainder, and fully released children cease to
  consume capacity. A monotone account observation sequence makes every stored
  universe historically reconstructable even across equal decision timestamps.
  Submission, order, and release mutations share the account lock and carry an
  authenticated visible-after observation marker; decision `N` includes exactly
  the mutation prefix below `N`.
  The durable runtime releases for proven-unsent expiry, exact broker rejection,
  execution bound to exact canonical-ledger economics, or the typed local
  simulation-horizon proof described below. Generic
  reconciled-terminal evidence remains gated.
- Local `SIMULATION_HORIZON_FINAL` replays the persisted exact events and
  watermarks, reproduces the sealed replay manifest, reruns
  `ConservativeSimulatedBroker` from the persisted session, model, submission,
  authorization, pinned calendar and instrument universe, and complete safe-
  retry attempt evidence, and requires the reconstructed result, order, and
  final event and proof/release recording instant to equal their durable facts.
  Before residual release, every final execution head must be completely covered
  by exact canonical-ledger `EXECUTION_ACCOUNTED` evidence; a sealed zero-fill order
  requires none. Unaccounted or stale corrections remain frozen.
- Account-scoped coordinator leases, immutable predecessor-bound revisions,
  monotonically increasing fences, transaction-internal trusted-clock rechecks,
  legacy-safe additive upgrade, and clean release are durable.
  Automated expired-lease takeover and paper/live broker effects remain gated.
- Immutable strategy/configuration/fixture selection, authenticated idempotent
  launch, job progress/history, report metrics and equity, trade trace,
  ledger/position evidence, and provenance views are implemented in the local
  API and browser.

### Exit gate — passed locally against deterministic fixtures

- The golden raw-price run starts with USD 1,000, buys four shares at USD 101.07
  with USD 0.54 fee, applies a 2:1 split and USD 10 dividend, sells eight shares
  at USD 54.93 with USD 0.58 fee, and reconciles to USD 1,044.04 ending equity
  and USD 1,034.04 settled/available trade cash.
- Golden tests prove a decision cannot fill from the same bar, shifting a future
  correction cannot alter earlier targets/orders or final economics, and an
  exact repeat produces identical decisions, orders, ledger, metrics, report,
  and run identity.
- Reducer and lifecycle invariant suites cover balanced postings, cash/share
  conservation, one-shot authorization consumption, cumulative fills, late
  fills, predecessor-ordered monotone corrections, and sticky fail-closed
  historical correction freezes.
- SQL concurrency tests prove parallel intent batches cannot reserve the same
  cash and parallel workers cannot claim the same job; expired job claims
  advance to a new attempt, rotate exact claim authority, and reject stale
  completion even when a worker label is reused.
- Submission integration tests prove current durable approval and fence binding,
  atomic logical-order/consumption/PENDING preparation, complete rollback on an
  injected failure, stable-fence renewal with an exact dispatch receipt,
  proven-unsent `ABANDONED` recovery, UNKNOWN recovery/freezing, and fail-closed
  rejection of unauthenticated reconciliation. Risk/lifecycle tests cover exact
  partial and frozen remaining capacity, released-child omission including
  equal-time release/observation ordering across both serialization orders,
  causal proven-unsent expiry evidence, canonical ledger economics,
  deterministic simulation-horizon reconstruction, and strict corruption
  rejection. Readiness rejects every persisted `RESOLVED` attempt
  and generic reconciled-terminal release while accepting only the typed local
  simulation-horizon proof.
- API/worker/workflow tests prove local session plus CSRF and idempotency gates,
  immutable catalog pin validation, one launch audit fact, golden report/
  manifest binding, and fail-closed report corruption. Browser tests cover the
  Strategies and Backtests launch/progress/report surfaces.
- These gates authorize deterministic local research only. Licensed external
  history, paper/live broker adapters, real broker reconciliation, automatic
  coordinator takeover, operator re-arm, and the Phase 4 activation gate remain
  incomplete.

## Phase 3 - research validity, live tape, shadow replay, and research UI (weeks 7-9)

### Sequencing and current status

- **Phase 3A bounded feature parity — first pure slice implemented:** ADR 0034
  defines one immutable `rolling_close_mean` artifact bound to an authenticated
  source tape, content-addressed dataset manifest, and sealed replay-run
  manifest. The reference feature has `lookback=2`, an artifact-bound
  publication lag, and `SKIP_AND_RESET` semantics: an incomplete or skipped
  batch emits no snapshot, clears history for every expected instrument, and
  requires two new complete observations. Causal snapshots bind the artifact,
  manifest, complete market batch, ordered source observations, value, and
  timing. Separate batch and incremental reducers use separate window-selection
  paths and must agree exactly before a manifest/artifact-bound parity receipt
  can exist. The snapshot `available_at` contract is recorded.
- **Phase 3B bounded causal target parity — pure slice implemented:** ADR 0035
  consumes only exact Phase 3A certification. At each complete batch trigger it
  exposes the latest snapshot per expected instrument from the current
  post-reset epoch only when `snapshot.available_at <= trigger.as_of`.
  Incomplete batches
  clear both visible and delayed pending features; missing evidence produces an
  explicit `WAITING` step and no target. Independent full-sequence-index and
  authenticated incremental visibility paths feed one versioned close-versus-
  mean whole-share target rule and must agree exactly before a feature- and
  strategy-bound target-parity receipt can exist. Intent conversion continues
  to use causal market prices, never the feature value.
- **Phase 3C bounded experiment governance — durable registry implemented:**
  ADR 0036 separates stable attempts from their append-only lifecycle events,
  retains unsuccessful attempts in the frozen budget, and allows only an exact
  completed validation configuration to be selected for final-test access.
  Train and validation evidence is segment-scoped; the final test is only an
  opaque commitment before a typed reveal authorization binds the exact
  pre-reveal registry head. A global tape-role ledger allows exploratory tape
  reuse while preventing any exploratory/holdout role crossover and reserving
  each holdout tape to one family. Canonical tape policies, family claims,
  families, attempts, events, reveal, and audit facts are durably authenticated
  and available through read-only inspection.
- **Phase 3D configuration-bound segment evaluation — bounded reference path
  implemented:** segment and holdout inputs are configuration-neutral feature
  evidence. A running attempt's exact `long_quantity` and
  `target_lifetime_seconds` configuration must reproduce a successful target
  parity certification before the same recorded actor may complete it. The
  immutable receipt binds configuration/schema validation, segment input,
  target runtime and result digests, counts, running event, times, and
  evaluator. Read-only views expose proof metadata only; no transcript contents,
  performance metric, criteria decision, or promotion is produced.
- **Phase 3E captured-tape research validity — pure fail-closed gate
  implemented:** ADR 0114 composes the exact Wave 1A production-prerequisite
  inputs with a separately recomputed admitted-source report, content-addressed
  capture/dataset/tape and replay/runtime/configuration evidence, causal
  half-open validity windows, and independent review of the exact combined
  bundle. Synthetic, recorded-fixture, generic-research, contract-only,
  mutable, mismatched, stale, context-replayed, or self-approved evidence fails
  closed. Vendor labeling and content hashes cannot authenticate origin. V1 has
  no external trust root or verifier, so every result retains exactly one
  authenticated-provenance blocker and no repository-local or external-shaped
  input can reach positive eligibility. Every source, admission, canonical-data,
  promotion, deployment, and trading effect remains `none`.
- **Phase 3F durable fixture-segment execution — bounded worker implemented:**
  ADR 0117 connects one exact Phase 3A certification to its queued Phase 3C/D
  attempt through immutable transcript artifacts, append-only job history,
  renewable/expired-claim-safe physical worker tokens, and one stable logical
  governed actor. Target artifact, governed completion receipt, terminal job
  event, and head advance commit atomically; crashes publish none of them.
  Enqueue retries lock and reload the current job/governance state and remain
  exact from running or terminal lifecycles; terminal retries are likewise
  idempotent. Changed input conflicts, corruption fails closed, and final-test
  evidence is admitted only after its audited reveal.
- **Phase 3G authenticated fixture provenance — bounded read views
  implemented:** ADR 0119 adds a query-only SQL boundary and GET-only job list
  and detail routes. Every returned job, supplied cursor, and list lookahead is
  authenticated through its artifacts, full event/head chain, complete
  governance/audit history, attempt, status, and completion linkage. The
  verifier requires exact cross-ledger lifecycle shape: queued job/event
  identity, every physical running claim, and terminal status/time/receipt must
  match their governed attempt facts without extras or gaps; failed jobs must
  also carry the one fixed governed non-executable reason, detail, and semantic
  identity. Feature artifact fields/counts are cross-bound to reconstructed
  segment evidence, and successful target fields/counts are cross-bound to the
  governed evaluation receipt. Ordered feature and target step tuples must
  independently reproduce the governed transcript/result/certification roots.
  Output cardinality is governed but ordered output members lack an independent
  governed root, so output members and identities whose only anchor is the
  stored artifact payload are excluded from the public claim. Jobs use
  deterministic keyset pages of at most 100 and retain only constant-size
  summary DTOs; details authenticate all events while exposing reverse-
  chronological sequence pages of at most 100. Frozen
  allowlisted records expose only independently authenticated opaque job,
  governance, certification, transcript, parity, completion, and context
  digests; counts; lifecycle ordinals/status; and safe timestamps. Artifact/
  payload identities, event/predecessor/artifact-link identities, transcript
  payloads and members, holdout identities/material, configuration values,
  caller-controlled labels, terminal detail, economic results, criteria, and
  promotion decisions remain structurally absent.
- Phase 3A and 3B evidence remains limited to repository-owned synthetic
  fixtures, Phase 3F/3G deliberately do not reuse the Phase 2 economic backtest
  worker, and Phase 3E has no qualified external captured-tape input. General
  segment execution and process/resource isolation, arbitrary or fitted
  features and strategies, mutation APIs, performance/criteria evaluation,
  captured live tapes, reconnect/freshness behavior, and shadow mode remain
  pending. Phase 3 is not complete and its exit gate has not passed.

### Build

- A bounded versioned feature-artifact contract is implemented for the
  manifest-bound `rolling_close_mean` reference feature, including source
  lineage, `lookback=2`, publication lag, and `SKIP_AND_RESET`. General feature
  artifacts, fitted training windows, and immutable fitted state remain pending.
- Exact full-sequence batch and authenticated incremental differential parity is
  implemented for that pure reference feature and repository-owned manifest
  evidence.
- Availability-gated full-sequence-index and incremental target parity is
  implemented for one exact Phase 3A certification and bounded reference
  target rule,
  including explicit waiting/reset steps and exact decision-feature lineage.
  Captured-tape feature/target parity and research workflow integration remain
  pending.
- A pure captured-tape validity gate now checks current exact production
  prerequisites, a separate recomputed `admitted` source decision, immutable
  source/capture/dataset/tape/replay/runtime/configuration pins, causal
  currentness, and a structurally independent exact-bundle review. It rejects
  every v1 candidate because the repository has no externally anchored capture-
  origin verifier; adding a positive path requires a separately reviewed trust
  root, issuer-authentication contract, and issuer-independence rules. It does
  not create or load a source, accept existing fixtures, or connect validity to
  segment execution.
- A durable bounded experiment registry records every stable attempted, failed,
  canceled, abandoned, and completed trial through append-only lifecycle
  evidence. The bounded reference completion path now requires exact
  configuration-derived target-parity evidence and running actor-identifier
  continuity.
  The bounded repository-fixture worker now schedules one exact attempt with
  rotating physical claims, immutable feature/target transcript artifacts, and
  atomic governed completion. Its job and transcript proof metadata is
  available through deterministic bounded authenticated read pages without
  exposing transcript members or caller-controlled labels. General scheduling,
  arbitrary execution, subprocess isolation, and resource quotas remain
  pending.
- Chronological and nested walk-forward evaluation, purging/embargo for
  overlapping labels, benchmark/cost stress, parameter stability, uncertainty,
  and declared multiple-testing treatment.
- A typed, audited final-holdout reveal is bound to frozen criteria, one
  completed validation configuration, the opaque holdout commitment, and the
  exact pre-reveal registry head. The selected configuration can produce one
  post-reveal bounded target-evaluation receipt; economic segment execution and
  isolation remain pending.
- A live market-data adapter with feed-entitlement metadata, quote/NBBO support,
  per-symbol freshness, gap backfill, reconnect watermarking, and captured event
  tapes. Run the candidate in shadow mode without any broker submission.
- Broader CLI- and browser-accessible economic/performance reports, experiment
  comparison, feature lineage, captured-tape playback, feed freshness, and
  replay-versus-shadow views. Phase 3G supplies only fixture job/transcript
  proof metadata through the API.

### Exit gate

Status: **open**. The Phase 3A and 3B reference slices supply exact local
feature-snapshot and feature-derived target parity evidence, and Phase 3C
supplies a durable bounded governance registry and opaque pre-reveal holdout
commitment. Phase 3D binds that target parity to an exact governed
configuration and running attempt. Phase 3E now freezes the fail-closed
captured-tape evidence prerequisite, but v1 cannot qualify any bundle until a
separately reviewed external provenance verifier exists.
Phase 3F durably executes only the repository fixture's configuration-bound
target-parity segment and publishes no economic result or promotion decision.
Phase 3G makes that job's bounded authenticated proof metadata queryable but
does not expose transcript members or add an economic or criteria view.
These slices do not satisfy the
captured-tape, reconnect, economic segment-execution/isolation, end-to-end
traceability, or reporting requirements below.

- Batch and incremental features/targets agree on the same captured tape.
- A reconnect backlog cannot emit one fresh intent per stale bar; expired targets
  are discarded and audited.
- Any trade can be traced to its availability-time inputs, feature artifacts,
  target, risk snapshot, code/image digest, and configuration.
- Parameter sweeps cannot inspect the final holdout or mutate shared run state.
- Reports label exploration, validation, and confirmation evidence and declare
  return, annualization, benchmark, cash-flow, cost, and uncertainty conventions.

## Phase 4 - broker execution qualification, recovery, and trading UI (weeks 10-12)

### Sequencing and current status

- **E\*TRADE live-broker target — architecture selected, implementation
  pending:** ADR 0096 selects E\*TRADE production as the intended live execution
  venue. E\*TRADE sandbox is protocol-only stored sample data and cannot satisfy
  paper-soak, lifecycle, reconciliation, timing, rejection, fill, slippage, or
  economic gates. The selection grants no credential access, account binding,
  broker call, or trading authority. Existing Alpaca Phase 4A-4AI artifacts
  remain immutable historical, paper-provider-specific, and non-authorizing;
  they must not be renamed or reinterpreted as E\*TRADE or live qualification.
- **Phase 4A offline Alpaca paper contract — local slice implemented:** ADR 0038
  records the reviewed paper endpoint and authentication-header names,
  documented provider order/TIF breadth, the candidate DIA/IWM/QQQ/SPY
  instrument mapping, client-order-ID and pagination constraints, a closed
  conservative status classifier, and the currently documented
  200-request-per-minute account ceiling. The local compiler produces only an
  intent-bound whole-share simple market `DAY` buy/sell shape with
  `extended_hours=false`; current tradability, exact-session, and reduce-only
  sell proof remain mandatory future gates.
- **Phase 4B offline client-order observations — local slice implemented:** ADR
  0039 binds a deterministic lookup description to the exact Phase 4A request
  and decodes bounded retained 200/404 bytes through a reviewed local wire
  profile. Matching request economics, same-ID mismatches, and temporarily
  not-visible 404 responses remain distinct.
  Provider timestamps preserve nanoseconds, and REST cumulative fills cannot
  become canonical executions or resolve `UNKNOWN`.
- **Phase 4C durable pre-decode ingress — local slice implemented:** ADR 0040
  commits exact bodies up to 1 MiB and allowlisted versioned transport metadata
  before provider decoding. Stable delivery idempotency and an independent,
  predecessor-linked account-local sequence plus terminal head are serialized
  under the existing account transition lock. The Alpaca lookup wrapper
  persists before decoding, including when empty, malformed, or schema-drift
  bytes make decoding fail. Receipts deliberately have no local-order or
  submission-attempt foreign key.
- **Phase 4D durable request-budget admission — local slice implemented:** ADR
  0041 adds immutable account-local broker request permits under the same SQL
  serialization boundary. A conservative rolling window, stable demand
  idempotency, progressively protected submission/recovery/critical ceilings,
  predecessor-linked permit history, and a terminal head make concurrent
  admission restart-safe. Issued capacity is never refunded because a crash
  cannot prove that an external request was unsent.
- **Phase 4E offline account/asset observations — local slice implemented:**
  ADR 0042 adds deterministic non-I/O account and exact candidate-asset
  descriptions, strict bounded response profiles, explicit fail-closed
  outcomes, and raw-first Phase 4C wrappers. Account balances remain
  noncanonical, and documentation-derived or unqualified synthetic fixtures
  establish neither provider-account identity nor current security readiness.
- **Phase 4F offline dispatch-preflight evidence binder — local slice
  implemented:** ADR 0043 cross-binds one canonical attempt and supplied parent
  snapshot, exact Alpaca request, risk session and active child capacity,
  stable fence receipt, raw-first account/asset observations, and exact
  submission demand/permit. Expected stale, blocked, or unavailable conditions
  remain closed findings, while immutable identity conflicts reject. The
  assessment enumerates every unresolved runtime gate and cannot transition the
  attempt or authorize transport.
- **Phase 4G authenticated paper account binding — local slice implemented:**
  ADR 0044 adds one bounded authenticated `GET /v2/account` runtime.
  Nonsecret configuration pins the local alias to an expected provider UUID and
  immutable paper secret reference/version. The flow resolves credentials
  ephemerally, durably reauthenticates a protected reconciliation permit,
  validates the same fence before and after strict TLS/no-redirect/no-proxy
  transport, persists completed in-bound raw entity bytes and representable
  metadata before decoding when trusted receive/record times are available,
  and appends a short-lived secret-free account-binding chain. HTTPX's
  two-second connect/pool/read/write inactivity bounds are not an end-to-end
  deadline. No deployed resolver or API/worker/trader/startup composition is
  enabled.
- **Phase 4H authenticated paper asset binding — local slice implemented:** ADR
  0045 adds one bounded authenticated exact-candidate
  `GET /v2/assets/{symbol}` runtime. A secret-free reference pins the fixed
  local instrument/symbol to an independently operator/review-pinned provider
  asset UUID. The flow requires the exact Phase 4G binding to remain the fresh
  durable terminal account fact before and after strict raw-first transport,
  consumes a new protected reconciliation permit, preserves the same stable
  fence, and appends a source-bound five-second asset-binding chain per account
  and instrument. No general security-master publication or deployed
  composition is enabled.
- **Phase 4I authenticated client-order lookup — local slice implemented:** ADR
  0046 adds one protected raw-first
  `GET /v2/orders:by_client_order_id` for an exact durable attempt whose current
  terminal event is `UNKNOWN` immediately before send and again after the raw
  response. The same terminal Phase 4G provider-account identity anchor and
  current recovery fence must authenticate across transport; the account
  continuity receipt does not claim its earlier status window is fresh. A 200
  compares the independent security-reference provider asset UUID, retaining a
  typed reconciliation-blocking mismatch when the UUID is null or canonically
  different. No current asset binding or present tradability is required for
  the historical observation. Qualified results are immutable historical
  receipts, while 404 remains inconclusive and no result can resolve, resubmit,
  or mutate the attempt.
- **Phase 4J durable bounded UNKNOWN lookup schedule — local slice
  implemented:** ADR 0047 binds one immutable plan to the exact durable
  `IN_FLIGHT` dispatch and terminal `UNKNOWN` event. Six one-shot local
  eligibility offsets at 1, 2, 4, 8, 16, and 32 seconds after the UNKNOWN
  commit are clipped strictly before the original dispatch's 60-second
  deadline. Durable slot consumption is serialized under the account lock,
  late polls coalesce missed slots instead of creating a restart burst, and
  each selected slot derives a new Phase 4I request/delivery identity.
  Matched evidence stops only the scheduler for reconciliation, mismatch blocks
  it, 404 waits for another slot, and deadline exhaustion leaves the attempt
  `UNKNOWN`.
- **Phase 4K durable normalized lookup reconciliation evidence — local slice
  implemented:** ADR 0048 reloads and reauthenticates an exact Phase 4I lookup
  receipt and its Phase 4C raw source, re-decodes the retained bytes, and
  appends one immutable historical fact under an account-local predecessor
  chain. Matching Order evidence remains a non-applying candidate; request
  economics and security-identity mismatches are quarantined; and a qualified
  404 remains inconclusive. Provider timestamps and cumulative values retain
  their exact precision, but neither local append order nor `updated_at` is
  provider revision authority and no execution is inferred.
- **Phase 4L source-scoped broker inbox admission — local slice implemented:**
  ADR 0049 maps one exact authenticated Phase 4K fact to a versioned historical
  observation identity and normalized inbox request. The identity is scoped to
  the source fact and digest, so identical values from separate lookups remain
  separate. Durable normalized requests retain the exact Phase 4K
  payload/digest and lookup/raw lineage; account-local source links form a
  predecessor chain and terminal head; and an explicit fixed-policy receipt
  records only withheld, quarantined, or inconclusive non-application.
- **Phase 4M bounded raw-first order-page contract — local slice implemented:**
  ADR 0050 freezes one non-I/O descending `GET /v2/orders` profile. An immutable
  capture has at most eight pages; each later page derives `before_order_id`
  from its exact full predecessor and a distinct reconciliation demand. Exact
  response bytes commit through Phase 4C before strict Phase 4B-profile
  decoding. A short page ends only the non-isolated cursor chain and a full
  eighth page is bounded truncation. No permit, authenticated transport,
  durable restart workflow, snapshot isolation, fact application, convergence,
  or trading authority is introduced.
- **Phase 4N bounded non-authorizing order-snapshot comparison — local slice
  implemented:** ADR 0051 compares two distinct ended Phase 4M captures only
  when they share an account and traversal profile, use disjoint raw receipts,
  and have strict source order. It flattens page boundaries into sorted provider
  order ID and order-digest views and reports exact added, removed, and changed
  IDs. A safety-truncated source is incomplete, a source pair observed less
  than two seconds apart remains waiting, and an exact qualified match remains
  unqualified with `converged=false`. It adds no persistence, runtime,
  readiness, reconciliation, or authority.
- **Phase 4O authenticated durable order-snapshot page runtime — local slice
  implemented:** ADR 0052 prepares and commits exactly one Phase 4M page per
  call. The SQL plan and head authenticate the exact next cursor and
  predecessor before credentials or request admission; each page consumes one
  fresh reconciliation permit and preserves the current fence and terminal
  Phase 4G provider-account identity across strict raw-first transport.
  The first durable preparation is a single-use claim, so overlapping calls or
  any crash after preparation fail before resend and conservatively stall that
  capture. Committed receipts reconstruct a contiguous prefix. Cursor
  exhaustion remains non-isolated, bounded truncation remains incomplete, and
  no convergence, reconciliation, readiness, or trading authority is added.
- **Phase 4P durable authenticated order-view comparison — local slice
  implemented:** ADR 0053 reloads two exact terminal Phase 4O prefixes,
  reauthenticates their complete durable source positions, and recomputes the
  Phase 4N comparison. Immutable receipts bind both capture and terminal-page
  identities and digests, views, differences, disposition, commit fence, and
  an account-local predecessor/head chain. Exact retry is idempotent and
  substitutions, forks, rollback, or orphans fail closed. Cursor-exhausted
  equality remains unqualified, bounded truncation remains incomplete, and no
  provider I/O, convergence, application, readiness, or trading authority is
  added.
- **Phase 4Q bounded restart-safe order-view supervision — local slice
  implemented:** ADR 0054 derives one deterministic action from an ordered pair
  of authenticated Phase 4O durable states. An invocation can execute at most
  one exact next page, wait without I/O before the later traversal's fixed
  scheduling boundary, or invoke Phase 4P after both prefixes end. It reloads
  both states after a page and accepts only exact one-page append-only
  advancement with the other state unchanged. The later prefix's authenticated
  first-page preparation, request-start, and receive times must all meet the
  same boundary before that prefix can be adopted. A stalled state fails before
  the executor; there is no loop, sleep, automatic resend, convergence claim,
  deployed worker, or new authority.
- **Phase 4R bounded raw-first position view — local slice implemented:** ADR
  0055 freezes one non-I/O `GET /v2/positions` description and commits every
  representable response through Phase 4C before strict decoding. The reviewed
  USD U.S.-equity profile caps a response at 512 objects and one mebibyte,
  preserves exact decimal lexemes, rejects duplicate provider asset or symbol
  identities and profile drift, and never truncates overflow. Empty and
  non-empty arrays alike remain historical, non-isolated observations with no
  canonical-position, convergence, application, readiness, broker-call, or
  trading authority.
- **Phase 4S bounded non-authorizing position-view comparison — local slice
  implemented:** ADR 0056 compares two distinct, source-ordered Phase 4R
  captures for one account and profile. It builds sorted provider-asset-ID and
  exact-position-digest views, reports added, removed, and changed IDs, and
  waits until a two-second local receive interval has elapsed. Raw array order
  and JSON formatting do not affect the view, exact decimal lexemes remain
  semantic, and even a separated exact match is unqualified with
  `converged=false`.
- **Phase 4T authenticated single-use position-view runtime — local contract
  implemented:** ADR 0057 binds one Phase 4R capture to the exact credential
  reference and terminal Phase 4G provider-account identity. A fresh durable
  preparation must precede secrets, capacity, and strict raw-first transport;
  stalled, completed, overlapping, or restarted use fails before those
  effects. One reconciliation permit and a stable account fence surround the
  request, and the recorder must independently revalidate that fence in its
  commit transaction before exact reload. The contract adds no retry, concrete
  SQL repository, canonical position, convergence, readiness, or trading
  authority.
- **Phase 4U durable single-use position-snapshot persistence — local slice
  implemented:** ADR 0058 makes one immutable SQL plan row the fresh-only
  claim and permits at most one exact immutable receipt. No plan is unclaimed,
  a plan without a receipt is permanently stalled, and an exact receipt is
  complete. Stable capture/account-key uniqueness, account-lock
  serialization, exact binding/permit/raw/fence source authentication,
  transaction-internal fence revalidation, full reconstruction and readiness
  verification, and nonempty downgrade refusal preserve Phase 4T's no-resend
  rule across restart.
- **Phase 4V durable authenticated position-view comparison — local slice
  implemented:** ADR 0059 reloads two exact Phase 4U receipts for the same
  local and pinned provider account identities and recomputes Phase 4S
  internally. Immutable receipts bind both source positions, signed timing,
  views, differences, disposition, commit fence, and an account-local
  predecessor/head chain. Exact retry reauthenticates the current call without
  rewriting its historical receipt; equality remains unqualified.
- **Phase 4W bounded restart-safe position-view supervision — local slice
  implemented:** ADR 0060 derives one action from two exact Phase 4U states.
  One invocation executes at most one earlier or later Phase 4T capture, waits
  without I/O before the fixed two-second boundary, or invokes Phase 4V after
  both sources complete. Stalled states initially loaded fail before effects;
  a concurrent unselected mutation is rejected after the bounded selected
  read, while durable pair-wide compare-and-swap remains pending. All ports
  identify the same process-local durable store, and reloaded state plus
  authenticated later preparation/request/receive timing prove the exact
  selected transition. There is no loop, sleep, retry, deployed scheduler, or
  new authority.
- **Phase 4X durable position-pair transition admission — local slice
  implemented:** ADR 0061 registers two globally unique role memberships and
  an eligible role claim under the shared account lock. Ordinary Phase 4U
  preparation rejects either registered member. Pair-aware preparation
  consumes the exact same-lease claim while inserting the unchanged Phase 4U
  plan in one transaction, followed by exact readback and a final fence check.
  The loser of the direct-prepare versus pair-registration race performs no
  second effect. Claim retry is historical; consumption, lease renewal, or
  takeover never creates fresh preparation authority. Provider I/O and
  Phase 4W execution remain outside this admission-only slice.
- **Phase 4Y pair-admitted position-view runtime composition — local slice
  implemented:** ADR 0062 composes Phase 4X through the unchanged Phase 4T
  runtime and bounded Phase 4W selector without holding a transaction across
  provider I/O. Every W/V source load requires exact role claim/consumption
  history; direct Phase 4U receipts and absent-but-consumed corruption fail
  before effects. A selected role is claimed before Phase 4T, then narrow
  snapshot and coordinator adapters atomically consume the canonical Phase 4U
  preparation and require the exact claim policy, lease digest, and expiry
  through pre/post/final/commit evidence. One call performs at most one
  capture, wait, or comparison. Crash-after-consumption remains stalled, and
  the distinct non-authorizing result binds unchanged W/T/U evidence to its X
  history.
- **Phase 4Z coherent process-local order-view supervision wiring — local
  slice implemented:** ADR 0063 advances Phase 4Q to contract and policy
  version 2. Its Phase 4O state loader and one-page workflow plus its Phase 4P
  comparison repository must expose one exact positive process-local
  durable-store identity before source loading, clock access, or any page or
  comparison effect. The O/P SQL repositories expose the identity of their
  exact shared SQLAlchemy engine; the opaque value is never canonical
  evidence. Split-store composition now fails before request capacity or
  provider I/O, while same-store ordered-pair and per-page admission remain
  pending.
- **Phase 4AA durable order-pair per-page transition admission — local slice
  implemented:** ADR 0064 defines an immutable earlier/later pair, gap-free
  exact-next-page claims, one-to-one preparation consumptions, and same-lease
  crash proofs. Revision 0024 normalizes and forward-backfills every completed
  or stalled Phase 4O preparation, adds globally unique pair members, durable
  claims, and atomic consumptions, and guards downgrade once non-derived
  history exists. Public Phase 4O preparation rejects registered plans under
  the shared account lock; reads and startup readiness reconstruct every
  source, predecessor, fence, preparation, and consumption.
- **Phase 4AB pair-admitted order-view runtime composition — local slice
  implemented:** ADR 0065 composes Phase 4AA through the unchanged Phase
  4Q/4O/4P path. A pair-authenticating loader requires every committed page to
  resolve to its exact ordered role claim, consumption, unchanged preparation,
  receipt, and page-local lease. The one-page workflow claims the exact prefix
  and source-head digest cached from Q selection, consumes it through a
  claim-bound Phase 4O adapter, and pins its lease through the unchanged
  credential, budget, raw-first transport, commit, and reload path. Every
  later-page claim is additionally checked against the exact authenticated
  terminal earlier prefix and source head before effects and in the final
  proof. One call
  advances at most one page, waits without provider I/O, or records one
  comparison; wait and comparison paths create no claim. The distinct proof
  result retains both ordered transition histories and the optional selected
  claim/consumption without adding convergence or authority.
- **Phase 4AC restart-safe UNKNOWN recovery composition — local slice
  implemented:** ADR 0069 composes the existing Phase 4J schedule, Phase 4I
  authenticated lookup, Phase 4K normalization, and Phase 4L inbox admission
  into one bounded invocation. Every durable participant must expose the same
  process-local SQL-store identity before reads, clocks, credentials, or
  effects. Source-indexed authenticated reads repair I-before-J,
  J-before-K, and K-before-L crash prefixes, and every attached receipt is
  replayed through idempotent K/L accounting before the schedule can issue
  another lookup. The proof result retains exact ordered J/I/K/L evidence and
  grants no UNKNOWN resolution, application, reservation, resubmission, or
  trading authority.
- **Phase 4AD bounded raw-first account-activity pages — local adapter
  contract implemented:** ADR 0070 freezes an ascending
  `GET /v2/account/activities` FILL traversal with page sizes of at most 100,
  exact last-activity-ID page tokens, eight-page/800-item limits, and Phase 4C
  body bounds. Every page has a distinct reconciliation demand and durable raw
  ingress before a strict versioned FILL decode. Exact IDs, timestamp and
  decimal lexemes, duplicate/schema/type/order/overlap checks, and explicit
  terminal-short-page versus bounded-truncation evidence are required. The
  contract grants no canonical execution/revision, cross-channel
  deduplication, application, readiness, or trading authority.
- **Phase 4AE authenticated durable account-activity traversal — local slice
  implemented:** ADR 0076 and migration 0029 advance exactly one Phase 4AD page
  through single-use durable preparation, credential resolution, Phase 4D
  request admission, restricted raw-first transport, and commit under the same
  account fence. Plans, preparations, receipts, and heads are reconstructed
  from exact source evidence at read and startup. An unresolved preparation
  fails closed after restart rather than resending an ambiguous provider call.
- **Phase 4AF exact bounded account-activity comparison — local pure slice
  implemented:** two supplied Phase 4AD captures are compared with exact
  ordered IDs and added/removed/changed sets. Terminal and bounded-truncated
  inputs remain distinct, and no equality result is promoted to completeness,
  convergence, canonical fill/correction identity, or reconciliation.
- **Phase 4AG source-authenticated account-activity comparison — local
  application slice implemented:** both distinct terminal Phase 4AE states
  are reloaded and fully reconstructed before the exact Phase 4AF result is
  recomputed. The application proves provenance only for those historical
  source positions and rejects active, stalled, empty, cross-account,
  cross-provider, cross-profile, or cross-store inputs.
- **Phase 4AH durable authenticated account-activity comparison — local slice
  implemented:** ADR 0083 and migration 0033 append one immutable comparison
  receipt for an exact ordered Phase 4AG pair under the account lock.
  Comparison values are recomputed, both raw-backed sources and the current
  fence are reauthenticated in-transaction, retries converge, and the
  account-local predecessor/head chain is verified at startup. Nonempty
  comparison history guards downgrade.
- **Phase 4AI bounded restart-safe account-activity supervision — local
  application slice implemented:** each invocation reloads exact Phase 4AE
  states and selects at most one page effect, one Phase 4AG comparison append,
  or one explicit no-I/O wait. It retains no in-process traversal state,
  exposes stalled claims instead of retrying them, and grants no reconciliation
  or trading authority.
- **Phase 4AJ recorded-offline E\*TRADE provider foundation — local pure slice
  implemented:** ADR 0113 adds exact provider-specific types for environment,
  nonsecret consumer/token scope, OOB callback policy, numeric account ID, and
  opaque `accountIdKey`. Sandbox and production data/order roots and all local
  scopes are cross-bound and disjoint, while both profiles retain the exact
  shared OAuth service identities. The sole enabled request description is a
  deterministic `GET /accounts/list` JSON-media profile with empty query/body
  and no authorization material. Balance, Portfolio, Orders, Transactions,
  Preview, Place, Cancel, raw decoding, persistence, OAuth, transport, account
  binding, and every authority remain closed. Sandbox evidence remains
  protocol-only and cannot satisfy traversal, lifecycle, reconciliation,
  timing, economic, soak, or readiness gates.
- **Phase 4AK bounded offline E\*TRADE Accounts List caller declarations — local
  pure slice implemented:** ADR 0115 adds a separate in-memory raw-first
  caller-declared response profile and strict decoder. Immutable supplied bytes
  are bounded to 262,144 bytes and 128 accounts and bind the exact typed
  provider, environment, endpoint/request description, declared origin,
  JSON/UTF-8 media, explicit
  `UNAUTHENTICATED_CALLER_DECLARATION`, and deterministic response and schema
  profiles. These exact bindings prove internal consistency only: arbitrary
  caller-supplied bytes, including a relabeled fixture, can be declared and
  decoded, and no enum or digest authenticates provider origin. Every returned
  layer exposes `provider_origin_authenticated=false` and
  `fixture_relabeling_detection_supported=false`. Raw-string enum substitution,
  malformed or drifted schema, duplicate keys, internally contradictory
  bindings, and duplicate or ambiguous account ID/`accountIdKey` mappings fail
  closed. Decoded identities remain historical unqualified caller-declared
  observations that cannot be consumed as authenticated provider evidence;
  transport, persistence, authenticated account discovery/binding, all other
  operations, and every authority remain closed.
- **Phase 4AL pure E\*TRADE OAuth 1.0a signing and supervised session — local
  pure slice implemented:** ADR 0118 adds exact typed `GET` signing intents for
  ADR 0113's request-token, access-token, renewal, and revocation endpoints,
  with the request-token callback fixed to `oob`. RFC 5849 UTF-8 percent
  encoding, encoded-name/value sorting, normalized parameters, HMAC-SHA1, and
  Base64 are pinned by RFC and synthetic vectors. Exact caller-injected trusted
  timestamps/nonces and a bounded in-memory fingerprint guard reject signing
  and verifier-consumption replay when its current returned state is threaded.
  The guard retains a nondecreasing signing timestamp and latest generation per
  typed environment/endpoint/consumer-reference scope across operations and
  reauthorization. Authorization confirmation returns one sealed,
  non-serializable exact-verifier-identity capability; access signing requires
  that same verifier object and confirmed-state identity and consumes the
  capability once. Secret wrappers and signing results are sealed and
  revalidated at sensitive boundaries;
  typed consumer/token reference revisions reject raw-string, wrong-kind, and
  cross-environment substitution. Consumer keys, tokens, consumer/token
  secrets, verifiers, signatures, Authorization headers, signing material, and
  token-bearing authorization URLs remain ephemeral and cannot enter `repr`,
  serialized evidence, or semantic digests. The secret-free reducer makes
  request-token, OOB authorization, verifier consumption, access-token,
  activity, renewal, two-hour inactivity, daily expiry, revocation, and
  reasoned reauthorization explicit fail-closed transitions. A monotonic time
  high-water survives every phase/generation, and each time/signing-driven
  transition retains its sanitized input identity. Reusing an older immutable
  state/guard can still fork in-memory history and mint a separate capability;
  there is no restart/process coordination, durable current-head comparison, or
  durable exact-once claim. It adds no secret
  resolution, ambient time/randomness, durable replay protection, browser or
  callback runtime, provider response authentication, filesystem, persistence,
  proxy/redirect/network transport, provider-origin claim, account binding,
  broker call, or authority, and adds no migration.
- The capability value and translated request description are immutable and
  content-authenticated, and lookup/account/asset observations retain exact
  response digests, while the raw journal authenticates exact account-local
  receipt chains and the budget journal authenticates capacity admission. The
  Phase 4F digest binds those local values without claiming they are current
  durable runtime heads. Phases 4G and 4H can establish exact receipt-scoped
  authenticated provider-account and pinned candidate-security bindings, and
  Phase 4I can retain an attempt-bound authenticated historical lookup, Phase
  4J can bound when distinct lookup attempts become eligible, and Phase 4K can
  normalize each exact durable source into historical reconciliation evidence.
  Phase 4L can account durably for each source-scoped request and its explicit
  non-application decision, Phase 4M can bind a bounded local raw-first page
  chain without claiming it is a provider snapshot, Phase 4N can compare two
  such captures without claiming convergence, and Phase 4O can authenticate
  and durably resume only their exact committed prefix. Phase 4P can durably
  retain the exact authenticated pair comparison without qualifying it, and
  Phase 4Q can select one restart-derived bounded traversal/comparison step
  without retaining in-process state. Phase 4R can retain and replay one
  bounded open-position response without treating it as current account truth,
  and Phase 4S can compare two such views without claiming provider time or
  convergence. Phase 4T can execute one exact position read only after a fresh
  single-use durable claim, and Phase 4U implements the exact claim/receipt
  repository while leaving deployed composition absent. Phase 4V durably binds
  the exact authenticated pair comparison, Phase 4W chooses one
  restart-derived capture, wait, or comparison step, and Phase 4X reserves and
  atomically consumes the selected pair transition before preparation. Phase
  4Y carries that claim and its exact lease through the unchanged Phase 4T
  provider-read path and reauthenticates every W/V source. Phase 4Z requires
  coherent Q/O/P runtime-store wiring before any order-view source read or
  effect without claiming durable pair admission. Phase 4AA adds the durable
  ordered-pair/page admission repository and normalized immutable Phase 4O
  preparation history, while Phase 4AB carries each admitted page through the
  unchanged Q/O/P runtime and reauthenticates every page before comparison.
  Phase 4AC drains the authenticated J/I/K/L recovery prefix before another
  scheduled lookup and makes each durable crash boundary resumable. Phases
  4AD-4AI implement bounded raw-first FILL-activity models, an authenticated
  one-page durable runtime, pure and source-authenticated comparisons, a
  predecessor-linked comparison repository, and a one-effect restart-safe
  supervisor. Phase 4AJ independently adds only the typed E\*TRADE isolation
  and Accounts List request-description foundation; Phase 4AK adds only its
  bounded in-memory caller-declared raw evidence and strict historical decoder;
  Phase 4AL adds only pure OAuth signing and secret-free supervised-session
  transitions. None reuses any Alpaca evidence. All slices remain
  non-authorizing. A
  deployed secret resolver, general
  security-master publication, runtime
  calendar/quote/reduce-only validation, end-to-end order request-budget
  enforcement, authenticated deployed lookup supervision, deployed traversal
  scheduling, stalled-capture recovery, streams, the general
  cross-channel identity/deduplication profile, decode quarantine,
  authoritative fact application, reconciliation, coordinator dispatch, and
  paper startup remain disabled.
- Phases 4A through 4AI are complete only as bounded local contract,
  persistence, and authenticated read-runtime slices with the explicit limits
  described above. Phases 4AJ through 4AL are complete only as a pure recorded-
  offline provider/request foundation, an unauthenticated caller-declared
  in-memory raw-response/decoder slice, and a non-I/O OAuth signing/session
  contract. Phase 4
  and its exit gate remain open. These slices are local worktree changes and do
  not authorize paper or live trading.
  Phase 3's captured-tape, reconnect, shadow, economic
  segment-execution,
  traceability, and reporting gates also remain open and are not bypassed by
  starting Phase 4 work.

### Build

- Continue the distinct E\*TRADE provider track without changing historical
  Alpaca schemas or evidence. Phase 4AJ implements the first pure boundary:
  fixed disjoint sandbox/production data/order REST origins and nonsecret
  consumer/token, account, budget, persistence, and audit scopes; exact shared
  token/authorization service identities; exact OOB callback metadata; strict
  syntax-only numeric-account-ID plus opaque-`accountIdKey` values; and a
  deterministic non-I/O Accounts List request description. Phase 4AK adds the
  bounded in-memory raw-first caller-declared Accounts List response profile and
  strict request/environment/declared-origin/media/charset/declaration/schema-
  bound decoder. Those bindings establish internal consistency, not provider
  origin; authenticated capture admission and fixture-relabeling detection
  remain pending. Phase 4AL adds exact pure HMAC-SHA1 signing and a secret-free
  supervised reducer for request/access token, OOB authorization, renewal,
  inactivity/expiry, revocation, and reauthorization transitions. It retains
  only typed nonsecret reference revisions and sanitized identities; all secret
  values and signing output remain sealed and ephemeral. Access-token signing
  consumes one in-process exact-verifier-identity capability, while the signing
  replay guard carries a per-scope nondecreasing time/generation high-water.
  A deployed secret resolver, durable nonce/replay state, authenticated token
  response and OOB handoff, authenticated account binding, provider transport,
  and bounded raw-first Balance, Portfolio, Orders, and Transactions reads
  remain pending. Later
  budgets must reserve cancellation, token-control, and reconciliation capacity
  and must not reuse Alpaca's request ceiling. Comet streaming remains disabled
  until independently qualified.
- Persist a separate deterministic, account-scoped E\*TRADE client-order ID that
  is collision-checked, at most twenty characters, and alphanumeric, mapped
  one-to-one to the unchanged canonical internal ID. Implement Preview then
  Place as distinct raw-first calls: persist the exact request digest and
  preview ID, use a local TTL shorter than three minutes, and immediately
  revalidate fence, risk/reservation, control/kill state, session, quote/collar,
  trusted time, OAuth session, account/instrument binding, and capacity before
  one Place call. Add a closed versioned Preview/Place/Cancel message and
  disclosure classifier: HTTP 2xx is never sufficient, unknown/review/
  restriction/confirmation messages block Place, and acceptance requires the
  exact account, preview/request, and provider order-confirmation identity. An
  ambiguous Place becomes durable `UNKNOWN`, sets control to `HALTED`, and
  permits no automatic retry, resubmission, or replacement. Reconcile through
  paginated Orders/Transactions and
  Balance/Portfolio evidence plus explicit broker-dashboard adoption; absence
  never proves unsent and clean disposition still requires human re-arm. This
  provider-specific rule amends ADR 0004's same-client-ID lookup assumption.
  An ambiguous Cancel likewise retains the reservation and pending-cancel
  uncertainty, blocks new exposure, and is never automatically reissued before
  Orders/Transactions/Portfolio reconciliation and human disposition. A 2xx
  message that cancellation is merely processing remains pending-cancel.
- Qualify E\*TRADE in order: recorded offline contracts; sandbox OAuth,
  transport, request shape, decoder, endpoint-isolation, and pagination field/
  request/response shape checks only;
  separately approved production read-only account/balance/portfolio/order/
  transaction checks; separately approved preview-only checks; local shadow and
  submission-boundary fault soak; then a separately approved directly
  supervised minimum-size live canary. Each stage is non-promoting and live
  remains disabled until every preceding implementation, evidence, security,
  operational, and owner-approval gate passes.
- The first offline Alpaca paper capability matrix, deterministic request
  translation, bounded client-order/account/asset response observations, and
  durable pre-decode raw receipt journal are implemented for the narrow v1
  subset. A provider-neutral durable request-admission ledger now supports
  conservative rolling capacity and protected recovery traffic. A pure
  dispatch-preflight assessment now cross-binds those values with the pending
  attempt, session, active capacity, and fence, but no network path is yet
  forced through it and no atomic dispatch seam consumes the assessment.
  Phase 4G now forces its one account-only request through durable budget
  freshness and stable-fence checks, retains the raw response first, and
  durably binds an operator-pinned provider account for at most five seconds.
  Phase 4H applies those restrictions to one fixed-candidate asset lookup,
  additionally reauthenticates the exact current terminal account binding and
  binds the operator-pinned provider asset UUID and current reviewed
  tradability state for at most five seconds. Phase 4I applies the protected
  UNKNOWN-recovery tier to one exact client-order lookup, reauthenticates the
  UNKNOWN head, provider-account identity continuity, and current recovery
  fence before and after the raw-first request, and retains only historical
  non-authorizing observation evidence. A decoded 200 with a null or different
  canonical asset UUID is retained as a typed security-identity mismatch; it
  does not require current tradability and cannot resolve the attempt.
  Phase 4J wraps those historical reads in a durable local schedule tied to the
  original dispatch horizon. One poll can consume at most the latest due slot;
  earlier misses are durably coalesced, and every selected slot receives fresh
  request and raw-delivery identities. A matching result stops further lookup
  scheduling only for reconciliation, while mismatch blocks scheduling,
  deadline exhaustion remains inconclusive, and every path preserves the
  terminal UNKNOWN lifecycle state.
  Phase 4K then normalizes an exact authenticated lookup/raw source into a
  durable historical evidence fact. Candidate, quarantine, and inconclusive
  dispositions are idempotent and source-authenticated, but cannot be applied
  to canonical lifecycle, execution, reservation, ledger, reconciliation, or
  readiness state.
  Phase 4L derives one source-scoped inbox request from each exact Phase 4K
  fact. Durable normalized request payloads, account-local source-link
  ordering, and explicit fixed-policy non-application receipts make every
  source accounted for without inventing a provider revision or cross-channel
  deduplication identity.
  Phase 4M freezes the first bounded order-list traversal shape. It derives
  each descending cursor and reconciliation demand, commits each response
  before strict decoding, and distinguishes non-isolated cursor exhaustion
  from an eighth-page safety truncation without enabling transport.
  Phase 4N compares two distinct ended captures under the same traversal
  profile. Its page-independent added, removed, and changed sets are local
  value differences only; truncation remains incomplete, insufficient observed
  separation remains waiting, and equality remains unqualified rather than
  converged.
  Phase 4O then executes one exact prepared page at a time. It persists the
  next-page claim before credentials and capacity, requires a fresh
  reconciliation permit plus stable account identity/fence across transport,
  commits raw bytes before qualification, and records a contiguous prefix
  under a final fence check. It deliberately has no automatic pagination loop
  or recovery after an issued permit.
  Phase 4P then reloads two exact ended prefixes, authenticates their complete
  durable sources, recomputes Phase 4N, and appends a transaction-fenced,
  predecessor-linked comparison receipt. That historical comparison remains
  non-authorizing even when the two decoded order views are equal.
  Phase 4Q selects one restart-derived step over an ordered plan pair. It
  advances at most one exact Phase 4O page, returns an explicit no-I/O wait
  before the later-start boundary, or invokes Phase 4P once both prefixes end.
  Returned page evidence is accepted only after exact append-only state reload
  verification, and stalled heads retain Phase 4O's no-resend behavior.
  Phase 4R then adds a bounded raw-first open-position observation. It has no
  transport, treats live mark-to-market values as historical exact-lexeme
  evidence only, and rejects malformed, duplicate, drifted, or oversized
  arrays after the representable raw delivery has been retained.
  Phase 4S compares two such sources with stable sorted asset-ID views,
  preserving exact field/lexeme changes and returning only waiting, difference,
  or unqualified equality.
  Phase 4T wraps one exact source in a strict authenticated request. A fresh
  durable preparation is single-use, one reconciliation permit and the same
  provider-account identity/fence bound the raw-first transport, and a distinct
  commit-time fence check precedes reload. At the Phase 4T boundary, the
  concrete repository and any automatic retry remain pending.
  Phase 4U then supplies that concrete repository with an immutable plan-as-
  claim and one-to-one receipt. Exact source FKs, historical reconstruction,
  readiness verification, and guarded downgrade make unclaimed, stalled, and
  complete states restart-stable without adding retry.
  Phase 4V reloads two complete receipts, requires one pinned provider account
  UUID, recomputes Phase 4S, and appends a fenced account-local comparison.
  Raw-ingress sequence establishes source order while signed wall-clock
  separation remains historical. Phase 4W then selects one restart-safe
  earlier capture, no-I/O wait, later capture, or Phase 4V append without a
  hidden loop or stalled-claim resend. Phase 4X registers the exact pair and
  converts one eligible role claim into the unchanged Phase 4U preparation
  atomically, closing the registered position-pair pre-effect race without
  holding a database transaction across provider I/O. Phase 4Y then runs the
  selected Phase 4T capture with claim-bound snapshot/coordinator adapters,
  authenticates exact Phase 4X history on every Phase 4W/4V load, and returns a
  distinct non-authorizing proof while preserving canonical Phase 4T/4U
  evidence. Phase 4Z then makes Phase 4Q reject split-store O/P composition
  before source reads or effects while leaving durable same-store order-pair
  admission pending. Phase 4AA supplies the independent pair/page proof
  contract, forward-compatible immutable preparation projection/backfill,
  durable member/claim/consumption repository, public unscoped-prepare
  exclusion, and startup verification. Phase 4AB then supplies
  pair-authenticating source adapters, claims the exact Q-selected prefix and
  head, and carries each page's own consumed lease through the unchanged
  Phase 4O provider-read and reload path. No transaction spans provider I/O,
  and one call remains bounded to one page, no-I/O wait, or one comparison.
  Tests use injected credentials and an internal trusted transport seam; the
  public orchestrator always constructs the exact restricted HTTP transport.
  The fixtures remain documentation-derived or explicitly unqualified
  synthetic evidence, not a real provider capture. A deployed resolver,
  data-feed selection, general security-master publication, authenticated
  stream reads, provider-qualified revision/execution/correction identities,
  decode quarantine, authoritative inbox application, reconciliation, and
  end-to-end order budget enforcement remain pending.
- Database-enforced account lease and monotonically increasing fencing
  generation, revalidated immediately before every broker side effect. Disable
  automatic failover because the broker cannot enforce the fence; manual
  takeover uses lease expiry, an in-flight safety interval, prior-runtime stop
  confirmation where possible, and the reconciliation barrier.
- Immutable submission attempts with payload hash and an authenticated provider-
  constrained correlation mapping. On ambiguous responses, enter `UNKNOWN`,
  use only that provider's qualified recovery path, and never blindly resubmit.
  Historical Alpaca work performs bounded delayed lookup by the same client ID;
  E\*TRADE cannot, so its Place attempt remains halted and manually reconciled.
  The offline result vocabulary,
  durable raw delivery receipt, one authenticated exact-UNKNOWN historical
  lookup path, bounded durable local scheduling, and historical lookup
  normalization plus source-scoped inbox non-application accounting are
  implemented, but deployed supervision, provider-qualified cross-channel
  identities, authoritative application, and resolution remain pending.
- Inbound inbox/deduplication for at-least-once broker stream and snapshot
  events. The pre-decode raw journal and Phase 4L's source-scoped normalized
  lookup requests/source links/non-application receipts exist, but they do not
  claim general deduplication. Phase 4M adds a bounded pure order-page chain,
  Phase 4N adds a pure two-capture value comparison, Phase 4O authenticates and
  durably commits one exact page at a time, and Phase 4P durably retains one
  exact source-authenticated pair result. Phase 4Q chooses one bounded
  restart-derived advancement, wait, or comparison action without a hidden
  loop. Phase 4R adds one bounded raw-first open-position array without
  claiming it is current or canonical, and Phase 4S compares two arrays without
  promoting equality. Phase 4T authenticates one freshly claimed position read
  and Phase 4U persists its non-retryable claim and exact receipt. Phase 4V
  persists the exact authenticated pair result, Phase 4W supervises one
  bounded pair step, Phase 4X adds durable pair transition admission, and
  Phase 4Y composes it through one exact-lease Phase 4T execution. Phase 4Z
  requires coherent process-local Q/O/P store wiring before any order-view
  source access or effect. Phase 4AA adds the durable order-transition
  repository, public-prepare exclusion, and immutable, exactly backfilled
  Phase 4O preparation facts. Phase 4AB composes those facts through one
  exact-lease admitted Phase 4O page execution and authenticates both complete
  per-page histories before Phase 4P comparison. Phases 4AD-4AI add bounded
  raw-first FILL-activity pages, an authenticated durable one-page runtime,
  exact pure and source-authenticated comparisons, migration 0033's immutable
  comparison history, and a one-effect restart-safe supervisor.
  None claims
  snapshot completeness or convergence, and
  deployed
  traversal scheduling plus stalled-capture recovery remain pending.
  Stable stream and snapshot revision identities,
  execution/bust/correction identities, raw decode quarantine, and fact
  application remain pending.
- Startup/reconnect barrier: enter `RECONCILING`, buffer stream events, obtain
  paginated account/order/fill/activity snapshots with overlap, apply both
  idempotently, repeat until two views converge, then become ready.
- Explicit policy that the v1 broker account is application-exclusive. Any
  unexplained manual/foreign order or economically relevant mismatch halts new
  exposure until adopted or resolved by the operator.
- Durable control states and precedence for pause, drain, flatten, halt, and
  explicit re-arm. Reserve broker request capacity for cancels/reconciliation.
- Quote-based freshness/collar recheck and risk-reservation revalidation
  immediately before dispatch.
- Browser deployment workflow, target/order/fill trace, coordinator ownership,
  unknown submissions, reconciliation differences, durable command receipts,
  and pause/drain/flatten/halt controls.

### Exit gate

Status: **open**. The Phase 4A-4AI bounded local contracts, raw journal,
request-admission ledger, offline preflight
assessment, short-lived authenticated account and
pinned-candidate asset bindings, historical authenticated UNKNOWN lookup, and
bounded local lookup schedule plus normalized historical lookup evidence and
source-scoped inbox non-application receipts, a bounded order-page chain, a
pure unqualified two-capture comparison, and an authenticated durable one-page
runtime plus durable source-authenticated comparison receipt, a bounded
historical position view, and an authenticated durable single-use position-read
path plus durable position-view comparison, bounded pair supervision, and
exact-lease pair-admitted runtime composition add no
trading side effect, general security-master
publication, canonical position state,
UNKNOWN resolution, authoritative reconciliation result, or lifecycle
application and satisfy none of the runtime/fault gates below.

Phase 4AJ adds only deterministic E\*TRADE endpoint/profile/account-identifier
and Accounts List request-description evidence. Phase 4AK adds only bounded
in-memory supplied raw evidence and unqualified historical decoded account
identities with an explicit unauthenticated caller origin declaration. The
declaration can wrap a relabeled fixture, and neither its enum nor any bound
digest authenticates provider origin. No authenticated capture/admission
artifact or authenticated provider-evidence consumer exists. Phase 4AL adds
only deterministic signing and secret-free in-memory session transitions; its
nonce guard is not durable and none of its states authenticates a token response
or provider origin. These phases add no authenticated or current provider
evidence, runtime authority, or satisfaction of any runtime/fault gate below.

Future E\*TRADE sandbox results may satisfy only protocol-contract checks and
cannot close any traversal-semantics, completeness, lifecycle, reconciliation,
timing, paper-soak, fault, economic, or readiness item. E\*TRADE live eligibility
additionally requires exact production account binding, raw-first read-only and
preview-only evidence, the Preview/Place contract, conservative request budgets,
manual ambiguous-Place recovery, and the complete promotion ladder above.

- Paper lifecycle works for accepted, rejected, partial, filled, canceled,
  cancel-rejected, expired, late-fill, bust/correction, and provider-specific
  status events.
- Two normal trader processes and rolling-deploy overlap cannot both remain
  authorized. Lease or database loss fails closed; forced/manual takeover is
  quarantined and reconciled before it may submit.
- Killing the process at every submission boundary never creates an untracked
  duplicate. Historical delayed client-ID visibility and transient “not found”
  cases are safe, while an E\*TRADE crash or ambiguous result after possible
  Place remains `UNKNOWN`, halted, and never automatically resent.
- Fill-during-cancel, stream/snapshot gaps, pagination, duplicate/out-of-order
  events, manual broker activity, and stale reconnect backlogs pass fault tests.
- No reconciliation mismatch is silently tolerated to enable new exposure.
- The same captured tape produces equivalent strategy targets in replay and
  shadow/paper before execution effects.

## Phase 5 - advanced risk, observability, and operations UI (weeks 13-15)

Status: **open**. Phase 5A implements the local durable operational-control
contract and persistence spine. ADR 0066 freezes
`RUNNING < PAUSED < DRAINING < FLATTENING < HALTED`, applies higher-severity
precedence to every non-rearm command, binds exact retries to account and actor,
fails closed on absent/corrupt state, retains breaker trips, and records
operation-scoped drain/flatten completion or residual facts. Explicit retries
after incomplete/deadline results receive distinct attempts at unchanged
severity, while unrelated no-ops preserve the active attempt. Manual re-arm is
the only downgrade and requires the exact head plus authenticated fresh
readiness, authoritative clean reconciliation, blocker dispositions, and any
state-specific terminal result. The existing three-state batch-risk contract
is unchanged: the compatibility projection maps drain/flatten to `PAUSED` and
absence to `HALTED`.

Phase 5F now adds an authenticated, loopback-only operations API. The existing
signed local session and matching CSRF token protect reads and mutations;
mutations also require idempotency and accept only a bounded reason code.
`REARM` is a separate server-authoritative workflow: an injected verifier
returns exact-head-bound readiness, reconciliation, incident, order, blocker,
and optional operation-completion facts, and the dedicated SQL method
reauthenticates those proofs under the account lock. The public raw repository
continues to reject every `REARM`. Missing read/control/verifier composition
fails unavailable, and the advanced-risk assignment route is registered only
when a current-fence authority and approved-policy service are injected.
ADR 0081 now supplies the concrete authenticated local composition: one
bounded repeatable-read SQL overview plus database-only `PAUSE`/`HALT` over an
already initialized control head on the exact same engine. It supplies no
drain/flatten executor, re-arm verifier, assignment, initialization, or broker
authority.

Phase 5B began with a separate approval-gated, observe-only contract. It
content-addresses proposed measurement bindings and policy candidates, records
typed `COMPLETE`, `INSUFFICIENT`, `UNAVAILABLE`, or `OVERFLOWED` evidence, and
binds exact all-candidate-rule evidence without producing a pass/fail result.
Those proposal artifacts remain non-authorizing. ADR 0068 now separately
freezes the owner-approved moderate paper-only DIA/IWM/QQQ/SPY thresholds,
windows, source authorities, and `REJECT`/`PAUSED`/`HALTED` matrix. The local
approved-policy/evaluator/schema and immutable
assignment/evidence/assessment repository are implemented. Assignment
commands use an exact expected-head compare-and-set, and retained source
membership must reproduce the observation's source-set digest before insert.
The additive cutover, assessment/trip/unchanged-Phase-2/admission-outcome,
legacy-writer lockout, startup-integrity, and final dispatch-authentication
path is implemented and locally verified. It remains disabled by default: no
deployed actor/account authority has assigned or activated it and no deployed
producer is inferred. The existing Phase 2 and Phase 5A contract versions,
rule tuples, and policy digests remain unchanged.

Phase 5C is implemented locally as a strict one-request strategy subprocess
and a durable claim/result composition. The protocol has bounded canonical
JSON, bounded stdout/stderr, a sanitized environment, no shell, a two-second
warning, and an inclusive five-second hard deadline. ADR 0079 commits an exact
pre-run claim under the current fence; only a newly inserted claim authorizes
one runner call, while retry/restart never reruns an unresolved claim. Claim
time is sampled under the account lock; a repository-bound one-shot permit
must authorize start within one second, and the sealed authorization has a
second atomic repository/PID-bound use consumed before runner preparation.
Bounded cursor-exact scans expose due claims without invoking the runner. At
the fixed nine-second recovery
boundary, the current fence may finalize an orphan as one deterministic
`CRASH`. Lifecycle activation locks out the legacy direct result writer. A
completed result leaves control unchanged; every
timeout, crash, protocol error, or resource overflow atomically appends a
severity-preserving `PAUSED` breaker transition and one source-idempotent
critical-alert incident. It never auto-resumes and does not stop the protected
order, risk, broker-event, cancel, or reconciliation loops. ADR 0087 adds one
approval-independent smoke artifact rather than a trading deployment: its
canonical manifest binds the exact standard-library-only child bytes,
protocol/configuration/result identities, and an empty-intent
`NO_EXPOSURE` result. The code-pinned parent check and trusted hash-then-compile
bootstrap fail closed, and the offline verifier neither executes the child nor
changes startup readiness.

Phase 5D now has a local provider-neutral critical-alert delivery slice. ADR
0072 binds source-idempotent incidents, claim-before-effect delivery attempts,
sanitized terminal results, strict one-/15-/30-second baseline milestones, and
startup integrity verification. Exact retries do not resend, a crash after a
claim remains explicitly unresolved, and concurrent same-key claims converge
on one provider request. The abstract primary/escalation route classes remain
provider-neutral. Secret-safe PagerDuty Events API v2 and Twilio Messaging
Service SMS adapters are implemented and tested locally, but amended ADR 0088
defers both providers; they select no destination, recipient, credential, or
escalation roster. ADR 0078 adds a bounded restart-derived
supervisor over those durable facts. An exact injected
route plan fixes distinct provider IDs and opaque destination/recipient-set
digests; deterministic incident/plan/route keys prevent substitution. Each
invocation reloads and validates history first, performs at most one provider
call, waits without I/O after an existing primary claim until the 15-second
boundary, never resends an unresolved escalation claim, and records explicit
total-delivery-failure evidence after terminal route exhaustion or when an
unresolved escalation claim reaches the 30-second equality boundary. That
evidence remains non-authorizing on the legacy worker: its older split
policy/writer path is retired and fails unavailable. Migration 0032 and ADR
0085 add the only local control composition. It proves same-store wiring,
reauthenticates complete durable history, requires a provider-called terminal
result to be replayed, and atomically binds either replay-terminal failure or
an unresolved escalation at its deadline to one fixed, severity-preserving
`PAUSED` transition and source receipt. Exact and concurrent retries converge.
The policy remains unwired. The provider implementations are not route
composition: no destination, recipient, credential, schedule, deployed worker,
channel probe, independence evidence, or deployment activation is selected.

Phase 5E has a local OpenTelemetry contract and bounded exact-type application
composer. It correlates genuine market-batch, target, reservation, immutable
submission-preparation, canonical broker-event, and reducer-derived
ledger-entry facts in one trace. `fill` and `reconciliation` remain explicitly
missing: the transient advanced-risk fill input is not a durable
correction-safe fill fact, and Phase 4 reconciliation evidence remains
historical and non-applying. Only opaque immutable IDs and digests are traced;
cross-process propagation is W3C Trace Context without baggage, and the
optional asynchronous provider has a bounded queue, batch, delay, and timeout.
ADR 0088 selects Sentry for diagnostic telemetry. A local Sentry Cloud
OTLP/HTTP trace-exporter factory validates a DSN, derives the fixed endpoint and
authentication header while redacting that header from representations and
failures, pins service/release/environment, and strips account/fact IDs and
other non-allowlisted span data. On 2026-07-29, the operator supplied a DSN
outside the repository and observed transport acceptance for one sanitized
synthetic export. That dated, non-durable setup observation is not checked-in
or reproducible readiness evidence. The exporter remains uncomposed: there is
no runtime sampling/export wiring, retention/access enforcement, outage probe,
reproducible transport receipt, or queryable-ingestion evidence.

Phase 5G includes an authenticated operations dashboard API and React route.
It renders the environment, source freshness, coordinator, strategy/deployment,
orders, fills, account/ledger, positions, risk, reconciliation, alert, and
control sections as an authenticated, non-cacheable snapshot. The signed local
session, matching CSRF header, loopback transport, and durable readiness protect
the read. A narrowly authenticated browser client consumes the granular
`control_pause` and `control_halt` flags and exposes only those fail-safe
commands. It preserves one idempotency key across explicit retries after
ambiguous outcomes, binds confirmation and retry to the exact account, requires
an enabled credential capability, bounded reason, and stronger HALT
confirmation, then refreshes the authoritative account overview after success.
It cannot drain, flatten, re-arm, assign policy, initialize control, or call a
broker.

Phase 5H provides a pure typed local operational-drill evidence contract for
kill-state, strategy-failure, total-alert-failure, data-gap,
broker-disconnect, and risk-trip scenarios. Inclusive deadlines, minimum
control severity, new-exposure withholding, explicit unavailable evidence, and
the prohibition on automatic re-arm determine each result. This typed contract
and the separate machine-readable pytest catalog are non-authorizing local
evidence; neither represents a deployed provider, telemetry backend, paper
account, or wall-clock game day.

Phase 5I adds a read-only historical paper-account enrollment attestation.
When all four nonsecret account/provider/secret-reference pins are configured,
one repeatable-read snapshot authenticates every binding chain, reconstructs
the configured account's complete permit/raw/observation lineage, and requires
the exact terminal binding to match every pin. The pure application receipt
exposes only opaque digests and sequence with current-status, control, broker,
exposure, automatic-rearm, and strategy-invocation authority false. Absence,
partial configuration, a foreign-only head, pin drift, rollback, orphaning, or
source corruption fails the configured attestation closed. No Alpaca API
credential value is selected, returned, resolved, or used by this path; it
constructs no resolver or transport and makes no database write or freshness
claim. See ADR 0089.

The local operations API still does not execute cancel/drain/flatten, qualify
Phase 4 reconciliation, dispatch to a broker, enable remote/live access, or
invent an authoritative re-arm verifier. Deployed advanced-risk producers and
assignment, no-exposure artifact runtime composition, Sentry runtime
composition and queryable-ingestion proof, external alert routes/recipients,
approval to activate the fixed local total-alert-failure `PAUSED` policy and
its exact authority digest, independence probes, and timed operational drills
remain pending. These local slices do not close any Phase 3 or Phase 4 exit
gate.

Amended ADR 0088 now selects, but does not activate, a supervised local paper
smoke preflight: one unbound exact-image verification plus a separate host-side
database/Sentry check using the owner's Mac CPU/RAM, a Supabase Free runtime
database, one historically enrolled Alpaca paper account without requiring a
data-plan upgrade, the ADR 0087 no-exposure artifact, and Sentry diagnostic
configuration. ADR 0089 lets the host-side check authenticate the configured
terminal enrollment history without treating its expired status window as
current. Hosted or unattended compute, PagerDuty, Twilio, paid Supabase
capacity, moderate-risk activation, and an external stale-heartbeat watchdog
are deferred. `PAUSED` is the configured non-authorizing policy. The current
preflight creates no control state and authenticates no account-bound durable
control head; its aggregate read-only scan rejects any `RUNNING` head. The
profile rejects live credentials, public operations ingress, provider
substitution, automatic re-arm, and test-database reuse.
With no external notification route or independent watchdog, every check is
directly supervised and cannot qualify as unattended deployment evidence. The
v2 pure nonsecret assessment reports smoke blockers separately from Phase 5
activation blockers, permanently retains local-supervision and deferred-alert
activation blockers, and grants neither broker nor exposure authority.
Current account-status evidence, runtime exporter composition,
queryable-ingestion evidence, authoritative producers, external alert/watchdog
paths, and wall-clock drill evidence remain open. A production container built
from digest-pinned bases and a CI admission check are implemented: the image
runs as a non-root identity without an inbound port, keeps the verified
strategy inputs root-owned, defaults to `paper`, and must exit `2` with only
non-authorizing public evidence while external smoke sources remain unbound.
The local workflow records its exact inspected `sha256:` image ID rather than
treating a mutable tag as immutable.

A separate owner-operated command now composes the existing Phase 4G account
read as an approval-gated enrollment operation. It requires the four nonsecret
`AQT_PAPER_ACCOUNT_ID`, `AQT_PAPER_PROVIDER_ACCOUNT_ID`,
`AQT_PAPER_BROKER_SECRET_REF`, and `AQT_PAPER_BROKER_SECRET_VERSION` values;
the canonical lowercase provider UUID must be obtained independently and is
never learned from the response. One approved operation ID permits at most one
fixed authenticated paper `GET /v2/account` with no retry. Exact replay fails
before a second request; a new operation ID is a new attempt requiring a new
approval, not an automatic retry. Every received bounded response is retained
exactly in Supabase before decode, including balances and other economic
fields, and only a matching usable response can append the secret-free
short-lived binding history. The command runs on the owner's local Mac with the
Supabase Free runtime database. It creates no control state, does not transition
or re-arm `PAUSED`/`HALTED` state, submits no order, creates no exposure, and
grants no broker-effect authority. On 2026-07-31, the separately approved
single-shot recovery executed and established one terminal binding at
account-local binding sequence one. The original raw-only checkpoint and both
request/lease histories remain preserved. This is historical identity evidence
only and does not claim current account status or Phase 5 activation.

An additive single-shot recovery mode handles only the exact
generation-one released-permit/raw-without-binding checkpoint. It requires
distinct prior and new operation UUIDs plus an explicit second-`GET` flag,
revalidates the retained response offline against the current reviewed profile
and independent provider-account pin, and preserves every original fact. Its
atomic lease acquisition can create generation two only, calls the unchanged
observer at most once, and cannot synthesize missing authenticated evidence,
change operational control, weaken the fresh path, or continue to generation
three after any result.

The `phase5-paper-deployment-readiness-v2` assessment and credential-aware
local preflight compose the approved boundary without weakening fail-closed
behavior. They validate an owner-only environment file, distinct Supabase
runtime/test identities, session-mode TLS, the exact migrated schema, the
inspected local production-image ID, Sentry configuration, and the checked-in
artifact/manifest. They also require the read-only aggregate control scan to
observe zero `RUNNING` heads. The credential-aware check runs on the host and
does not execute a bound image. A successful result is
`smoke_preflight_ready`, not Phase 5 activation. Alpaca API credential
variables remain unrequested, unreturned, unresolved, and unused by that
preflight. When all four nonsecret enrollment pins are present, ADR 0089
authenticates the exact historical terminal binding but never its expired
account-status freshness. Every account-specific control head remains
unauthenticated by the profile, external notifications and the watchdog remain
unavailable, and synthetic route evidence cannot remove the permanent
activation blockers.

Successful exact-ID image inspection, database connectivity/schema validation,
Sentry configuration validation, and offline artifact verification are
preflight evidence only. The dated synthetic Sentry transport observation is
separate, non-durable, and not queryable-ingestion evidence. The current
preflight creates no control state. Its account attestation is historical and
its control observation remains aggregate: no heads or non-running heads may
be present, but any `RUNNING` head fails readiness. A durable strategy claim
would require an authenticated account-bound `RUNNING` head; this profile
supplies only a configured non-authorizing `PAUSED` policy, approves no
transition, leaves the durable no-exposure invocation unrun, and keeps Phase 5
open.

### Build

- **Phase 5A durable operational-control spine — local slice implemented:**
  immutable gap-free account transitions, authenticated heads, actor-bound
  idempotency, severity-safe concurrent updates, breaker-trip retention,
  explicit drain/flatten results, fail-closed risk compatibility, startup
  integrity verification, and guarded downgrade. Broker-side control execution
  remains disabled.
- **Phase 5F authenticated operations and proof-only re-arm — local slice
  implemented:** loopback session/CSRF authentication, mutation idempotency,
  allowlisted no-store projections, bounded reason-only commands, and a
  dedicated exact-head SQL re-arm path fed only by injected authoritative
  server facts. The default durable local composition authenticates one
  repeatable SQL snapshot and exposes only database-backed `PAUSE`/`HALT` over
  an existing head on the same engine. Drain/flatten, re-arm, initialization,
  and advanced-risk assignment remain absent without their distinct
  authorities. No route invokes a broker, trusts client readiness assertions,
  or enables remote/live access.
- **Phase 5B approval-gated evidence boundary — contract-only groundwork
  implemented:** immutable proposed measurement bindings, explicitly
  unapproved policy candidates, bounded causal source membership, typed
  incompleteness/overflow, exact Decimal evidence, non-authorizing complete
  bundles, and an evaluation gate fixed at `OWNER_APPROVAL_REQUIRED`. ADR 0067
  preserves that historical non-authorizing boundary.
- **Phase 5B moderate paper policy — specification approved; local
  evaluator/persistence foundation implemented:** ADR 0068 fixes flow-adjusted
  session-loss/drawdown, worst-case concentration/cash leverage, 30-return
  volatility, fresh SIP spread, modeled/realized slippage, and broker
  reject-rate semantics for DIA/IWM/QQQ/SPY. A hypothetical-only `REJECT`
  never trips control; current/committed facts can request durable `PAUSED` or
  `HALTED` with equality, window, source-completeness, pending/unknown
  exposure, fee/dividend, and external-cash-flow behavior fixed. Migration
  0026 plus immutable policy registration, expected-head assignment history,
  exact source membership, deterministic assessment persistence, and strict
  corruption reads are implemented locally. Migration 0030 adds the immutable
  atomic outcome and exact decision/admission foreign-key identities. The
  cutover, greatest-severity trip, unchanged Phase 2 decision, admission
  sidecar, exact retry/divergence, rollback, startup-integrity, legacy-writer
  lockout, and final dispatch-authentication path is locally verified and
  disabled by default. Deployed authenticated assignment, authoritative
  producers remain pending; deterministic local crash/fault coverage is in the
  Phase 5 matrix, while deployment and wall-clock drills remain open.
- **Phase 5C supervised strategy execution — local slice implemented:** strict
  one-request subprocess protocol, fixed input/output/JSON/argv bounds,
  sanitized environment, process-group cleanup, inclusive two-/five-second
  warning/kill semantics, and five typed outcomes. Revision 0028 durably binds
  each result to its account fence and exact pre/final control heads. Revision
  0031 adds immutable pre-run claims and finalizations: only a new claim may
  call the runner, restart cannot rerun an orphan, and the current fence
  performs deterministic fail-closed recovery. Claim time is sampled under the
  account lock, a repository-bound one-shot permit enforces the strict
  one-second start window, and a second sealed atomic authorization use prevents
  sequential or concurrent replay before process creation. Bounded cursor-exact
  scans discover due claims without running strategy code, and lifecycle
  activation rejects the legacy direct result writer. The one-second start,
  five-second execution, and
  three-second aggregate-cleanup budgets yield the fixed nine-second recovery
  boundary. Result, control, incident, and finalization commit atomically.
  Every non-completed result requests
  severity-preserving `PAUSED`; success cannot re-arm. Strategy artifact
  approval, stronger OS sandboxing, deployment, and timed drills remain open.
- **Phase 5D durable critical-alert delivery — local slice implemented:** ADR
  0072 records source-idempotent incidents, gap-free single-use provider
  claims, receipt-digest or sanitized-failure results, strict deadline
  evidence, same-key concurrency convergence, corruption-aware readiness, and
  guarded migration downgrade. ADR 0078 adds exact injected route-plan
  binding, deterministic route keys, history-first restart derivation,
  no-I/O waits, one-call-per-invocation execution, unresolved-claim
  preservation, and explicit total-failure evidence after terminal route
  exhaustion or an unresolved 30-second boundary. ADR 0085 retires the split
  control seam and composes the worker with migration 0032's same-store
  repository. Only durable replay-terminal failure or an unresolved escalation
  at its deadline may atomically append the fixed local `PAUSED` transition and
  exact source receipt; provider-called terminal evidence waits for replay,
  retries converge, and stronger control states are preserved. The contracts
  grant no broker authority. Bounded secret-safe PagerDuty and Twilio HTTP
  adapters are implemented and unit-tested, but amended ADR 0088 defers both
  providers. Destinations, recipients, credentials, route-plan/worker
  composition, escalation roster, deployment/schedule, channel probes, proof
  of channel independence, and activation of the fixed policy with its exact
  actor/authority digest remain approval-gated and undeployed. Strategy failure
  incident creation is already atomic with its control transition.
- **Phase 5E OpenTelemetry correlation — partial local slice implemented:**
  bounded opaque fact-ID/digest correlation across the six causally validated
  fact types currently available together in the local path; explicit W3C
  Trace Context without baggage; and bounded asynchronous export. The composer
  reports `fill` and `reconciliation` as missing instead of relabeling other
  facts, span acceptance is not an export receipt, and telemetry grants no
  trading authority. ADR 0088's selected Sentry Cloud OTLP/HTTP trace-exporter
  factory is implemented and unit-tested with secret-safe authentication
  handling and outbound attribute sanitization. On 2026-07-29, the operator
  observed one sanitized transport acceptance using an externally supplied
  DSN; that is a non-durable setup observation, not checked-in or reproducible
  evidence. Authoritative fill/reconciliation producers, runtime composition,
  reproducible transport and queryable-ingestion proof, sampling and
  retention/access enforcement, and outage testing remain open.
- **Phase 5G operations dashboard and fail-safe browser controls — local slice implemented:**
  React/Vite route plus authenticated non-cacheable GET snapshot for
  environment, freshness, coordinator, deployment, orders, fills,
  account/ledger positions, risk, reconciliation, alerts, and audited control
  history. Unavailable/stale sources stay explicit and deterministic fixtures
  stay labeled and mutation-disabled. Granular flags expose only PAUSE/HALT;
  enabled credential gating, bounded reasons, account-bound explicit
  confirmation, ambiguity-safe idempotency reuse, and authoritative
  post-success refresh are covered locally. Drain, flatten, re-arm, assignment,
  initialization, broker actions, and deployed broker-authoritative evidence
  remain unavailable.
- **Phase 5 deterministic fault matrix — local slice implemented:** one
  machine-readable catalog and runner execute exact fake-clock/domain/SQL
  evidence for strategy claim/finalization crashes and lease handoff, alert
  boundaries and atomic fixed-`PAUSED` control binding, advanced-risk strict
  thresholds and atomic rollback, data gaps, uncertain exposure,
  database/lease loss, and
  manual-only re-arm. Provider delivery, telemetry outage, paper broker/data,
  and wall-clock game-day drills remain explicitly `not_run`.
- **Phase 5H typed operational-drill evidence — local slice implemented:** a
  pure bounded contract evaluates the six required fault classes against
  inclusive deadlines, minimum control severity, new-exposure withholding,
  unavailable evidence, and manual-only re-arm. It grants no runtime or
  deployment authority and remains separate from the machine-readable pytest
  catalog.
- **Phase 5I exact historical enrollment attestation — local slice
  implemented:** all-or-none nonsecret account pins feed one read-only,
  repeatable-read authentication of the exact configured terminal Phase 4G
  history and all of its durable sources. The sanitized result remains
  historical and non-authorizing after the five-second status window expires.
  It performs no credential resolution, broker request, write, control
  transition, or strategy invocation.
- Deployed provider routes and recipients for every critical failure, with
  delivery probes, approved activation of the fixed total-failure policy, and
  its exact actor/authority digest.
- Timed kill-state, strategy-failure, alert-failure, data-gap, broker-disconnect,
  and risk-trip drills against deployed authoritative components.

### Exit gate

Status: **open**. Local evidence now covers the durable operational-control
spine, authenticated operations/proof-only re-arm transport, the approved
advanced-risk evaluator and persistence foundation, supervised/durable
strategy results with atomic failure trips/incidents, provider-neutral critical
alerts plus tested PagerDuty/Twilio adapters, bounded OpenTelemetry correlation
plus a tested Sentry OTLP trace-exporter factory, and the read-only operations
dashboard. The Phase 5B atomic cutover/admission path is locally verified but
remains disabled and unassigned. None of those local slices proves deployed
broker control, authoritative metric/reconciliation producers, an approved
account assignment, strategy artifact/runtime deployment, credentialed alert
delivery, telemetry export, a complete eight-stage trace, provider
independence, or timed deployed drills. Phase 5H and the deterministic catalog
are local regression evidence only.

The owner-operated account enrollment and Phase 5I attestation narrow one
identity-composition step but do not change this gate. The dated durable
history proves the pinned paper-account identity, and the current read-only
attestation proves exact terminal continuity after its five-second status
window expired. Neither is current account status, an approved account
assignment, durable operational-control head, reconciliation barrier,
broker-control deployment, or activation fact.

The Phase 5B cutover is additive and quiesced. An assessment binds the exact
pre-transition control head, active assignment, evidence, batch,
snapshot/capacity, and fence; an optional greatest-severity trip binds that
assessment in the same transaction; and an admission sidecar binds the
unchanged v2 decision plus final control head. No pre-cutover decision is
backfilled, no decision without its exact post-cutover sidecar may dispatch,
and no runtime assignment occurs until all required authoritative sources are
available.

- Every broker call is traceable to a current fence and single-use risk approval.
- Boundary/property tests prove configured limits including pending-cancel and
  unknown-order exposure.
- Kill-state matrix drills must be timed and audited; drain and flatten must
  report explicit completion or residual exposure rather than assuming success.
- Strategy timeouts, alert-channel failures, data gaps, broker disconnects, and
  risk trips produce the intended state and require manual re-arm.
- The UI cannot call the broker directly; the current dashboard remains
  observational, and the narrowly capability-gated PAUSE/HALT client uses the
  separately authenticated durable-command API.

Closing the gate therefore still requires credentialed, recipient-bound,
deployed primary/fallback route composition, an escalation roster, channel
probes, and operational independence evidence; Sentry exporter runtime
composition with queryable ingestion plus enforced sampling, retention,
access, and outage policy;
authoritative deployment composition for account assignment, risk sources,
applied correction-safe fills, reconciliation, re-arm, and broker control; a
selected strategy artifact plus runtime sandbox; and timed fault/drill
evidence. These are deployment or authority decisions, not defaults that the
repository may invent.

The supervised local topology and its deliberate omissions are owner-approved
by amended ADR 0088. The exit gate remains open because unattended runtime
composition, external alert routes/recipients, and an independent watchdog are
deferred, while exporter runtime wiring, queryable-ingestion proof,
authoritative facts, and timed deployed evidence do not yet exist. The local
no-exposure preflight is not a substitute for those gates.

Phase 6A now begins operational hardening with a provider-neutral trusted-time
evidence contract, one injected probe step, and local durable supervision. It
binds exact source/authority, host, monitor-epoch, UTC, monotonic, sequence, and
source evidence; derives rather than accepts the signed offset; preserves the
reviewed `<250 ms` healthy, inclusive `250-1,000 ms` warning, and `>1,000 ms`
hard/latching bands; and proves strict sample freshness, 30-second replacement
cadence, and a continuous 60-second healthy recovery interval. The public
reducer pins that policy and seals/recomputes derived state. The probe passes a
fixed one-second monotonic deadline to its injected source and rejects
successful overruns or UTC/monotonic elapsed divergence above 250 milliseconds.
Identity-conflicting bindings fail before source I/O and cannot self-establish
a recovery chain.

Durable Phase 6A registers a fresh non-resumable epoch for each process,
retains every probe attempt in an immutable predecessor chain, and advances one
host head with an exact compare-and-swap after source I/O. Replay reconstructs
state only from public samples through the public reducer; stale sessions,
concurrent losers, gaps, forks, malformed payloads, policy substitution,
projection changes, and head rewinds fail closed. A fresh epoch deliberately
does not carry monotonic state, latch state, or recovery qualification across
restart. The retained history is tamper-evident, not externally authenticated
or rollback-proof.

`clock_recovery_qualified` remains evidence only and never automatically
re-arms. On 2026-07-31, the owner approved and applied migration 0034 to
runtime Supabase; revision, table presence, empty trusted-time histories, and
the operational-schema integrity gate were verified. At the Phase 6A boundary,
no source, source-uncertainty bound, watchdog, scheduler, readiness/control/
exposure wiring, alert, API, deployed supervisor, or paper authority was
implied. Those deployment choices required later composition. See
[ADR 0086](adr/0086-provider-neutral-trusted-time-monitor.md) and [ADR 0090](adr/0090-durable-trusted-time-persistence-and-one-shot-supervision.md).

Phase 6B begins desktop-browser bundle splitting. Feature routes now load
through distinct React lazy chunks behind one accessible, polite loading
fallback; the local placeholder-only trading routes remain synchronous. The
production build proves separate data, research, operations, risk, audit,
reconciliation, and settings route artifacts. An offline production-bundle
admission contract now pins the exact eleven dynamic routes, graph-aware React,
MUI, TanStack Query, and residual vendor partitions, strict `dist` asset
resolution, and inclusive 300,000-byte per-asset and 625,000-byte initial-graph
ceilings. The admitted build measures a 277,872-byte largest asset and 615,022
bytes across its five-asset initial graph. This cache/parsing partition does not
claim lower total startup bytes, CSP, production sessions, table virtualization,
chart downsampling, backend SSE, or multi-browser end-to-end evidence. See
[ADR 0091](adr/0091-fail-closed-production-browser-bundle-admission.md).

Phase 6C initially selected the evidence-only local trusted-time source and
cadence. The profile fixes host `local-paper-docker-primary-v1` and pins Chrony
4.8 in `-x` mode to the exact Cloudflare/Netnod two-provider NTS composite
recorded by the
[archived v1 authority
manifest](adr/evidence/0092-source-authority-v1.json), SHA-256
`356723c84e30478f18ad99f3cfef2ee65b3bdd3fc26936a7d5c9910fd1bcb3ab`,
with strict source/auth/leap admission, one-second deadlines, no retries, and
conservative uncertainty capped at 100 milliseconds. Classification now uses
absolute point offset plus uncertainty against the existing
250/1,000-millisecond bands. One
durable probe runs immediately and later probes stay on an absolute 20-second
monotonic grid; a gap above 30 seconds blocks at the next evaluation. The source
container has
no port or `SYS_TIME`, cannot set the host clock, and uses bounded local
CPU/RAM. Runtime, migration, and supervisor database clients require exact
`verify-full` and explicitly bind the hash-pinned checked-in Supabase 2021 root
CA; DSN/default-root substitution fails closed. Migration 0035 refuses
nonempty trusted-time history and was applied to runtime Supabase on
2026-08-01 through the exact purpose-built operator. The retained mode-`0600`
postflight artifact has SHA-256
`73085244cad0c24f22a06b22e8cf106c26f9e69a3bf5b32b9a296e995e165e6a`
and verifies the exact postflight catalog, full operational schema, pinned TLS
binding, and zero trusted-time histories. A directly supervised 2026-08-01
window passed immutable-image, topology, kernel process/clock-domain,
persistence, fixed-cadence, and clean-stop inspection, but its canonical
artifact is `not_qualified`: five of five current-epoch evaluations were
`source_unavailable`, with Netnod selectable but excluded from the required
combination. The qualification SHA-256 is
`d65a1270b91865ef674af5ea91d23daa0872c392af6b6aa05de3708056c919ac`.
That Netnod result, its archived manifest, and its qualification hashes remain
immutable historical evidence. It records image-admission digest
`2de1fa43994a3918b956ccc749da834ea0636f1983bf33207b0745b8bd3f9c12`,
but its canonical bytes predated content-addressed retention and no old Netnod
admission file is claimed.

ADR 0093 rotates the [current v2 authority
manifest](../infra/trusted-time/source-authority.json) to
`phase6c-local-chrony-nts-authority-v2`, source ID
`chrony-nts-cloudflare-system76-virginia-v2`, and adapter
`phase6-chrony-4.8-nts-evidence-v2`, using `time.cloudflare.com` and
`virginia.time.system76.com`. Both sources remain mandatory over NTS-KE TCP
4460 and negotiated NTP UDP 123, with the same strict selected-plus-combined
composite, 100-millisecond cap, and no fallback. System76 publishes no SLA,
upstream ensemble, redundancy commitment, or leap-smear policy for the
endpoint, so none is assumed. Code/config implementation, immutable-image
admission, and live qualification are complete for one retained local window.
The authority manifest SHA-256 is
`9b514dc25b0cd084aedf1841b305260f22b070b70e396defc9ecce2f9545506c`,
the persisted authority-registry projection SHA-256 is
`8e7a822503c5f73359cc18ee62dee4f56fb3e67f10b725374f8ef24c94344e9e`,
the Chrony configuration SHA-256 is
`5b59d843624fa3b1a923804e44df96a7fbce3848380bf0d5a4b888072310fa23`,
and the reviewed source revision SHA-256 is
`db81102def51115d85e9584ff8539aae1eede787939d0268e552dba40e8953b4`.
The retained content-addressed authority-v2-era image-admission artifact uses
the superseded `phase6c-trusted-time-image-admission-v1` schema and has the same
semantic and file SHA-256:
`b4519a60ae77987b1f2459c26b9ccd9782dd36946a46767a14531cf84807e76e`
and binds source image
`sha256:8d704f59e4b627e38035b8056f9a63037e610f635cac12a8bf76ec4eff3422f3`
and supervisor image
`sha256:ca86611fc6177ec50d80ef0f4ed280bef93865d954c8aee0dceac403cf079d0c`.
It omits `git_revision` and the current v2 loader rejects it.
The retained `phase6c-live-trusted-time-qualification-inspection-v5` artifact is
`qualified`: epoch sequence 8 contains eight current-epoch evaluations
spanning 140.064973522 seconds, with seven recorded samples, qualified cadence,
a fresh 15.535495716-second-old terminal sample, and 11.034056-through-
16.0458345-millisecond uncertainty. The terminal state was
current-process-bound, `healthy`/`within_limit`, and recovery-qualified. One
intermittent System76 `D` observation was retained as `source_unavailable`,
then recovered without
relaxing the mandatory two-source rule. The qualification SHA-256 is
`1eb6c9396d9c82a76a1b57ba0b3266b4a420905e3f29e33613693087f23a728c`;
its exact artifact bytes have SHA-256
`0d0575adc139cc0ec2516d3d5011727986d17e0f856ca810da3bbe84ce0cdec2`.
The project then stopped cleanly, supervisor before source: both containers and
the project network were removed, secret staging was empty, and both named
volumes were retained.
The result is point-in-time evidence, not a System76 availability or SLA claim,
and all authority flags remained false. An authenticated external head anchor,
an independent watchdog,
and every readiness, control, new-exposure, alert, re-arm, paper, and live
consumer remain open. See historical
[ADR 0092](adr/0092-evidence-only-local-chrony-nts-trusted-time-supervision.md),
[ADR 0093](adr/0093-system76-virginia-nts-authority-rotation.md), and the
[runbook](runbooks/trusted-time-supervisor.md).

Phase 6D implements a sparse, signed external-head evidence boundary without
changing any trading authority. Provider-neutral contract
`phase6d-provider-neutral-external-trusted-head-anchor-v1` binds the exact
authenticated local head to an Ed25519-signed canonical checkpoint. The raw
32-byte private key remains outside Supabase; the admitted public key, source,
host, runtime database, separate anchor project, least-privilege Auth
principal, private bucket `aqt-trusted-time-anchors-v1`, and deployment
identity are fixed by a nonsecret authority artifact. The separate project is
still the same storage provider and may share the same owner/admin trust
domain. Its row-level writer policy and no-overwrite client do not make
Supabase Storage WORM or administratively independent.

The Phase 6D worker is single-flight and stays off the 20-second local probe
path. It uses an absolute 300-second checkpoint grid and classifies anchor
evidence stale at 360 seconds or greater. Startup and explicit on-demand work
consume the complete local journal and durable intent/receipt history in
bounded pages inside one repeatable-read SQL snapshot. The complete remote
prefix is listed, downloaded, and authenticated in bounded pages, including a
second listing/hash pass that rejects namespace drift. Provisional pages are
released and only a constant-size sealed proof/tip is retained. Full-audit
memory is bounded, but time and provider requests remain linear in retained
history and no startup-time SLO is claimed at the maximum horizon.

Subsequent incremental work uses the compact authenticated tip and verifies
the exact remote terminal and next sequence plus new local suffix rows. This
bounded incremental check does not detect every arbitrary middle-row deletion
while the process remains running; the full startup/on-demand audit does.

The durable sequence is intent before provider I/O, no-overwrite upload,
authenticated provider readback, a second exact provider `GET`, then receipt.
The second `GET` produces application-sealed, single-use evidence bound to its
identity and exact bytes. Persistence accepts only that evidence; callers
cannot construct it or substitute locally retained candidate bytes. A restart
or ambiguous remote response recovers the one persisted pending intent before
any successor. Only a typed,
authenticated local-head compare-and-swap advance and a positively classified
provider outage are retryable; every integrity, identity, signature, fork,
rollback, persistence, and unclassified error fails the worker fatally.
Enrollment remains default-deny and requires both a full audit and an explicit
runtime flag. Production fixes `allow_enrollment=False` with no environment
override, so first enrollment requires a separately approved reviewed
enablement. This paragraph records the pre-enrollment design state; ADR 0097's
separately approved `new` operation subsequently confirmed sequence 1 on
2026-08-08, as recorded in the current Phase 6 status below.

Migration `0036_phase6_time_anchors` was applied transactionally to runtime
Supabase on 2026-08-01 after the designated test-PostgreSQL proof passed. Its
file SHA-256 is
`9928c457f2593c7b3b4d6f3520eec716bb63375edb1dba3226d44d88cddcdda4`.
The retained preflight and postflight artifact-file SHA-256 values are
`6a0947293540dd6ef60b2a2cc95a52aa687f47b593ac54e28a0b1ea16b2802ed`
and
`92eb4d6afdac3a3725012668caf6e3df131505f028972be5f133d31b6c6c1fff`.
Postflight recorded `migration_committed=true`, no restore, the exact catalog
and operational-schema integrity, and zero intents/receipts. Existing trusted-
time history was not enrolled.

The secure launcher now parses exactly four assignments once from a dedicated
current-user-owned, owner-only launch environment: the database value plus
absolute paths for the nonsecret authority, Auth secret, and raw 32-byte signing
key. Missing, duplicate, valueless, malformed, or additional assignments fail
closed. The general repository `.env` and any file containing broker,
application, telemetry, or unrelated credentials are forbidden; basename
`.env` is rejected before opening. Descriptor-walk loading requires an absolute
canonical path with no symlinked parent and a stable, current-user-owned,
single-link mode-`0600` regular file. A separate owner-only inspection environment
contains exactly `AQT_DATABASE_URL`, also under a non-`.env` basename. The
launcher validates and stages all four inputs as separate owner-only
mode-`0400` config/secret mounts, admits their exact paths, metadata, sizes, and
in-memory digests, waits until the supervisor has loaded all four, then retires
the staged leaves and revalidates their mount outcomes. No secret content is
passed through Compose interpolation. Image admission contract
`phase6d-trusted-time-image-admission-v3` binds the exact migration 0036 bytes,
schema head `0036_phase6_time_anchors`, intent/receipt catalog, `Makefile`,
`scripts/bounded_subprocess.py`, `scripts/credential_env.py`, the exact captured
build Git revision, and one nonsecret canonical OS boot-session ID. The loader
requires the mandatory
`images.supervisor_executable_import_manifest_sha256` and rejects the old v2
shape rather than adopting it. It also requires that session to remain current
before applying the 15-minute monotonic freshness window, so reboot replay
fails closed.

Admission build now happens secretlessly from a clean exact merged worktree
before approval. A fixed Git environment disables replacement refs and external
configuration. Two status samples reject staged, unstaged, or nonignored
untracked state; nonordinary index flags are rejected globally; and the exact
reviewed path set, modes, and stable bytes must match bounded `ls-tree` and
`cat-file` reads of HEAD. Non-exempt ignored and info-excluded additions under
reviewed source directories cannot evade that comparison.

The current trusted-time Make targets still create a fresh locked, offline uv
environment rather than reuse `.venv`, but this legacy path does not
authenticate uv, the base interpreter, or project build hooks before execution
and is test-only. Production remains blocked until the fixed preinstalled
root-owned read-only launcher/runtime and trusted pre-entry service/container
policy freeze; production performs no operation-time uv/build/install. The
2026-08-05 cache-prewarm observation is historical evidence only.

The builder constructs one bounded deterministic tar only from allowlisted HEAD
blobs, validates the Dockerfile-specific deny-by-default context contract, and
feeds that same tar to both direct target builds under one exact minimal Docker
environment. The Dockerfile frontend is content-addressed as
`docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e`,
and the verifier rejects a mutable or different directive. Each quiet build
returns an exact immutable `sha256:` ID, and
verification/admission operate on those captured IDs instead of resolving the
mutable tags. Admission v2 and verifier JSON retain the captured Git revision
alongside those IDs. Compose validation consumes the exact HEAD YAML over stdin with
implicit env-file loading disabled and a fixed project directory. After
`trusted-time-images` retains one content-addressed artifact, fresh manual
approval binds an exact 40-character lowercase merged Git revision, artifact
SHA-256, source `sha256:` image ID, and supervisor `sha256:` image ID. Admission
launch never builds or replaces that artifact. Before opening the dedicated
launch environment it validates the tuple against the same exact-HEAD gate,
loads the content-addressed artifact, revalidates its canonical owner-only
bytes, freshness and current reviewed inputs, fully verifies those exact
installed images, fences the local Docker daemon, and validates the placeholder
Compose model from the approved HEAD bytes. The identical frozen YAML payload
is then used for every Compose `up`, `ps`, and `down`; live Compose/default-file
changes cannot influence consumption after validation. Direct Docker probes
receive only the finite minimal pass-through environment, with `LC_ALL` as the
only admitted `LC_*` key. Runtime Compose payloads are capped at 8,192 bytes and
rendering has a 15-second timeout. Git, Docker, Compose, and macOS boot-identity
commands use command-specific streaming input/output caps and absolute
deadlines; overflow or timeout kills and reaps the isolated process group. The
launcher repeats the revision, daemon, and approval gates after staging and
immediately before Compose, which runs
with `--no-build --pull never`; verifier runs also use `--pull=never`. After the
expected terminal and verified teardown, one final revision/artifact gate must
pass before any v2 receipt is retained.

Lexical validation rejects relative, noncanonical, root-equal, and outside-root
artifact paths before any Git or Docker side effect. Descriptor operations
separately enforce owner-only parent/file metadata.

Admission-only contract `phase6d-unenrolled-secure-launch-admission-v2` now
adds that approval binding, a secretless no-prior-supervisor-container
preflight, full current-attempt container identity and zero-restart binding,
byte/deadline-bounded terminal observation, and an exact typed worker failure
for stable empty remote history while `allow_enrollment=False`:
`head_anchor_remote_history_absent_enrollment_not_approved`. It cannot confuse
that state with configuration, provider, integrity, or unknown failures. Only
the post-validation path that has consumed and retired all four inputs,
revalidated their mounts, observed the exact terminal, removed the topology,
and proved the same stable creation/mount identity for both named volumes may
atomically retain a canonical owner-only content-addressed receipt and exit
successfully. Exact canonical-output failure rolls back the just-linked
receipt and fsyncs its removal. Failure to confirm either operation exits 2
with fixed stderr reason `admission_retention_unconfirmed` and requires manual
artifact inspection; it never becomes a zero-exit admission. An early Compose
failure or private supervisor-identity-disappearance race is
`secure_launch_incomplete` only when it positively observes that exact expected terminal. Missing or
unqualified terminals and unrelated failures retain their narrower nonzero
outcomes and do not publish an admitted receipt. A successful v2 receipt binds
the exact approved revision, artifact SHA-256, and both image IDs. CLI tuple
validation proves value shape and runtime correspondence only; it does not
prove that the revision was merged, prove who approved the tuple, make it
single-use, impose an approval TTL, or prevent replay. The manual approval
record supplies merge provenance and approval evidence. Receipt UUIDv4 values
likewise provide no approval, trusted-time freshness, or anti-replay guarantee.
That historical secure-launcher attempt was `ATTEMPTED_NOT_ADMITTED`. A later
fresh admission and separately approved one-shot operation confirmed sequence 1;
normal persistent supervision remains blocked.

Phase 6D now also implements the approval-bound first-enrollment
operator from
[ADR 0097](adr/0097-approval-bound-first-trusted-time-enrollment.md). It does
not weaken the normal supervisor: production still fixes
`allow_enrollment=False` with no environment override. A separate
profile-only `trusted-time-first-enrollment` service uses the immutable
supervisor image, exact four config/secret inputs, read-only/capability-free
security boundary, bounded resources, and `restart: no`; it has no Chrony
dependency, exposed port, background worker, or successor loop. It waits for a
host release before database/provider work and exits after authenticating only
sequence 1 with reason `enrollment`. It cannot prepare sequence 2, a periodic
checkpoint, a transition checkpoint, or a `clean_stop` checkpoint.

The host launcher `scripts/enroll_trusted_time_head_anchor.py` and separate
Make targets `trusted-time-enroll-first` and
`trusted-time-recover-first-enrollment` keep a new empty-history operation
distinct from separately approved recovery of a sequence-1 pending intent or
reobservation of its confirmed receipt after an ambiguous completion. One
operation approval binds its UUIDv4 and mode, the exact merged
revision/artifact/source-image/supervisor-image tuple, the applicable
unenrolled-admission receipt SHA-256 (fresh for `new`, original claimed receipt
for `recover_pending`), and the exact anchor authority, deployment, runtime
database, anchor project, source authority, signing public key, host, principal,
and bucket identity digests. Recovery additionally binds the prior `new`
operation UUIDv4 and exact retained-claim SHA-256.

New mode binds a fresh pre-mutation unenrolled receipt. Recovery reloads the
exact owner-only prior `new` claim, verifies its content/approval hashes and
canonical mode, and requires its receipt, Git revision, immutable image IDs,
and every authority/identity digest to match. The claim's original image-
admission SHA must match the original receipt. If freshness requires a reissued
image admission, only the current image-admission SHA may differ. Any changed
revision, image ID, receipt, or identity digest is outside this recovery
contract. The reissue is an image-admission artifact, not another unenrolled
admission launch; the retained claim keeps that normal target quarantined.
Secretless `trusted-time-readmit-images` verifies and freshly admits only the
exact already-installed source/supervisor pair after reproducing the same image
IDs from the sealed reviewed Git context; recovery binds its new admission SHA
and the original receipt/prior-claim tuple.

The launcher holds the global trusted-time launcher lock shared with normal
start and unenrolled admission, so no host launcher can overlap it, and
atomically retains an owner-only immutable single-use claim immediately before
release. Before it opens owner inputs, exact crash cleanup accepts only zero
project containers plus recognized staged-input orphans, or one authenticated
first-enrollment one-shot whose container/image/service/command/security/state
and four read-only sources match in structured `Mounts` or legacy `Binds` form.
It never reads those staged contents or executes release, always proves project
and network removal and named-volume preservation, and rejects unknown entries or
drift. `new` may clean only pre-claim residue; any claim blocks it before Docker
inspection, while recovery requires its exact prior claim. A claim is never
removed, so a crash consumes the approval. It retires staged inputs and repeats
the revision, admission, daemon, image, container, topology, mount, and identity
gates before release, including a minimum reserve in
the image-admission monotonic freshness window. After release, the outcome
separates an immutable approval-state recheck performed without the TTL from a
current image-admission freshness observation. Expiry prevents confirmation
but neither it nor another gate failure can suppress evidence about a possibly
completed operation.

Any retained first-enrollment claim quarantines both normal start and
fail-closed unenrolled admission before topology creation. This prevents the
normal worker from recovering a pending sequence-1 intent or creating sequence
2 after either an ambiguous or confirmed one-shot. The dedicated separately
approved `recover_pending` launcher is the only implemented post-claim runtime
path. A confirmed outcome does not clear the quarantine: reopening persistent
supervision requires a later separately reviewed start change bound to the
exact retained claim and confirmed outcome.
Persistent start is additionally rejected unconditionally before claim lookup,
Git, Docker, or owner-environment access. Claim scanning remains defense in
depth; loss or deletion of local artifacts cannot reopen the current gate.

The failure boundary is stage-aware. A positively classified provider outage
before intent commit is `provider_unavailable_before_commit`. Once intent
commit begins, ambiguity is `first_enrollment_recovery_required`. A possibly
durable sequence-1 receipt whose final SQL/remote postcondition, cleanup, or
terminal observation cannot be confirmed is
`first_enrollment_completed_postconditions_unconfirmed`, not permission to
retry new enrollment. Only `first_enrollment_confirmed` may succeed, and it
must prove exactly one sequence-1 intent, receipt, and remote object; no
sequence 2; a stable bounded full remote audit; retired inputs; exact approved
identity bindings; and all authority flags false.

Host-layer `approval_already_consumed` and
`first_enrollment_launch_configuration_rejected` remain pre-release and cannot
reuse the operation UUIDv4. After release, the launcher attempts to retain an
immutable owner-only outcome for success, recovery-required, completed-but-
unconfirmed, missing or malformed terminal output, post-release admission
expiry, immutable-binding final-gate failure, cleanup failure, and teardown
failure. If that retention cannot be confirmed, fixed host fallback
`first_enrollment_outcome_retention_unconfirmed` exits nonzero, preserves the
claim and SQL/remote evidence, and requires manual review; it is not a runtime
terminal reason and cannot qualify success. The launcher removes the one-shot
container and project network,
proves the project topology absent, and preserves captured named-volume
identities without `down --volumes`. It never deletes or rewrites SQL intents,
SQL receipts, remote objects, claims, or outcomes to simulate rollback.
An unconfirmed global lock release after outcome retention instead emits
`first_enrollment_launch_lock_release_unconfirmed`, exits nonzero, and never
reports operational success. It does not remove, rewrite, or downgrade the
already-retained canonical outcome.

The first separately approved `new` operation confirmed on 2026-08-08 and its
exact owner-only claim/outcome evidence is retained. This does not authorize a
repeat, recovery, persistent start, or sequence 2. ADR 0098 authenticates that
retained evidence for secretless review while leaving runtime execution closed.

The adapter's remote-namespace cap is 250,000 objects, about 868 days or 2.38
years at one checkpoint every 300 seconds and less when event checkpoints are
included. It is an object-count horizon, not a startup-time SLO; full
verification remains linear despite bounded memory and constant retained
proof. A tested generation/handoff contract is required before that bound.
Separate anchor project `pgplscpqsvyraleyaphm` is Healthy on Supabase's Free
plan with its Data API disabled. Its exact private
`aqt-trusted-time-anchors-v1` bucket has retained owner-only dashboard
verification of the 4,096-byte limit and `application/json` restriction. That
dashboard observation is partial provisioning evidence only. On 2026-08-04,
approved provisioning SQL SHA-256
`68be661f65b3f6b45d7732744790d8155aeb4aae75d6311d196d711e39321135`
committed to the anchor project. Read-only postflight at
`2026-08-04T05:35:35Z` proved the exact whole `storage.objects` catalog of six
policies for the dedicated writer and restrictive guards, with no reader
principal or reader policy. On 2026-08-05, the dedicated writer password was
rotated and verified through a fresh Auth sign-in. The offline generator then
exclusively created and runtime-decoder-validated the owner-only signing key,
Auth secret, and nonsecret authority outside the repository. Its secret-free
receipt-file SHA-256 is
`c52cb3eccfefed713822fe797ac5f2f93c33565b60b41940faa93b2bb30bc264`,
the authority SHA-256 is
`9747c97be9cfabf51e524eef66120e8c7ec860be18e064416b17aa197eeb8f7c`,
and the deployment-identity SHA-256 is
`e1290de2b5b340dee07f327af42f18b6bba0ccba0ea003be37783abc7b4ae892`.
The first behavioral Storage proof ran on 2026-08-05 with proof ID
`0396c9fe-0a8f-4b17-8c71-faa8a8033bb0`. Authentication, one no-overwrite
canonical insert, and authenticated listing succeeded, and the exact synthetic
object remains retained. Authenticated canonical read then failed closed with
`proof_canonical_object_changed`: the listed key returned the provider's
outer-400/inner-404 `NoSuchKey` mask. Sanitized failure evidence has SHA-256
`530a6ea5075ec787c16bdcbc1eb3a52e2900661e036e35ee24bb371c32f6d536` and
records `UNKNOWN_REVIEW_REQUIRED`; no retry or enrollment followed. The v1
SELECT policies omitted Storage operation `object.get_authenticated_info`,
which the observed GET path requires in addition to
`storage.object.get_authenticated`. After the atomic v2 policy correction, the
separately approved same-object resume passed on 2026-08-05 without a fresh
canonical insert. It admitted the retained failure evidence, listed and read
the exact object, denied overwrite, upsert, update, delete,
noncanonical-namespace insert, real-control-bucket insert, anonymous
insert/list/read, and public read, and verified the final object and namespace
were unchanged. The owner-only pass file SHA-256 is
`85b225f908efa87ce3c424a3bacf77023a4ed07aba18af0c19589613ab7f97c8`,
and its internal `evidence_sha256` is
`5072b832a6fa3ae01009aa5ff2f89c30e8c24593f87273377bb67dc2afda6171`.
Enrollment remained `UNRUN` with `allow_enrollment=false`. Fresh parse-only
Compose and immutable-image admission then passed on 2026-08-05. Historical
owner-only image-admission artifact SHA-256
`10e7feea32ed2ad093e59f7075e60147af5fa4835986e7772262a44f64a81b07`
binds source image
`sha256:c3d81b9e1fa19b1d8131c99554da2c8ee8e6b928f27444293e82b237a24371a0`
and supervisor image
`sha256:06944ec20029fca39db5e8069f3cb3d1397333304cd6ca70343bf2c6fff312ba`;
it grants no authority or new exposure. Two later builds from merged revision
`377cb9bcc80dfeafde680097e483d2f3195f615b` and identical reviewed-input
SHA-256 `d691523d732e29c59773411e145c6462e94505b1d5e7e92e523a152b64ac9a10`
retained historical artifacts
`b78bda0469077672beacbb746d0278db8b4f84dc5aead65d155c61b98ba4d0d7`
and
`a119b19699c4ce97a13c207d47a9c80c796194d71c99ace97489800838d1dabe`
with the different immutable image pairs recorded in
[ADR 0094](adr/0094-separate-supabase-signed-sparse-trusted-time-head-checkpoints.md).
At the 2026-08-07 pre-build review, these three were the retained canonical or
content-addressed `image-admission*.json` artifacts. They use a superseded v1
schema, omit the captured `git_revision`, and are historical evidence only; the
current v2 loader rejects them.
This permitted drift means neither tuple can approve a later rebuild. The
following secure launch did not admit and retained no v2 receipt;
that historical `ATTEMPTED_NOT_ADMITTED` result was followed by a fresh
admission and confirmed first external enrollment.
The approval-binding hardening is merged in revision
`2fcd3cdcf343bf4ef0630b2923190df7556c630d`. The historical retry boundary was
later satisfied by fresh images, a new admission, and exact approvals. The
resulting authenticated sequence-1 evidence remains non-authorizing and does
not qualify persistent supervision.

On 2026-08-07, the separately owner-approved bounded read-only runtime
diagnostic V5 returned `diagnostic_passed`. It authenticated the exact runtime
and anchor-project binding; verified the current database schema, trusted-time
integrity, and startup snapshot; found zero local anchor intents and receipts;
and observed the exact remote deployment prefix empty and stable across two
bounded one-item lists. It reported nine retained epochs, one evaluation in the
latest epoch, and 112 local transitions. Supabase sign-in may have updated Auth
session/audit metadata, but the diagnostic made no application-database or
Storage-object write. Its stdout was operator-observed, not retained as a v2
image-admission or secure-launch receipt, and every readiness, control,
exposure, alert, re-arm, paper, and live authority remained false.
Readiness, operational control, arming, exposure/new exposure,
broker action, alert delivery, automatic re-arm/resume, paper trading, and live
trading remain false. See
[ADR 0094](adr/0094-separate-supabase-signed-sparse-trusted-time-head-checkpoints.md).

The provisioning renderer now admits the whole `storage.objects` policy
catalog, not merely policies with the Phase 6D prefix: preflight accepts an
empty set or the complete exact expected set, and postflight rejects every
unrelated or missing policy. Fresh installation creates final names directly;
both fresh and existing modes create each equivalent audit policy in a
rollback-only PL/pgSQL subtransaction, compare raw `pg_policy` trees, and catch
a private rollback sentinel before raising any real definition drift outside
that handler. A transaction-scoped relation lock excludes concurrent policy
DDL. This preserves exact idempotent verification without owner-only policy
rename or removal DDL. The current local v2 contract adds
`object.get_authenticated_info` to both the permissive writer SELECT
policy and restrictive SELECT guard. It also renders a fail-closed v1-to-v2
operator: an exact-catalog rollback-only DROP-capability probe (SHA-256
`73f7db8b16033848cbc9790310bd7a6d4e3c4537d6a694cac9fdf368d12eea18`)
and an atomic two-policy upgrade (SHA-256
`b35de9ae59438481a9f4e26bb9e18a6c3fd37eca2648f7f0ded3e6c87e0fee55`).
The rollback-only probe passed under Supabase SQL Editor role `postgres` on
2026-08-05 and reached its terminal rollback. Its owner-only evidence SHA-256
is `706ddc3a7a9e9f656e42b037b7e92e0dd2acd90cdd68a97d2fa4ef653bd29e81`.
The subsequent read-only postflight (SQL SHA-256
`f9dff727a72661a3deafa84a7d711db73b4499427bb003b0687c58b8c96078ce`)
proved the private bucket and complete six-policy v1 catalog byte-equivalent
to the retained baseline while preserving the one failed-proof object. The
atomic upgrade was then approved and committed under role `postgres`. Its
owner-only applied evidence SHA-256 is
`57a4ce0914d36b179adce7f40afda99bb7bd5d859a2a9f33cb2d40984bca62e3`.
Locked read-only postflight proved only the two SELECT policies changed, both
carry exact operation `object.get_authenticated_info`, the other four remain
byte-equivalent to v1, the complete six-policy v2 catalog is exact, and the
retained object plus disabled enrollment are unchanged. Offline artifact generator
`scripts/generate_trusted_time_anchor_artifacts.py` exclusively creates the raw
key, runtime Auth secret, and nonsecret authority outside the repository with
`allow_enrollment=false` and enrollment `UNRUN`. Credential-safe proof operator
`scripts/prove_trusted_time_anchor_storage.py` requires owner-only evidence for
a real separate private control bucket, retains one synthetic canonical object
in a proof-only deployment/host prefix outside the runtime's exact prefix,
strictly proves the allowed and denied Storage operations, has no cleanup mode,
and leaves enrollment `UNRUN`. The artifact generator was run successfully on
2026-08-05. After the approved policy correction, the proof operator resumed
the exact retained failure evidence and object without a second canonical
insert and completed the denial matrix. The retained pass file SHA-256 is
`85b225f908efa87ce3c424a3bacf77023a4ed07aba18af0c19589613ab7f97c8`,
with internal `evidence_sha256`
`5072b832a6fa3ae01009aa5ff2f89c30e8c24593f87273377bb67dc2afda6171`;
enrollment remained `UNRUN` and `allow_enrollment=false`.

Phase 6E has a dormant, provider-neutral preparatory state contract,
`phase6e-provider-neutral-trusted-head-watchdog-state-v1`. It treats raw signed
checkpoint bytes and caller-supplied monotonic values as untrusted candidates.
A signature and exact gap-free successor prove only submitted-record integrity,
not provider origin, current terminality, remote advancement, stop state,
freshness, or liveness. The reducer never reports `CURRENT` or `STOPPED` and
never calculates staleness from a caller value. Every nonfatal result is
`UNAVAILABLE` with `STARTUP_NO_BASELINE`, `BASELINE_ONLY`,
`PROVIDER_TERMINAL_PROOF_ABSENT`, or `PROVIDER_UNAVAILABLE`; a signed successor
or `clean_stop` advances only chain diagnostics. Malformed records, invalid
signatures, identity mismatches, forks, rollbacks, gaps, and input-clock
regression fail closed. The sealed output is bound to the contract and exact
authority, but no consumer exists and every authority flag is false.

This is pure dormant code, not a deployed watchdog. It adds no Supabase or
provider adapter, runtime process/container, external failure domain, alert
delivery, readiness/control/new-exposure/re-arm integration, deployment,
drill, or Phase 6 exit evidence. The rollback-only DROP-capability probe is now
retained and passed, and the atomic v1-to-v2 policy upgrade is applied and
postflight-verified. The reviewed, separately approved same-object resume is
also complete and retained. Fresh parse-only Compose and historical
immutable-image admissions are retained without granting authority. The
approval-binding hardening is merged and the bounded V5 runtime diagnostic has
passed without granting authority. On 2026-08-08 the dedicated first-enrollment
operator completed one separately approved `new` operation. Its owner-only
claim and outcome confirm sequence 1 with reason `enrollment`, one stable
authenticated remote object, no sequence 2, all eight host gates true, and all
authority flags false. Enrollment is `CONFIRMED`, but the retained claim still
blocks normal start and unenrolled admission. ADR 0098 adds a pure exact
claim/outcome decoder, an owner-only unambiguous loader, and a non-authorizing
review projection that keeps the historical enrollment tuple separate from a
proposed later start tuple. Persistent start, sequence 2, and shutdown remain
hard-closed pending the separately reviewed runtime binding. ADR 0099 freezes
the single-use operation, fresh sequence-1 reauthentication, exact sequence-2
`epoch_rotation`, crash, confirmed-outcome, and supervisor-first `clean_stop`
contracts. Its current code-only implementation uses one globally single-use,
fixed owner-only retained-claim slot. A stable bounded inventory rejects any
existing fixed-name or legacy per-operation claim before retention and during
revalidation. It also includes a fixed, bounded in-container pre-mutation
release barrier; a dormant read-only sequence-2 postcondition issuer; and a pure
claim-to-successor binder. The issuer performs a complete SQL replay, a stable
bounded two-object remote audit, then another complete SQL replay. It freezes
the exact sequence-2 `epoch_rotation` receipt, record, and confirmed-anchor
ordinal while permitting independently authenticated local probe suffixes to
advance monotonically. The binder requires the claim's sequence-1 predecessor
and all nine identity digests and returns only
`successor_candidate_unqualified`; the existing host outcome remains
`UNCONFIRMED` and every authority field remains false.

An import-only claimed-release handoff checks the exact retained enrollment
before reauthentication and again before and after claim retention, closes its
read-only sequence-1 issuer before retention, rechecks the empty claim slot,
and durably retains and revalidates the claim against its canonical owner-only
artifact root. It returns only
`claimed_release_handoff_unqualified` plus these exact inert argv elements, in
order: `docker`, `container`, `exec`, `--user`, `10001:10001`, the full 64-
character lowercase-hex container-ID candidate,
`/opt/autoquant/trusted-time/bin/autoquant-trusted-time-python`, and the fixed
target ID `post-enrollment-release`, with no additional arguments. It
authenticates neither container nor topology identity;
`container_identity_authenticated` and `topology_authenticated` remain false.
The ID remains untrusted until a future executor independently revalidates the
exact topology immediately before release. The handoff does not inspect or
execute Docker, create a topology, publish the marker, observe or mutate
sequence 2, retain an outcome, or expose a CLI.

Contract `phase6d-post-enrollment-start-created-topology-snapshot-v1` now adds
a separate pure, import-only never-started topology candidate. It binds the
exact approval/proposed launch, two equal structurally valid daemon projections,
two equal stable named-volume identity projections, two equal submitted order-
independent full-ID project inventories, and exactly two isolated inspections
keyed by those IDs. Exact Compose labels derive source and supervisor roles.
Top-level and configured images, effective path/arguments, configuration, environment,
healthcheck, network, mounts, hardening, and every execution-bearing `created`
state field must match. Missing nullable projection fields, numeric type
confusion, unsafe device/namespace/DNS/link/sysctl/logging/proc policy, and
ambiguous or repeated staged paths fail closed. The snapshot retains only four
SHA-256 inspection/image-configuration projections, nonsecret identity
bindings, and separate inert
source-first `docker container start` argv values. It does not read Docker,
files, secrets, or clocks and cannot retain a claim, mutate topology, start a
container, release the barrier, or contact SQL/provider state. Daemon, volume,
submitted-inventory, container, and topology authentication plus every
authority field remain false.

Contract
`phase6d-post-enrollment-start-staged-unreleased-topology-snapshot-v1` now adds
the distinct pure state required after the two containers are running but
before claim or release. It binds the exact prior created snapshot and requires
the same operation, approval, immutable launch, daemon, volume, inventory,
container, and image-configuration identities. Caller-supplied inspections must
show an exact nonterminal, unrestarted running topology with a healthy source.
Equal caller-supplied before/after candidates must show the exact database-
secret-consumed marker, both fixed release paths absent, and all four staged
host inputs retired. The result retains only nonsecret identity and
digest projections, has status
`staged_unreleased_topology_snapshot_unqualified`, and leaves observation-
provenance, created-topology, daemon, volume, inventory, container, topology,
database-secret-consumption, release-absence, staged-input-retirement, source-
start, supervisor-start, start-order, and every authority field false. It
performs no I/O and retains no raw
inspection, image-configuration, marker, staged-path, environment, mount, or
state object.

Contract `phase6d-post-enrollment-topology-observation-reader-v3` now adds the
strict dormant observation boundary without changing either pure snapshot
contract. One exact caller-owned inert issuer is activated in place, owns an
opaque native global launcher-lock lease, and pins a
canonical absolute Docker executable plus local socket and daemon identity,
and binds the session to one process and one non-copyable lifecycle. Its guarded
production signer is bound to the exact issuer owner, session, and creating
PID. The lifecycle still serializes each raw observation or cursor operation
outside a consumed choreography. Its additive private
`_run_exclusive_choreography` callback acquires one opaque token exactly once
and only on a fresh issuer with no prior observation, cursor, active operation,
or consumed choreography. The token is bound to the exact issuer,
authentication capability, session, creating PID, and exact current-thread
identity; it is non-copyable, nonserializable, valid only in the callback, and revoked before
the callback returns. The C at-fork handler closes the child's inherited lease
descriptor first; the sole Python child callback then scrubs closure and heap
state without native calls or inherited-lock acquisition.

Lease acquisition fixes an absolute 600-second deadline on one production
suspend-aware host action clock owned and identity-sealed by the topology
issuer. Linux uses `CLOCK_BOOTTIME`, macOS uses `mach_continuous_time` scaled by
`mach_timebase_info`, and every other or unavailable platform fails closed; an
injected clock remains only a test seam. A clock regression or observation at
exactly or after that deadline fails closed. Raw
Docker commands retain a two-second deadline; during the callback each timeout
shrinks to `min(2 seconds, remaining time)` and the lease is checkpointed again
after the command. The unchanged v1 transcript's 2,000-millisecond field
records that ceiling, not a claim that a smaller leased runner timeout was not
applied. An unleased raw observation/cursor call or attempted close
during the callback poisons the issuer and revokes the lease without releasing
the outer flock before callback unwind. Every command also has independent
stdout/stderr caps. The decoder accepts only one
compact LF-terminated UTF-8 JSON value, rejects duplicate keys, nonstandard
constants, floats, oversized integers,
surrogates, and depth/node exhaustion before any projection is trusted.

The same acquisition fixes a second absolute bound from the identical
monotonic origin: recovery retention expires at `start + 605 seconds`, with
equality expired. Claim retention, action poison, the `start + 600 seconds`
action boundary, recovery-capability arming, and retention start never reset
either deadline. The five-second outer interval is not action time and cannot
be used for a Docker read, cursor, release, SQL/provider call, or any other
topology observation or mutation. An `unbound` or `claim_admitted` recovery
capability is revoked by action poison or the 600-second equality boundary and
cannot be armed during that outer interval.

The issuer performs 14 bounded reads for the never-started state and 16 for
each staged-unreleased state. Raw observations require the exact image root
IDs, Linux/runc/container confinement, complete sandbox and network attachment
metadata, stable daemon, volume, inventory, and separately inspected bridge
identity, plus exact post-probe container state. The staged path performs two
fixed descriptor-held, read-only in-container marker/absence probes, inspects
the containers only after both probes have exited, and observes the four host
retirements through owner-only no-follow directory descriptors. It can issue
one created envelope and at most two ordered staged envelopes; staged ordinal
1 names the created envelope as predecessor, ordinal 2 names ordinal 1, and
both staged snapshots must have the same stable snapshot digest.

The same issuer now exposes `issue_observation_cursor` under contract
`phase6d-post-enrollment-topology-observation-cursor-v1`, with sole status
`topology_observation_cursor_unqualified`. Each process-HMAC-sealed cursor uses
one bounded daemon read and revalidates the live PID, global lock, executable,
socket, daemon, and session. It binds its ordinal, staged count, created/last
observation digests, and first staged snapshot digest. At most three ordered
cursors may be issued per session. Each cursor is bound to its exact registered
object identity in the originating process, is non-copyable and nonserializable,
and is invalid after fork. Cursors authenticate reader position, not freshness
or action authority.

Only the outer envelopes authenticate the lock/daemon observation provenance.
The unchanged pure snapshots still authenticate no submitted topology, and
the envelopes retain no raw Docker response, secret, staged path, or mutable
inspection object. Topology, start order, both starts, claim retention,
release, persistent start, sequence 2, shutdown, and every operational or
trading authority remain false. The exact one-shot host orchestrator described
below is now their sole supported composition point. No worker/main, Make,
Compose, ordinary launcher, or trading path invokes these seams; normal
persistent start and shutdown remain hard closed.

The pure two-stage same-session composition is now implemented. Contract
`phase6d-post-enrollment-start-pre-claim-topology-fence-v1` returns only
`pre_claim_same_session_topology_fence_unqualified` after reauthenticating the
exact created envelope and staged ordinal 1 and binding their one session,
created-observation identity, direct predecessor, approved launch, topology
identity projections, and staged snapshot digest. Contract
`phase6d-post-enrollment-start-pre-release-topology-fence-v1` returns only
`pre_release_same_session_topology_fence_unqualified` after reauthenticating
that exact pre-claim fence and staged ordinal 2 and proving the ordinal-2-to-
ordinal-1 predecessor, same created observation/session, and unchanged staged
snapshot digest.

The binders perform no I/O and authenticate only the opaque process-private
observation provenance plus those submitted same-session chain/equality
relationships. They authenticate no clock, freshness, claim, current topology
for an action, or temporal adjacency to release. An ordinal 2 issued before
claim retention can be cached and later satisfy the pure structural binder;
therefore it is explicitly not release authority. Claim retention, topology
mutation, both starts, release, persistent start, sequence 2, shutdown, and
every operational/trading authority remain false. Only the exact one-shot host
orchestrator composes them; no worker/main, Make, Compose, ordinary launcher, or
trading path invokes either binder.

Contract
`phase6d-post-enrollment-start-claimed-pre-release-topology-fence-v1` now adds a
code-only chronology slice with sole status
`claimed_pre_release_topology_fence_unqualified`. It requires the same live
issuer and exact pre-claim fence. Function
`prepare_post_enrollment_start_claimed_pre_release_fence` performs this fixed
order: exact approval binding and descriptor-anchored live absence of all four
staged inputs; first consecutive cursor at staged count 1 plus pre-claim
validation; real claim retention and revalidation through the existing claimed-
release handoff; second consecutive cursor still at count 1; issuer-created staged
ordinal 2; pre-release binding; third consecutive cursor at count 2 with ordinal
2 last; and final retained-claim revalidation. It never accepts a submitted
ordinal 2. A cached ordinal 2, preadvanced cursor, nonconsecutive cursor, changed
issuer session, forked predecessor, a mismatch between the full ordinal-1 and
ordinal-2 observations, or claim drift therefore fails closed. This rejects a
preissued ordinal 2 only within this call. Cursor 3 is one daemon/session read,
not a full topology observation, and topology drift after ordinal 2 is not
detected. Called directly, the original preparer retains its raw per-operation
behavior and does not prove uninterrupted issuer ownership.

The additive
`prepare_post_enrollment_start_leased_claimed_pre_release_fence` wrapper accepts
the private callback token, runs that same chronology, and returns the unchanged
v1 result and public payload. It checkpoints the exact lease before structural
preparation, immediately before and after claim handoff, after final retained-
claim revalidation, and after constructing the result; every leased cursor and
ordinal-2 Docker read also checkpoints the lease and uses the shrinking
timeout. No lease digest, monotonic field, or checkpoint is added to the v1
payload or made durable. The result retains no token and proves no active
callback after return.

The process-sealed result authenticates observation provenance, the same-session
chain and stable-topology match, claim retention and chronology, ordinal 2 after
the claim, and the final cursor session. It is bound to its exact registered
identity in the originating process, is non-copyable and nonserializable, and
is invalid after fork; public authenticated payload projection revalidates that
exact type, process seal, and nested evidence. It is not durable evidence. It
does not authenticate freshness or a current topology for an action. It does
not publish or execute the release marker, mutate topology, start either
container, observe or create sequence 2, qualify
persistent topology, retain a host outcome, or grant authority. Only the exact
one-shot host orchestrator may invoke it; no worker/main, Make, Compose,
ordinary launcher, or trading path does. Real claim persistence means every
failure once claim preparation begins is
recovery-required because this seam cannot establish claim absence versus
retention after that boundary. A crash can leave only the durable consumed
claim: no chronology/release result can be reloaded and no recovery command
exists. The unqualified result is not permission to release or retry.

Contract
`phase6d-post-enrollment-start-retained-recovery-outcome-v1` now adds the
dormant pre-release recovery disposition, with sole status
`recovery_required`. The private
`_run_exclusive_choreography_with_recovery_retention` wrapper creates one exact
callback-local, PID/thread/session-bound, non-copyable retention capability
alongside the action lease. It can be armed only by the exact process-sealed
leased claimed-chronology seam. Before claim preparation, that seam mints a
non-copyable, nonserializable one-shot authorization bound to the exact issuer,
lease, recovery capability, artifact and ignored roots, PID, and thread. The
reader consumes that exact tuple before registering an opaque binder; forgery,
substitution, replay, or direct issuance fails closed. A `finally` edge removes
the authorization whether the reader consumes it or issuance raises any
ordinary or asynchronous failure first. The claim writer accepts only that
registered binder and, immediately before its exclusive `O_EXCL` creation
boundary, checkpoints the exact live action lease, flock, roots, and absolute
action deadline. That successful checkpoint is the only transition from
`unbound` to mandatory one-way `claim_admitted`; binding refuses a binder that
skipped it. After the first exact post-retention revalidation, binder consumption
revalidates the claim, flock, deadline, and registration, arms the capability
with that exact receipt while atomically revoking the binder, then revalidates
the claim again. Any pre-arm failure, including asynchronous interruption,
revokes and poisons; any post-arm failure marks retention `unconfirmed`. The
seam cannot accept or execute an arbitrary callback. If the exact retained claim
receipt is absent or unavailable at outcome preflight, no outcome write begins.

At poison or equality with `start + 600 seconds`, action authority is revoked
immediately while the owner callback and flock remain live. The armed retention
capability is the sole non-action exception and can be consumed exactly once by
`retain_post_enrollment_start_recovery_required_outcome` before equality with
the unchanged `start + 605 seconds` outer deadline. It retains one content-
addressed owner-only `recovery_required` outcome bound to the exact claim. It
cannot observe or mutate topology, unlink or replace evidence, retry retention,
publish release, create sequence 2, restore the action lease, or grant any
operational or trading authority. Beginning at or after the outer deadline
writes nothing. If a begun write cannot be confirmed before that deadline, the
capability remains consumed, any possibly durable file is never unlinked, and
the retained claim remains the hard-closed recovery fact. If the claim or exact
outcome becomes unavailable after exclusive creation begins, the possibly
durable artifact is preserved but
`TrustedTimePostEnrollmentStartOutcomeRetentionUnconfirmed` is raised and the
internal retention state remains `unconfirmed`; it is never reported as terminal
retained success.

Contract `phase6d-post-enrollment-final-action-topology-observation-v1`, with
sole status
`final_action_staged_unreleased_topology_observation_unqualified`, now adds one
distinct full action-time read without widening the staged v1 ordinal chain.
After staged ordinal 2 and all three cursors, private method
`_issue_claimed_final_action_topology_snapshot` accepts only a one-shot
authorization bound to the exact claimed pre-release object and digest, created
observation, approval, approved launch, staged-path tuple, issuer, active lease,
PID, and thread. A `finally` edge removes any authorization that issuance does
not consume. The reader performs another complete 16-read staged-unreleased
observation under the shrinking action deadline. It independently revalidates
the claimed type/process seal and private created, ordinal-2, and cursor-3
identities; requires staged count 2, cursor count 3, ordinal 2 last, the same
first staged snapshot, and no prior final observation; and issues neither staged
ordinal 3 nor cursor 4.

Contract `phase6d-post-enrollment-start-claimed-action-topology-fence-v1`, with
sole status `claimed_action_topology_fence_unqualified`, binds that final reader
envelope to the exact process-sealed claimed pre-release fence. Function
`prepare_post_enrollment_start_leased_claimed_action_topology_fence` accepts only
the exact claimed result and its one-shot private claim-origin tuple: issuer,
lease, armed recovery capability, artifact and ignored roots, PID, and thread.
The claimed result registers that tuple only in the process-private capability
registry; neither its public payload nor the later action-fence payload contains
the lease or recovery capability. Successful consumption removes the full
issuer/lease/recovery/root/PID/thread tuple before any final read and retains
only a weak reference to the originating issuer as a consumed-origin tombstone.
That tombstone conveys no lease, recovery, observation, or mutation authority;
it exists only so any later replay can still poison the origin. A wrong or
replayed tuple fails closed and poisons the registered or tombstoned origin.
The preparer then requires the exact recovery capability to remain armed while
revalidating the live lease, named lock, roots, and shrinking deadline throughout
the operation. It revalidates the retained claim before and after the full read
and checkpoints both the armed recovery escape and action lease through result
construction. Its result is process-local, non-copyable, nonserializable, and
invalid after fork. The public payload retains only authenticated digest
projections; the in-process object retains its sealed claimed result and final
observation so validation can recheck the nested evidence. It does not retain
the lease or recovery capability and does not prove authority survives after
return. Current-session, freshness, and topology authentication fields remain
false: this observation is not temporal adjacency or release authority.

Invalid input before the exact claimed fence is established is rejected. Once
that exact object is presented, a missing, wrong, or replayed origin tuple is
recovery-required and poisons its registered originating action; an exact
candidate issuer is poisoned as well. Any later observation, claim, armed-
recovery, lock, deadline, checkpoint, or result failure likewise poisons action
and reports recovery-required while preserving the already armed recovery token
for the owning outer callback. The preparer does not retain an outcome. This is
a dormant action-adjacent fence, not the active controller: it closes the final
cursor-only topology-observation gap at its own code boundary but authorizes no
release, runtime, sequence 2, persistent topology, success outcome, or trading
action.

Contract `phase6d-post-enrollment-start-active-controller-admission-v1`, with
sole status `active_controller_admission_unqualified`, now adds the first
dormant active-controller admission without executing an action. Function
`prepare_post_enrollment_start_active_controller_admission` accepts only the
exact process-sealed claimed action-topology fence and its one-shot private
controller-origin tuple: issuer, active lease, armed recovery capability,
artifact and ignored roots, PID, and thread. It consumes that tuple through
`_consume_claimed_action_fence_controller_choreography`, revalidates the exact
action fence and retained claim, and repeatedly requires the same live lease,
named lock, issuer/daemon session, roots, shrinking deadline, and armed recovery
escape through result construction.

Successful consumption removes the full tuple from the action-fence registry
and retains only a weak reference to the originating issuer as a consumed-
origin tombstone, so replay still poisons the origin without retaining lease,
recovery, or root authority there. After the remaining checks and exact result
construction succeed, the preparer registers that same exact tuple in a
distinct one-shot future-continuation registry bound to the exact admission
result. Any ordinary or asynchronous failure after origin consumption and
before return unregisters any partially installed admission-result and
continuation state, leaves the action-fence registry's weak tombstone intact,
and poisons the originating action. Neither registration enters the public
payload. The result directly retains only sealed nested evidence, is process-
local, non-copyable, nonserializable, and invalid after fork. Private
`_consume_active_controller_continuation` is called only by the code-only
`run_post_enrollment_start_active_controller` tail; no supported runtime surface
can call it. The seam is pop-before-validation and one-shot: an exact-result
attempt replaces the continuation's full origin tuple with an admission-local
weak issuer tombstone across ordinary or asynchronous failure, and makes replay
fail closed and poison the origin without granting an effect.

Preparation positively authenticates only the exact action fence, live issuer/
lock/daemon session, active lease, armed recovery capability, canonical roots,
PID/thread binding, and retained-claim revalidation at the admission boundary.
Those transient checks are not asserted to survive return: current-session,
freshness, and topology-authentication fields remain false. It performs no
Docker, file mutation, release, SQL, provider, topology, or outcome operation
and does not make the prior topology read current for a later effect. An input
of the wrong action-fence type is rejected. Once an exact-type action-fence
object is presented, a
missing, wrong, stale, or replayed origin tuple and any later claim, lease,
armed-recovery, lock, root, deadline, or result failure are recovery-required,
poison the registered or tombstoned originating action, and leave the already
armed recovery capability to the owning outer callback. Release, runtime,
sequence 2, persistent start, topology qualification, success outcome,
shutdown, and every operational or trading authority remain false. In
particular, `active_controller_authorized=false` and
`controller_execution_authorized=false` are explicit payload and result
properties; admission is not controller execution.

The separately admitted effecting-controller code slice is now implemented as
`phase6d-post-enrollment-start-active-controller-v1`, with terminal success
status `post_enrollment_start_confirmed`. Public function
`run_post_enrollment_start_active_controller` has no direct CLI, Make, Compose,
or reusable launcher invocation. The one-shot host orchestrator is its sole
supported caller, and can call it only inside the same private choreography
callback by consuming the exact admission's one-shot continuation. It
revalidates the retained claim, action fence, live lease,
PID-bound issuer session, named outer lock, roots, and deadline, then performs a
fresh 16-read staged-unreleased observation immediately before the effect. The
original 600-second callback deadline is never restarted.

Before release, the controller requires at least 260 seconds of the original
lease budget. It first issues a caller-owned post-effect candidate, then
atomically transitions the exact pre-release recovery capability to the
post-effect controller-outcome state; asynchronous interruption cannot leave a
committed effect with only the old pre-release writer. The old writer is invalid
after transition. That irreversible transition is the conservative release-
attempt admission boundary and occurs immediately before command spawn:
`release_attempted=true` from that point even if interruption prevents the
eventual syscall, and every such failure is retained as post-effect rather than
falling back to the legacy pre-release writer. The bound command runner seals
the exact executable, argv, opening environment projection and digest, timeout,
and output bounds. The
fresh pre-effect pass also requires all deadline, release, and ready final and
staging names to be absent. The exact in-container release command first
publishes owner-only contract
`phase6d-post-enrollment-start-sequence-two-deadline-v1`, binding an absolute
Linux `CLOCK_BOOTTIME` deadline exactly 120 seconds after its issued instant,
the current Linux boot identity by digest, and the fixed release-marker digest;
only then does it publish the release marker. PID 1 reads that same deadline
immediately after release admission and before signal-handler or runtime
composition. Any stale final name, live or abandoned staging name, reboot,
clock regression, or late release fails closed and leaves no readable success
barrier.

The normal supervisor gives its initial full-audit `epoch_rotation` attempt the
same absolute deadline minus five seconds, so runtime initialization cannot
restart or widen the window. One process-bound startup-effect guard is shared by
the repository attempt and a deadline-bound provider wrapper. It requires 50
seconds before a durable SQL call and 16 seconds before bounded provider I/O,
checks again afterward, detects clock regression, fork, or deadline crossing,
and is retired only after exact ready publication. The resulting maximum worker
window is 115 seconds; every work selection checks that cutoff, timeout latches
fatal/abort, and transient startup retry cannot cross it. Long-lived local
probing does not begin until that initial audit succeeds and the owner-only
`phase6d-post-enrollment-start-sequence-two-ready-v1` marker is atomically
published. Marker publication is itself limited by both a five-second local
bound and the shared absolute deadline; a late visibility commit is poisoned so
the reader cannot mistake it for success.

The image-only inspection executable
`autoquant-trusted-time-post-enrollment-runtime-state` implements
`phase6d-post-enrollment-runtime-state-v1`. It validates the release marker and
canonical boot-bound deadline, waits only to that exact 120-second
`CLOCK_BOOTTIME` deadline, validates the sequence-two-ready marker, and then
revalidates all three identities and the still-open deadline before emitting one
bounded nonsecret `sequence_two_ready_observed` receipt. That receipt includes
only `sequence_two_deadline_marker_sha256`, not its numeric instant or boot
identity. The
host controller allows at most 122 seconds for that one Docker exec, while the
in-container absolute deadline remains stronger. The controller separately
requires at least 130 seconds after runtime-state observation, at least 50
seconds after the first successor and persistent-topology pass, and five seconds
before terminal outcome retention; those later reserves are why the pre-effect
gate is 260 seconds rather than merely the 120-second in-container window.

Sequence-2 qualification is not delegated to a caller-supplied repository
attempt. Contract `phase6d-post-enrollment-start-sequence-two-verifier-v1` is a
process-private, exact two-call verifier prepared before the effect from the
admission, issuer, lease, recovery capability, roots, PID/thread, retained
claim, original action deadline, database identity, and exact read-only
configuration. It lazily constructs its private SQL and Supabase resources on
the first call. Its SQL router admits only deadline-guarded verification reads;
its provider wrapper exposes no upload, and it has only the public Ed25519
verifier, never a signer or private key. The verifier uses the exact clock
object sealed into the topology issuer, so its phase cutoffs and the issuer's
original action deadline remain in one host clock domain. The first exact
verification must finish before the original deadline minus 85 seconds and the
second before that deadline minus eight seconds. Only two identical results
plus confirmed cleanup produce `verification_transcript_sha256`. A wrong or
replayed call while the live origin still exists closes the verifier and
poisons the topology issuer.
Every terminal zero-, one-, or two-call path then erases admission, binding,
claim, issuer reference, lease, recovery capability, deadline, PID/thread, and
resources; only inert terminal status plus the binding, configuration, and
optional completed-transcript digest projections remain. A later replay still
rejects but cannot poison an issuer whose reference has already been erased.
The preparer, verifier, and its digests remain non-authorizing and have no CLI,
Make, Compose, launcher, or host-runtime surface.

After that receipt, the controller authenticates the sequence-2 successor
twice around one persistent-topology pass containing stable before/after post-
release namespace observations and binds contract
`phase6d-post-enrollment-start-persistent-topology-snapshot-v1`, whose snapshot
status remains `persistent_topology_snapshot_unqualified` in isolation. That
pass contains three equal database/deadline/release/ready/staging-absence
barriers: the third and final barrier runs after every other topology read, so
later marker drift cannot be hidden behind the final daemon, volume, network,
or inventory observations. After the second equal verifier read, the controller
performs one final runtime-state observation capped at two seconds and requires
its complete receipt and digest to equal the first runtime-state evidence
exactly. Only then may it publish the verifier transcript, successor, or other
success facts. It then
retains exactly one owner-only terminal artifact under
`phase6d-post-enrollment-start-retained-controller-outcome-v2`: either
`post_enrollment_start_confirmed` with the exact pre-effect observation digest,
release/runtime/successor/persistent-topology evidence and persistent-topology
transcript digest, or a fixed progress-sensitive
`recovery_required` outcome after the effect boundary. Reason progression is
exactly `release_outcome_unconfirmed` → `sequence_2_unconfirmed` →
`success_outcome_unconfirmed` → `post_enrollment_start_confirmed`. Sequence
qualification remains unconfirmed until the second equal verifier read after
persistent topology; there is no separate `persistent_topology_unconfirmed`
terminal reason. Reason
`success_outcome_unconfirmed` applies only after two matching sequence reads and
persistent topology qualify but durable success retention has not: those
sequence/runtime/topology facts remain true while overall qualification and
controller success remain false. A post-effect failure is truthful, terminal,
and never authorizes retry; inability to confirm that retention remains an
explicit unconfirmed hard failure. Retention is deliberately two-phase. Both
the controller writer and legacy recovery writer atomically reserve the same
never-removed owner-only global `O_EXCL` slot,
`.post-enrollment-start-controller-outcome-slot`; either writer's partial
reservation excludes the other. Controller preparation makes the slot and
content-addressed outcome durable but keeps that `prepared` artifact publicly
ineligible. Only after the issuer's process-private registry reaches
`post_effect_confirmed` does the publisher, while holding the slot lock
exclusively, move from
`.post-enrollment-start-controller-outcome-commit-staging` to fixed commit
marker `.post-enrollment-start-controller-outcome-committed` and fsync the final
directory entry. Public `committed` load and revalidation hold the slot lock in
shared mode, require commit staging absent, and revalidate the exact slot,
prepared artifact, and commit-marker bytes and inode. Commit failure downgrades
the registry to `post_effect_unconfirmed`; asynchronous interruption after the
exact publicly committed receipt revalidates instead preserves
`post_effect_confirmed`. The legacy recovery writer creates the shared slot with
legacy status `reserved` and keeps that exact inode exclusively locked through
fixed hidden staging-name
`.post-enrollment-start-recovery-outcome-staging` write and file fsync, final
hard-link, first directory fsync, staging unlink, identity check, second
directory fsync, and final byte readback. Only after those checks does it rewrite
and fsync the same locked slot as `retained`, fsync the directory, and read back
the exact slot bytes and inode. Legacy recovery load and revalidation take the
slot lock in shared mode, fsync both slot and directory, require exact
`retained` status with staging absent, and bind both final and slot identities;
a controller-contract slot cannot validate a legacy final. A `reserved` or
partial slot therefore keeps an ambiguous final ineligible even if cleanup
cannot restore staging. Cleanup first renames the final to staging, then tries a
staging sentinel, and finally unlinks the final, accepting only staging-present
or final-absent state. Conversely, a later loader may independently fsync and
confirm a completely written final whose exact locked slot already reached
`retained`.

ADR 0104 completes only the durable graceful-stop targeting prerequisite.
Controller outcome v2 embeds one complete canonical 64-KiB-bounded
`phase6d-post-enrollment-start-durable-shutdown-locator-v1` plus its digest;
the shared outcome reader bound is 128 KiB. Exact historical v1 outcomes remain
loadable with v1 slot/commit markers but are never rewritten and have no
locator. The inert target
`phase6d-post-enrollment-graceful-stop-target-v1` binds a structurally committed
v2 confirmed outcome, its locator, and unqualified v3 start slot/envelope
digests. The inert decision
`phase6d-post-enrollment-graceful-stop-decision-v1` adds a distinct stop UUID,
stop-only replay domain, and stop-only decision. ADR 0105 adds the complete
inert authentication chain: a strict separate stop authority identity, exact
decision statement and v2 envelope, explicit-authority public verifier, and
offline public-only provisioner and detached-signature workflows. Stop
authority installation requires the exact start authority to exist and have a
different public-key digest. The real stop manifest remains absent, and every
currentness and action authority remains false. ADR 0106 adds the strict
currently supported v3-contract retained start-attempt loader and an isolated historical-chain
decision-candidate binder. It reloads and revalidates the committed confirmed
controller outcome v2 and locator, v3-format start slot, external signed start
envelope, reviewed-Git start authority, semantic v2 approval, provenance, and
complete operation/revision/image tuple before deriving and durably publishing
the content-addressed decision-v1 candidate. Its expected digests are review
assertions, not caller-selected target facts. The receipt contract is
`phase6d-post-enrollment-graceful-stop-decision-candidate-receipt-v1` with
status `graceful_stop_decision_candidate_prepared_unqualified`; every live and
stop authority remains false. ADR 0112 adds the separate zero-caller,
read-only recovery surface
`load_post_enrollment_graceful_stop_decision_artifact_receipt`. It uses audited
stable external bindings, reauthenticates that complete historical chain,
requires exact agreement with the candidate, and reconstructs the unchanged
ADR-0106 receipt rather than accepting receipt bytes or persisting a sidecar.
Private pre-publication seams capture descriptor/raw canonical source state as
tagged exact built-in tuple trees containing primitive scalars and exact tuples.
Authority consumers validate literal tags, lengths, and primitive slot types and
read only numeric tuple positions, so no heap tuple-subclass descriptor supplies
authority. Target, decision, and receipt construction use only those snapshots,
never public retained-loader objects or `receipt.public_payload`. Dependency
objects are transient exact-type/identity construction views; their attributes,
properties, serializers, and equality never supply an authority comparison,
and they are never retained in the loaded registry.
There is no public receipt encoder or digest helper. The public loaded wrapper
retains only the exact candidate bytes/path, directory and nine-field file
identity, and source-derived immutable receipt bytes and digest; it exposes no
receipt, decision, outcome, attempt, approval, or other nested truth-bearing
object. Load leaves the wrapper inert, records only a non-authorizing exact
pending binding, and its canonical diagnostic view rejects fact access; no heap
property supplies authority. The explicit
`authenticate_loaded_post_enrollment_graceful_stop_decision_artifact_receipt`
call consumes that pending entry first, fresh-loads the durable chain, compares
the rebuilt primitive snapshot with the immutable load-time snapshot, installs
the active registry entry solely from immutable source and invocation values,
and repeats historical, candidate, and registry checks through return. Wrapper
fields, descriptors, seals, methods, properties, and public receipt objects are
non-authorizing views and never supply a registry value or decision. Every
failed or interrupted path burns that entry; only return ambiguity may leave
the already-owned identity token active. The pending and active registries retain only
the exact outer wrapper weak reference, PID/thread and invocation identities,
and immutable primitive source snapshots; they retain no nested dependency
object. Revalidation consumes the active entry before validation, fresh-loads
and compares solely against that popped immutable record, and keeps it burned
on every terminal path, so success leaves the wrapper inactive again. Heap
properties during the active interval are diagnostic only; the consuming
module-level revalidation result supplies the bounded historical fact.

The operational probe-producer filesystem graph is designed to use only exact
native owner builtins called in the frame that consumes and closes them, with
no raw descriptor, fileno, `ctypes`, or Python owner-return helper. A fixed CPython
launcher now statically registers the exact owner before interpreter
initialization, removes the temporary native name before target code, and
permits only literal profile-specific targets. The operational wheel/image
contains that owner-only launcher and excludes the admission-only bounded
process primitive. The last four operational inline-Python probes now map to
the fixed, no-extra-argv targets `image-schema-contract`,
`post-enrollment-staged-barrier-read`,
`post-enrollment-pre-effect-runtime-absence`, and
`post-enrollment-persistent-barrier-read`; all are callable mappings with null
fixed arguments rather than console-script aliases. The schema projection is
in-memory and imports no filesystem owner. Marker reads use exact `/` to `tmp`
native traversal, immutable bytes and `Stat9` observations, before/after
parent/name/file checks, fixed child-first cleanup, and async-exception
priority; canonical immutable bytes are not published until owners close, and
no mutable authority object is passed to JSON serialization. This
implementation remains
dormant and test-only until the separate admission profile binds exact source
and executable/callgraph receipts, remaining process callsites use their
reviewed native transactions, escaped process sessions are contained or
excluded, and the root-owned read-only runtime, image ID, complete
dependency/RECORD closure, executable/import manifest, and effective mount
receipts are reviewed as one boundary. The trusted container/service
exec boundary must sanitize loader environment before the dynamically linked
launcher starts and deny same-UID tracing/process injection; clearing `LD_*` or
`DYLD_*` inside C is too late. Production performs no user-owned disposable
install or operation-time uv/build.

Repeated marker equality supplies conditional currentness only under an
explicit trusted write-once publisher contract for every final marker pathname
and the absence of a hostile same-UID writer throughout the sequential
multi-marker probe. The current code does not provide an aggregate atomic
filesystem snapshot; it provides bounded sequential observations. Activation
therefore remains blocked until deployment admission proves the
write-once/no-hostile-writer boundary or a compound native snapshot transaction
replaces the sequential reads.

Fixed-probe semantic validation is also conditional on explicitly excluded
selection and spawn boundaries. Each producer captures its stdout/stderr sinks
before any filesystem or schema callback; the process-entry stream selection
must therefore already be trusted. The caller captures daemon/environment
primitives before resolver callbacks and binds an exact executable string plus
`Stat9`, but same-inode executable bytes, loader closure, and hostile external
replacement remain admission responsibilities. Topology, active-controller,
and schema-verifier probes still cross the legacy Python runner/Popen boundary,
which reconstructs mutable environment/cwd state and does not establish an immutable aggregate spawn transaction.
Production activation remains blocked
until the admitted native broker/launcher closes that host-spawn boundary; the
current tuple/parser repair does not claim otherwise.

Closure-owned issuance/choreography live-call tokens and the callback-only exact `RLock` runner are audited here solely for opaque-lease retention and close disposition, not as authentication of mutable choreography, checkpoint, retention, recovery, or effect authority. No held lock or opaque-lease authority crosses a function `RETURN`, generator `yield`, or context-manager handoff.

Mutable `ChoreographyRegistration`, `_ChoreographyCheckpoint`, recovery, post-effect, and controller retention checkpoints/outcome state, and the effect-authority graph are a separate production-activation blocker outside this signoff. Every effect remains blocked until their tuple state is hardened and their entire transitive path proves exact `KeyboardInterrupt`/`SystemExit` identity and cleanup. The legacy unenrolled/enrollment Python launch-lock and runner/Popen spawn paths, hostile same-UID writer/path replacement after validation, and executable/tool-byte admission also remain explicit blockers.

The final TEST-only native issuer choreography freeze now covers Checkpoints
A–O and operation tags 1–15. It retains native ownership of the opaque launcher
lease: Python receives no descriptor, `fileno`, or `detach`, and the registered
C at-fork handler closes and scrubs the child's inherited lease before the
Python child callback clears its closure and heap views. The `inert` →
`activating` → `active` → `burned` lifecycle, exact PID/interpreter/thread
and `RLock` binding, closure-owned live-call tokens, choreography checkpoints,
and recovery, post-effect, and controller-retention records are now covered by
the complete TEST matrix. No held lock or opaque authority crosses `RETURN`,
generator `yield`, or a context-manager handoff.

The exact evidence cut pins native source SHA-256
`da2bc638b92b49a4c1c747d02983558d1dbff80fa7c7c64e16bbefa669e051d5`,
final Checkpoint-O contract SHA-256
`fbe300d11a721bff67329394a00a1be7337de96de23ed816a2ec877d2dbca388`,
and owned-test candidate SHA-256
`65be32ea883ceee022d2ba88781a5342190bf98f5b68c51beee9deeedb3b598d`.
Checkpoint O is TEST-only tag 15, `formal_force_revoke`. It accepts only an
exact empty built-in tuple, covers all 13 phases, requires a completely zero
fail-closed origin and `1 <= q <= UINT64_MAX-3`, and admits exact `ACTIVE` or
`BURNED` outer lifecycle state. `REVOKED` is a real revision-advancing
self-edge, not an inert replay.

Normal O publication installs the canonical `REVOKED` State at `q+1`.
Every attached authority becomes `REVOKED` at `q+1`, every attached witness
becomes `CLEARED` at `q+1`, and every State summary and dependency tombstone is
zeroed. A pre-store hard row publishes State and attached-record terminal
revisions at `q+1`; a post-store hard row advances only State to `q+2` while
the already-detached records remain terminal at their actual `q+1` publication.
Every attached non-durable record has exact `prepared_at_revision + 1`
lineage; a prepared controller receipt is at exact current revision `q`, and a
durable controller receipt is the sole exact `prepared_at_revision + 2`
exception. Its immutable historical/current lifecycle relation permits only
`ACTIVE` → `ACTIVE`, `ACTIVE` → `BURNED`, or `BURNED` → `BURNED`; resurrection
from historical `BURNED` to current `ACTIVE` is rejected.

O performs no clock sample, filesystem or path proof, external-barrier action,
or durability reproof. Repairable semantic mismatches reconcile once to the
exact pre-store or post-store hard row and surface as `OSError`; organically
unreachable persistent corruption of captured immutable record or binding
bytes is never restored or rebound, and forced complete/raw confirmation of
that impossible state fail-stops. Exact `KeyboardInterrupt` and `SystemExit`
identity and cleanup precedence remain covered.

On CPython 3.12.13 and 3.13.3, the isolated O behavior matrix passed 541 tests
per minor (1,082 total), and the full plugin-free A–O suite passed 1,993 tests
per minor with only the same two inherited `os.fork()` warnings. Strict TEST
and production builds passed on both minors (the TEST build retained seven
audited inherited warnings; production retained zero), and `_self_test()`
returned `None` on both. The CPython 3.12 ASan+UBSan run passed; leak checking
alone was disabled because Darwin does not support that sanitizer mode.
Production preprocessing, string, and symbol audits found no Checkpoint-O or
tag-15 identifiers, tokens, methods, or exported symbols.

This closes only the guarded TEST choreography matrix; it does not constitute
runtime or production admission. No issuer caller is operationally admitted,
and the guarded TEST-only native surface grants no Docker, spawn, mutation,
retention, release, or effect authority. The reviewed but non-admitted host
allocates and activates explicitly and closes in `try/finally`.
Validation and a later Docker effect are not atomic, and hostile same-UID path
replacement, the legacy Python runner/Popen environment and spawn boundary,
executable/tool/loader-byte admission, remaining process-callsite migration,
containment, immutable image and effective-mount receipts, and root-owned
read-only deployment remain explicit production-activation blockers.

The ADR APIs have no production caller, receipt decoder, CLI, Make workflow,
runtime consumer, writer, or effect path. Their prerequisite now has a pinned
native build/install, fixed static launcher, image manifest, and packaging CI
matrix; admission receipts, process-callsite migration/containment, and mount
hardening remain open. No reviewed-Git stop loader, currentness
verifier, operation-bound stop replay reservation, admission, terminal stop
outcome writer, effecting CLI or Make executor, Docker caller, or runtime
effect is implemented;
`trusted-time-stop` remains hard closed and reports that no effecting approved
shutdown operator is implemented. ADR 0107 now hardens the existing attempt and
worker only: the exact current `clean_stop` request must produce its own paired
provider readback and durable receipt before clean completion. An unchanged-head
no-candidate result is unconfirmed, and a receipt recovered for an older intent
cannot substitute. Periodic, on-demand, and other non-clean-stop no-candidate
success remains unchanged. ADR 0108 now adds only
`phase6d-trusted-time-head-anchor-clean-stop-terminal-result-v1`: an exact
process-local new-record result binding the request schedule, sequence and
predecessor, current head/anchor/semantic values, confirmed/local counts and
terminal ordinal, receipt UTC, audit/recovery flags, exact-one mutation counts,
and current intent/readback/receipt digests. A PID-bound registry hides the
exact request object, and the worker consumes that identity atomically once
before clearing in-flight state. The background exact-result accessor remains
unused by main. No no-record disposition, provider-terminal currentness,
authenticated wire, durable stop outcome, slot, admission, signal, effect, or
Make surface is added. ADR 0109 next adds one code-only host observer with no
live or effect consumer except ADR 0111's dormant zero-caller composition under
contract
`phase6d-post-enrollment-clean-stop-terminal-reauthentication-v1`. Its one-shot
issuer validates a fresh exact SQL full replay S1, performs a bounded full
authenticated provider pass A, matching names pass B, audited boundaries, late
exact list/GET of terminal `N`, empty `N + 1`, and final provider identity, then
requires a fresh SQL S2 to equal S1. One issuer-owned suspend-aware 120-second
deadline covers every SQL/provider operation; PostgreSQL is connection-level
read-only and the repository surface is snapshot load/discard only. The local
provider wrapper exposes only identity/list/download methods, but the admitted
Supabase credential remains externally writer-capable and its HTTP requests are
not one atomic snapshot. The sealed result is therefore one point-in-time fact,
not freshness, lasting currentness, a durable outcome, or authority. The module
is reviewed-source-bound and Docker-excluded with zero production callers, CLI,
Make/wire/artifact/persistence/signer/upload/effect surface. A durable progress-
sensitive stop outcome/recovery protocol and exact current operation/topology
binding must still precede later slot reservation or effects.

ADR 0110 now implements the dormant filesystem foundation for that protocol.
The Docker-excluded, reviewed-source-bound module is
`scripts/trusted_time_post_enrollment_graceful_stop_lifecycle.py`, and it
accepts only an explicitly injected ignored root's exact `trusted-time` child.
One fixed immutable `.post-enrollment-graceful-stop-attempt-slot` is ordinal
zero, phase `attempt_reserved`, the repository lock point, and the permanent
global replay slot; there is no separately creatable attempt slot or
per-operation root. Every later recognized stage must be a typed
content-addressed file with the next exact ordinal, root digest, and
predecessor digest. Bounded reload
rejects duplicates, gaps, alternate predecessors, skipped stages, and unknown
or future files inside the dedicated lifecycle namespace. The repository has
no generic append, rewrite, delete, reset, retry, resume, or optimistic absence
surface.
Stable inventories expose only an exact validated prefix; inventory or
durability ambiguity yields `retention_unconfirmed` with every prefix receipt
withheld.

The root embeds the signed-v2 envelope, exact locator, and ADR-0104 start-chain
projection only as structural bindings. It does not consume or retain ADR
0106's decision-artifact receipt or historical source artifacts; every
historical-authentication fact stays false, and later admission must
reauthenticate rather than infer authority from storage.

Its exact contracts are
`phase6d-post-enrollment-graceful-stop-attempt-v1`,
`phase6d-post-enrollment-graceful-stop-progress-v1`, and
`phase6d-post-enrollment-graceful-stop-retained-outcome-v1`. The progress
prefix can contain only ordinal zero `attempt_reserved` and ordinal one
`operation_bound_supervisor_bridge_required`; no ordinal two, signal,
post-signal, or success phase exists. The sole terminal publication is status
`recovery_required`, reason
`operation_bound_supervisor_bridge_unavailable`, through a distinct fixed
outcome slot and commit marker that are not another attempt/progress root.
The progress transcript and outcome commit marker are separately
domain-separated by
`phase6d-post-enrollment-graceful-stop-progress-transcript-v1` and
`phase6d-post-enrollment-graceful-stop-outcome-commit-v1`.

The real artifact root has no production creator. Unit tests reserve only
injected temporary roots. ADR 0111 now provides the dormant unqualified
operation-bound ADR-0108 bridge and one-shot ADR-0109 consumption seam, but
positive post-signal and confirmed-success construction remains absent or
unreachable until authenticated live transport, same-lock authority/topology
admission, and lifecycle-v2 integration are separately reviewed.
The module is reviewed-source-bound and Docker-excluded with no CLI, Make,
Compose/Docker, subprocess, signal, provider, SQL, signer, upload, authority
loader, topology reader, admission, recovery executor, effect callback, or
runtime consumer. `trusted-time-stop` remains hard closed.

The exact public surface is limited to canonical record/receipt types, strict
codecs, read-only `load_retained_*` and `revalidate_retained_*` functions, and
the non-authorizing recovery-state inspector. The only writer is the private
`_build_post_enrollment_graceful_stop_lifecycle_repository(ignored_root=...)`
test seam with three fixed private transitions. Its builder has no default
root, and the repository, construction, persistence, owned-descriptor, and FFI
seams have zero production importers.

ADR 0111 now implements only the dormant correlation that ADR 0110 named as
missing. Low-level request and result contracts
`phase6d-trusted-time-head-anchor-clean-stop-supervisor-bridge-request-v1` and
`phase6d-trusted-time-head-anchor-clean-stop-supervisor-bridge-result-v1`
strictly encode one operation, exact ordinal-one lifecycle bindings, exact
supervisor, exact selected worker request, and immutable ADR-0108 terminal
projection. Registration occurs before clean-stop selection; the core stores a
constructor-local five-field work tuple and validates the exact work identity,
core, process, and Thread at bind, issue, and take. The second ADR-0108 consume
returns its registered immutable projection, and private take returns captured
canonical bytes once. Generic clean stop does not issue this result.

Dormant host module
`scripts/trusted_time_post_enrollment_graceful_stop_supervisor_bridge.py`
builds the request from one exact inert, pending ADR-0112 loaded wrapper and
revalidated ADR-0110 attempt/progress. It owns the wrapper's exact pending
authentication and immediate active consumption/revalidation, then burns and
cross-binds one exact ADR-0109 registry snapshot. Its same-process composite
promotes only the exact decision-receipt and historical-chain authentication
facts from that private handoff, the bounded ADR-0109 observation, and an
explicitly unqualified exact-terminal-cross-binding fact. Transport/origin,
currentness, freshness, topology, lifecycle, durability, reservation,
admission, outcome, recovery, signal, teardown, operational control, and
trading authority remain false.

This is not a runnable milestone. Both private core entry points and the host
bridge have zero production callers; no main/background, transport, lifecycle
writer, CLI, Make, Docker/Compose, signal, provider/SQL, or effect surface was
added. ADR 0112 provides the dormant inert-load, explicit-authentication, and
consuming-revalidation flow for the durable ADR-0106 receipt, and ADR 0111 now
owns that exact private handoff. ADR-0110 v1 still stops at ordinal one.

ADR 0116 freezes the remaining graceful-stop work as one non-separable,
design-only dependency chain: authenticated bounded replay-safe host/supervisor
request/result transport for a separately versioned lifecycle-v2-compatible
wire family; same-lock fresh current topology, trusted-head, stop-authority, and
exact-operation admission before reservation or effect; a new immutable
lifecycle-v2 repository and compatible request/result/host-binding family that
consume that admission and retain every pre-CALL intent, separately
authenticated post-CALL result, confirmed-success terminal, and
recovery-required ambiguity without constructing, consuming, or reinterpreting
ADR-0110/0111 v1 state; PID/thread/at-fork invalidation before any live registry
construction; and only then the effect sequence. That sequence retains the
structural v2 wire result, freshly consumes and durably cross-binds an ADR-0109
host reauthentication through the v2 host seam before any
supervisor/source/container/network effect, stops the supervisor then source,
performs exact ID-bound container/network teardown, proves both named volumes
unchanged, performs a distinct post-teardown terminal reauthentication through
a separate v2 seam, and publishes one durable outcome. A missing or ambiguous
result after reservation is recovery-required and never retry evidence. This
preserves ADRs 0111 and 0112's accepted transport → same-lock admission →
lifecycle-v2 order while keeping their v1 types dormant. The v2 family must
reject v1 contract strings, bytes, decoded objects, attempt/progress receipts or
digests, host composites, scalar/digest adapters, and every mixed-version root,
prefix, directory, or object graph; v1 decoders must reject v2 in the opposite
direction, and wrapping v1 bytes in a v2 envelope is forbidden. The transport,
admission, lifecycle schema and contract IDs, worker association, v2
historical-receipt handoff, cross-version import/decoder boundaries, fork
mechanism, effects, both reauthentication bindings, recovery operator, and
numeric deadlines remain unimplemented external blockers. ADR 0116 changes
documentation only; `trusted-time-stop` remains hard closed.

ADR 0112's current private handoff is bound to ADR 0111's v1 bridge and is not a
v2 input. A later implementation review must choose either a separately
versioned ADR-0112 consumed-snapshot seam bound to the v2 bridge identity or an
independent v2 loader/consumer of the same historical durable sources. Direct
v1↔v2 negative vectors and an architecture/import guard proving that v2 cannot
reach v1 lifecycle loaders, codecs, builders, or host binders are mandatory
acceptance evidence; this plan does not select the concrete schema or handoff
implementation.

The ADR-0111 static freeze includes a mandatory raw-byte manifest for every
regular Python source below the exact `apps`, `packages`, and `scripts` roots.
The only lexical prune is third-party `apps/web/node_modules`; all symlinks
outside it and all first-party Python path or byte changes fail review. The
walker also rejects native extension families, legacy sourceless bytecode, and
source/native anomalies inside `__pycache__`. Standard interpreter-generated
or crafted `.pyc` and `.pyo` files are rejected everywhere; Git/Docker ignore
rules are not a bytecode trust exception. A distinct path-framed bootstrap
manifest covers `.python-version`, `pyproject.toml`, `uv.lock`, the exact hashed
native build-constraint closure, the test-launcher builder, executable-image
manifest helper, exact Hatch native hook, and the bounded-process,
owned-descriptor, and launcher C sources and rejects alternate local build
configuration.
Make and CI set non-overridable `PYTHONDONTWRITEBYTECODE=1`, run the project-
independent architecture gate before project sync/build/import work, rerun it
after installation/native packaging, and keep later gates cache-free.

The exact bootstrap is
`uv run --isolated --no-project --no-config --offline --no-python-downloads --python 3.12 python -I -B scripts/check_architecture.py`. It disables project and persistent-config discovery, uses an
isolated environment and an already installed offline Python 3.12, excludes
workspace/`PYTHONPATH` imports, and writes no bytecode. Run it directly before
parsing Make on an unreviewed checkout. CI places it in a standalone prerequisite
job before backend or native sync/build and repeats it after those operations.
The interpreter and standard library remain trusted deployment inputs.

The Python manifest intentionally does not attest vendor `node_modules`,
ordinary third-party `site-packages`, or startup hooks such as `sitecustomize`;
those remain controlled trusted-environment inputs. The private native owned-
descriptor extension is separately source/build/origin/byte/image-manifest and
runtime-mount attested and is not admitted by that generic exception.
Full raw digests pin the Makefile and CI workflow around that command, including
step reachability and failure propagation. GitHub workflow execution and
required-check branch protection remain external trusted controls rather than
facts established by ADR 0111.

The code-only one-shot host execution layer is now implemented under contract
`phase6d-post-enrollment-start-host-orchestrator-v3`. Its separate outer field
`orchestrator_status=terminal_outcome_retained` never replaces the nested
controller or legacy terminal `status`. Canonical
`phase6d-post-enrollment-start-execution-approval-v2` bytes are accepted only
inside the content-addressed signed
`phase6d-post-enrollment-start-execution-approval-v3` envelope. Execution-facing
contracts are `phase6d-post-enrollment-start-execution-attempt-v3` and
`phase6d-post-enrollment-start-execution-admission-v3`.
`load_post_enrollment_operator_attested_execution_approval` authenticates the
exact reviewed `100644` authority Git blob for the nested v2-approved revision,
strict public key, plain-Ed25519 statement, complete v2 semantics, exact
proposed revision/image tuple, and stable base-image provenance. The host
requires current `HEAD` to equal that revision before Docker, issuer,
runtime-input, or reversible preflight. Under the issuer flock, owner-held staged-input creation and
all later reversible daemon, Compose, runtime-input, and isolated existing-image
diagnostics complete before `verify_and_write_existing_image_admission` writes
an independent just-in-time witness for the same revision, image IDs, reviewed-
source digest, and provenance. Witness creation/load, execution admission, and
the choreography sample the same native suspend-aware clock domain
(`CLOCK_BOOTTIME` on Linux or `mach_continuous_time` on Darwin), so system sleep
consumes the witness's required 605-second headroom.

After the choreography lease is acquired, sequence-1 preparation and
`_prepare_reviewed_topology_creation` confirm the owner-held bindings, reviewed
effect-only Compose projection, and exact-empty container/network inventory
without mutation. Only then does `reserve_post_enrollment_execution_attempt`
permanently create the host-wide owner-only
`.post-enrollment-start-execution-attempt-slot` with `O_EXCL`, fsync, and exact
readback. One-shot consume revalidates the exact reviewed authority, envelope,
nested v2 approval and provenance, current witness, and permanent slot
bytes/inode. The host stores
`mutation_may_have_begun` before
`_execute_prepared_reviewed_topology_creation` can issue effect-only Compose
`create`. Confirmed pre-slot failure leaves the slot absent and the same stable
approval reusable without repeated human approval; reservation or later
ambiguity is permanently consumed. The unchanged slot filename treats every
exact complete historical
`phase6d-post-enrollment-start-execution-attempt-v2` slot as consumed; partial
or unknown state is retention-unconfirmed. V1 wrappers, unsigned-v2 execution,
and old approval-artifact-only shapes hard reject. The process-sealed admission
remains non-authorizing in isolation.

The host executor owns the topology issuer's single flock from before owner-
held staging and reversible preflight through exact-empty prepared-create
validation and reviewed Compose `create --no-recreate` through the complete
callback unwind and exact close, whether that path confirms pre-claim teardown,
retains a terminal, or ends in fatal manual classification. The issuer seals the authenticated created
observation before returning it, so a lost return can still drive only the exact
pre-claim teardown. The effect-only Compose input labels both services and gives
the default attachment a full domain-separated, issuer-session-derived network
name plus the exact issuer-session invocation label. The derived-name collision
is checked before create; post-create, staged, action, persistent, and teardown
observations require both values, so wrong-session or missing-label resources
fail closed. The fixed legacy network remains untouched, and cleanup uses only
authenticated container IDs and the exact authenticated network ID, never a
name or broad Compose target. Its materialization owner adopts each of the four
exact staged-input inode records inside the materializer, closing the
asynchronous CALL-to-STORE cleanup gap without any directory sweep. The only
network-only partial-create case accepted for cleanup has the exact derived
name and invocation label, two stable empty inventory reads, and zero
containers; cleanup removes its exact network ID without a container-remove
call. Created topology truth, its digest, and the four private staged-input
digests are registered atomically as one in-process value.

The post-enrollment projection injects four private expected SHA-256 bindings
into the supervisor only: the database URL bytes and the three head-anchor
input bytes. The fixed legacy/base Compose validator requires those variables
to be absent and grants no start authority; supervisor main requires all four
because only the dynamic post-enrollment topology may start it. The loaders
hash the exact bytes they read and compare before decode or use. The fixed
nonsecret consumed-input marker is published only after all four comparisons
succeed. A mismatch exits with code 2 before marker, readiness, or claim and
keeps the exact authenticated exited supervisor eligible for pre-claim ID-only
teardown. Restoring the staged path cannot qualify the failed attempt. Neither
the marker nor command output publishes the private digests.

The only sequence-1 path is signer-free contract
`phase6d-post-enrollment-sequence-one-read-only-reauthentication-v1`: it has
read-only SQL/provider capabilities and a public Ed25519 verifier. It is
prepared against the exact still-`unbound` recovery tuple before topology
mutation, is invoked only after staged-input retirement, and must finish before
the unchanged 260-second controller reserve. Staged-input retirement is an
exact descriptor-anchored, restartable state machine; interruption never turns
cleanup into continuation. The fixed order is prepare sequence 1; return the
exact-empty prepared-create fence; reserve the permanent attempt slot; consume
and revalidate approval, witness, and slot; store the mutation flag; execute the
prepared effect-only create; start and qualify the source; start the supervisor
and authenticate consumed-input barrier readiness; retire all staged inputs;
issue staged ordinal 1 and the pre-claim fence; enter the conservative
no-teardown marker-call boundary; invoke sequence 1 while recovery is still
`unbound`; checkpoint the binder as `claim_admitted` immediately before claim
`O_EXCL`; retain and read back the claim, consume the exact binder inside the
writer before its return, and commit the fully populated recovery tuple by
storing `armed` last; complete ordinal 2 chronology; issue the
final action fence and controller admission; prepare the read-only sequence-2
verifier; and run the exact active controller. The action and recovery bounds
are 600 and 605 seconds from one suspend-aware clock origin; the controller's
260-second pre-effect requirement is unchanged.

Failure may run the exact reviewed teardown only before the marker-call
boundary. It authenticates the sealed live inventory, removes only the exact
container IDs and exact network ID, and never removes either named volume or
uses label/name-scoped Compose down. The host stores a conservative
no-teardown flag before calling the authoritative marker. From that CALL
boundary onward no ordinary or asynchronous failure tears down. The exact
read-only state query retains legacy recovery only when recovery is `armed`;
an unarmed, advanced, ambiguous, or unclassifiable state instead produces fatal
manual review while preserving the topology and whatever evidence is already
durable. Failure at or beyond reservation, including pre-claim teardown, is
projected conservatively as fatal because the permanent attempt slot is
consumed or ambiguous. Confirmed failure before reservation instead retires
owned inputs, leaves the slot absent, and preserves the same stable approval for
a later explicit attempt. The
standalone isolated host
CLI disables abbreviation and exposes only
`--operator-attested-approval-artifact` for the canonical v3 envelope and
`--runtime-env-file` for the owner-only runtime environment file. Its sole
public entry is `run_operator_attested_post_enrollment_start_once`. It is not
wired into Make, Compose, worker, trader,
ordinary startup, shutdown, readiness, exposure, broker, or trading paths.
The effecting function rejects an ordinary import call; only the attested
isolated `__main__` path may invoke it.
The CLI accepts only a terminal returned or raised by the current process-
sealed invocation; an unrelated prior global outcome is never substituted for
preflight, cleanup, close, replay, or asynchronous failure. Once either legacy
recovery or controller retention commits, the live issuer registry holds that
exact receipt. The controller, host callback, and outer scope durably
revalidate and adopt only that current-scope identity across CALL/STORE or
CALL/RETURN interruption; they never search the global artifact directory for
a substitute.

ADR 0100 implements the public-material provisioning prerequisite for a future
authenticated external operator attestation. The dedicated private Ed25519 key
remains outside the repository and runtime; only its exact raw 32-byte public
key may enter the isolated offline provisioner. The public bytes must be one
canonical compressed Edwards25519 non-identity prime-subgroup point; identity
or other torsion, mixed-subgroup, noncanonical, and off-curve encodings fail
before candidate publication. Preparation writes an owner-only content-
addressed candidate outside the source tree. Installation is a separate
command that requires both the reviewed authority-artifact SHA-256 and reviewed
raw-public-key SHA-256 before it can copy identical canonical bytes to fixed path
`infra/trusted-time/post-enrollment-operator-attestation-authority.json`.
The path remains intentionally absent until that explicit operator step.

The eight-field manifest freezes contract
`phase6d-post-enrollment-operator-attestation-authority-v1`, Ed25519, key ID
`aqt-post-enrollment-start-operator-ed25519-v1`, the canonical Base64 public
key and its SHA-256, service/status, and replay domain
`github.com/km8trix/AutoQuantTrader/production/trusted-time/post-enrollment-start/operator-attestation/v1`.
The fixed file is excluded from image build context. The workflow provides no
private-key generator/reader, signer, environment or standard-input key
channel, Docker, network, database, controller, execution-admission, attempt,
or runtime effect. ADR 0103 is the sole production consumer and reads only the
exact reviewed Git object, never mutable working-tree bytes. Once an operator
installs the exact reviewed public material, the source diff still requires
normal review, commit, merge, and rebuilt provenance. ADR 0101 below separately
defines inert signed-attestation bytes and verification without weakening the
existing v2 approval, attempt-local witness, or explicit execution decision.
Public-key installation alone authorizes nothing. See
[ADR 0100](adr/0100-post-enrollment-operator-public-key-provisioning.md).

ADR 0101 now implements that separately reviewable signed-attestation byte
boundary as a pure dormant codec/verifier only. Its canonical statement fixes
Ed25519, the exact ADR-0100 authority artifact/contract/key/public-key/replay-
domain identity, decision `approve_one_post_enrollment_start_attempt`, exact v2
contract, and SHA-256 of the exact canonical newline-terminated v2 approval
bytes. Plain Ed25519 signs those complete statement bytes directly, not their
digest and not Ed25519ph. The envelope contract, inert at this layer,
`phase6d-post-enrollment-start-execution-approval-v3` Base64-wraps the exact v2
bytes and binds their digest, the nested statement and its digest, and an exact
64-byte signature.

The verifier requires the authority object explicitly and returns only
`operator_signature_authenticated_unqualified` under verification contract
`phase6d-post-enrollment-operator-attestation-verification-v1` and fixed service
`trusted-time-post-enrollment-operator-attestation-verification`. Pure
statement/envelope canonicalization remains in the domain module; adapter
`Ed25519PostEnrollmentOperatorAttestationVerifier.from_authority` owns only the
public-key operation and returns
`TrustedTimePostEnrollmentOperatorAttestationVerification`. The result binds
the authority, public-key, v2, statement, and envelope digests while every
exposed operational authority remains false. It does not semantically decode
v2, establish freshness or durable replay exclusion, reserve the fixed attempt
slot, admit execution, or authorize the controller. That slice adds no
authority-file loader, fallback/default key, signer, private-key API, CLI, Make
target, or host/runtime change. ADR 0103 is now its sole production
consumer inside the complete v3 gate; the fixed authority file remains absent.
See
[ADR 0101](adr/0101-inert-post-enrollment-operator-attestation-verification.md).

The authority domain enforces the strict canonical non-identity prime-subgroup
point rule at construction and decoding, and the adapter independently repeats
it before key construction and signature verification. A backend accepting an
arbitrary 32-byte identity, torsion, mixed-subgroup, noncanonical, or off-curve
encoding cannot produce an authenticated verification result.

ADR 0102 now implements only the next code-only offline artifact workflow. The
`prepare-statement` operation accepts an explicit external content-addressed
ADR-0100 authority candidate, exact content-addressed v2 approval, reviewed
authority/public-key/v2 SHA-256 values, and an external mode-`0700` directory;
it exclusively retains exact mode-`0600` signing bytes at
`trusted-time-post-enrollment-operator-attestation-statement-<sha256>.json`.
After an independent signer returns only a raw 64-byte signature,
`verify-signature` additionally pins the statement and signature SHA-256 values,
reopens and cross-validates every public artifact, verifies plain Ed25519, and
retains only
`trusted-time-post-enrollment-start-execution-approval-v3-<sha256>.json` in a
separate external mode-`0700` directory.

Both Make targets use only explicit paths and reviewed digests. They have no
private-key/generator/signer, environment or standard-input, network, database,
Docker, subprocess, controller, attempt, admission, host, or runtime surface;
the script is excluded from Docker build context, and no production caller
invokes either public workflow operation. Receipt contract
`phase6d-post-enrollment-operator-attestation-artifact-receipt-v1` remains
unqualified with statuses
`operator_attestation_statement_candidate_prepared_unqualified` and
`operator_attestation_envelope_verified_unqualified`. Its v2 check is explicitly
`canonical_top_level_identity_only_semantics_unqualified`; signature
authentication is respectively `not_authenticated` and
`authenticated_unqualified`, never semantic approval. See
[ADR 0102](adr/0102-offline-post-enrollment-operator-attestation-artifacts.md).

ADR 0103 now implements the atomic admission integration. It authenticates the
exact reviewed authority Git object, requires v3 with no unsigned-v2 downgrade,
semantically revalidates the exact wrapped v2 bytes, binds all authority/
statement/envelope/v2 identities into the attempt and admission contracts,
preserves the current slot and consumed v2 history, and reverifies the
authority, envelope, approval, slot, provenance, and fresh witness at
reservation and consumption. ADR 0102 itself satisfies none of those
requirements. See
[ADR 0103](adr/0103-atomic-operator-attested-post-enrollment-execution-admission.md).

This is implemented code, not an admitted live operation. No immutable
revision/image set or external execution artifact has been operationally
admitted for this new executor, and no release was executed while implementing
this slice. Stable provenance and its exact external approval are an initial
domain boundary; a just-in-time witness and explicit execution decision are
attempt-local. A confirmed pre-slot failure does not force the human approval
to be repeated. Every readiness, re-arm, exposure, broker, paper-trading, live-
trading, and operational-control authority remains false. The next
implementation boundary is operational provisioning and review, not more
execution-admission code. Only after the real reviewed authority and external v3
artifact exist, exact merged provenance is rebuilt, and a fresh image witness/
runtime preflight plus explicit isolated invocation decision complete may a
start be considered. Only after a confirmed start may a separate sealed
watchdog provider-terminal issuer authenticate the complete new suffix,
bind two stable namespace passes to their exact digest/count/terminal identity,
prove that no higher sequence exists, and capture its own independent
monotonic instant. That future deployed runtime, not dormant v1, must apply the
360-second stale threshold with equality stale and every stale result
unavailable before any watchdog consumer is designed or qualified. See
[ADR 0095](adr/0095-dormant-provider-neutral-trusted-head-watchdog-state.md).

## Phase 6 - deployment, browser security, and operational hardening (weeks 16-18)

### Build

- Migration 0035 is applied and postflight-verified on runtime Supabase with
  zero trusted-time histories. ADR 0092 locally composes ADR 0086/0090 with
  the exact authenticated Cloudflare/Netnod source, reviewed uncertainty bound,
  fixed host, and immediate/20-second schedule. Offline and live runtime
  admission passed, but the retained live window is `not_qualified` because the
  second source was not combined. Preserve that outcome. ADR 0093 approves the
  exact Cloudflare/System76 Virginia v2 authority while retaining the strict
  selected-plus-combined and 100-millisecond rules. Its exact bytes and images
  are admitted, and its retained
  `phase6c-live-trusted-time-qualification-inspection-v5` window is qualified
  with seven of eight evaluations recorded; one intermittent System76 `D`/
  `source_unavailable` observation recovered under the unchanged rule. Treat
  this as point-in-time evidence without claiming unpublished System76
  availability, SLA, upstream, redundancy, or leap-smear properties. ADR 0094
  now implements the signed sparse-head contract, durable intent/readback/
  sealed-second-`GET` receipt recovery, bounded separate-Supabase adapter,
  paged full-audit worker, applied migration 0036, secure four-input launcher,
  and exact 0036-head/catalog image admission. The pre-admission-hardening
  baseline passed 103 focused tests and the actual Compose verifier; that
  historical result does not cover the later typed-terminal observer or
  approval-bound v2 receipt path. The hardening is merged at
  `2fcd3cdcf343bf4ef0630b2923190df7556c630d`, has local verification, and the
  bounded V5 runtime diagnostic passed on 2026-08-07. The then-required fresh
  image build/admission and exact approval subsequently completed for the
  confirmed first-enrollment operation; that tuple is consumed and historical.
  The separate Healthy Free-plan
  project and its Data-API-disabled, exact private primary bucket now have
  retained dashboard evidence. On 2026-08-04, approved provisioning SQL SHA-256
  `68be661f65b3f6b45d7732744790d8155aeb4aae75d6311d196d711e39321135`
  committed; postflight proved the exact six-policy no-reader catalog and
  dedicated writer. On 2026-08-05, the writer password was rotated and verified,
  and the signing/Auth/authority artifacts were exclusively generated outside
  the repository and runtime-decoder-validated. The first real-control-bucket
  behavioral proof authenticated, inserted, and listed one retained synthetic
  object, then failed closed at authenticated read because the deployed v1
  SELECT contract omitted the Storage authenticated-info operation. Exact
  rollback-only capability-probe passed and retained exact-catalog postflight;
  the approved atomic v1-to-v2 upgrade is applied and postflight-verified.
  The separately approved same-object resume then passed without a fresh
  canonical insert: retained evidence, list, and read were exact; every
  overwrite, upsert, update, delete, noncanonical-namespace insert,
  real-control-bucket insert, anonymous insert/list/read, and public-read probes
  were denied; and the final object and namespace were unchanged. Its owner-only
  pass file SHA-256 is
  `85b225f908efa87ce3c424a3bacf77023a4ed07aba18af0c19589613ab7f97c8`,
  with internal `evidence_sha256`
  `5072b832a6fa3ae01009aa5ff2f89c30e8c24593f87273377bb67dc2afda6171`.
  Fresh parse-only Compose and historical immutable-image admission passed
  without granting authority or new exposure. The earlier owner-only admission
  artifact SHA-256 is
  `10e7feea32ed2ad093e59f7075e60147af5fa4835986e7772262a44f64a81b07`,
  binding immutable source image
  `sha256:c3d81b9e1fa19b1d8131c99554da2c8ee8e6b928f27444293e82b237a24371a0`
  and supervisor image
  `sha256:06944ec20029fca39db5e8069f3cb3d1397333304cd6ca70343bf2c6fff312ba`.
  The later drifted artifacts `b78bda0469077672beacbb746d0278db8b4f84dc5aead65d155c61b98ba4d0d7`
  and `a119b19699c4ce97a13c207d47a9c80c796194d71c99ace97489800838d1dabe`
  and their ADR-0094-recorded image pairs are also historical and authorize no
  retry. At the 2026-08-07 pre-build review, these three were the retained
  content-addressed `image-admission*.json` artifacts. They use a superseded v1
  schema, omit the captured `git_revision`, and are rejected by the current v2
  loader.
  The historical secure-launcher runtime admission was
  `ATTEMPTED_NOT_ADMITTED`. It was followed by a fresh image admission,
  fail-closed unenrolled receipt, exact single-use approval, and confirmed
  ADR-0097 `new` enrollment on 2026-08-08. The retained owner-only evidence
  proves sequence 1 and no sequence 2; normal-supervisor enrollment remains
  hard-disabled. A fresh secretless image build/admission from exact merged
  revision `0fc52b17ef50d597ed40bd8dd6b5ca4fdf6c3523` passed on 2026-08-09.
  Its non-authorizing artifact SHA-256
  `1187b1f46357aa2074a71c3654faca82bc77f6d5941464c86a91fdc144f146de`
  binds source image
  `sha256:a1e8f25e76874b092c863b41a4bc11187b623885fc51260dd23cf6d6acf604e9`
  and supervisor image
  `sha256:4954613be6d192cc315bfae614ee3944003c7124fc48d1d3408b3dcb41c8547c`.
  That tuple predates the staged-release code and is historical build evidence,
  not an approval or usable admission for a later revision. A fresh secretless
  build/admission from exact staged-release merge revision
  `6c4f89d9745bac380ef370663d9fb54495be95bc` also passed on 2026-08-09. Its
  owner-only, non-authorizing artifact SHA-256
  `b6145e6a79b5ea818dd2318154ceedd5abb52b84b74f559b0910b7b94e6dc334`
  binds source image
  `sha256:70c600e4b2c51980541b78fbcbbf121487c12c09a2cfcfc569a83883a87c3c3f`
  and supervisor image
  `sha256:10fce1ef4031cd19bd4e88f544a11948894e0d0ba23116ded5f40a5173b7ef96`.
  It grants no authority or new exposure and predates the current sequence-2
  observation code. ADR 0098 implements
  only the pure canonical decoder, unambiguous owner-only loader, and non-
  authorizing old-evidence/new-target review projection. ADR 0099 defines the
  exact single-use start and graceful-stop lifecycle and now includes the
  dormant durable retained-claim primitive, in-container pre-mutation release
  barrier, read-only exact sequence-2 postcondition issuer, and pure
  claim-to-successor binder. The issuer can only authenticate an already-
  existing sequence-2 `epoch_rotation`; the binder emits only
  `successor_candidate_unqualified`. Neither is wired through worker/main,
  Compose, Make, or a host launcher, and all authority remains false. Any
  retained enrollment claim still blocks normal start and unenrolled admission.
  ADR 0104 additionally freezes the complete durable shutdown locator inside
  controller outcome v2 and sealed non-authorizing graceful-stop target and
  decision projections. Historical v1 outcomes are locator-unavailable. The
  stop replay domain and decision are distinct from start. ADR 0105 adds only
  a distinct strict public authority identity, signed-decision codec, explicit-
  authority verifier, and offline public candidate workflows; the real stop
  authority remains absent and installation requires a public key different
  from the reviewed start authority's public key. ADR 0106 now supplies the
  supported v3-contract start-attempt loader and offline decision-v1 candidate
  writer. It reloads and revalidates the exact confirmed outcome v2, locator,
  v3 slot, signed start envelope, approved Git authority, semantic v2 approval,
  provenance, and start tuple before construction; historical v2 attempts and
  v1 controller outcomes remain ineligible and immutable. The separate
  `prepare-decision` Make workflow retains only an inert candidate. No signer,
  reviewed-Git stop-authority loader, stop-attempt slot, current topology/head
  proof, effect admission, stop outcome/recovery, effecting CLI, or runtime
  caller exists; `trusted-time-stop` continues to exit 2. Durable recovery must
  be designed before reservation. ADR 0107 makes the current rule explicit and
  fail closed: only a receipt created by the exact current `clean_stop` request,
  with both paired readback and receipt identities, can complete clean stop.
  ADR 0108 preserves that one new-record completion in a sealed process-local
  result and requires atomic one-shot adoption by the exact request identity;
  replay, scalar-equal cross-core substitution, copy, drift, serialization, and
  fork fail closed. Unchanged-head no-candidate completion remains unconfirmed,
  and a recovered prior receipt cannot substitute. The exact-result background
  accessor is not composed into main and adds no no-new proof, stable provider
  terminal, durable outcome, slot, admission, signal, effect, or operational
  target; other request reasons keep their existing no-candidate behavior. ADR
  0109 adds only a bounded S1/provider/S2 reauthentication with full two-pass
  remote audit, late terminal GET, empty-next check, and final identity; its
  only consumer is ADR 0111's dormant zero-caller composition, and it adds no
  durable operation association or live/effect consumer. ADR 0110
  adds only the dormant filesystem lifecycle: one fixed immutable ordinal-zero
  root is also the permanent replay slot, followed by typed append-only hash-
  chained records and one recovery-required terminal publication. Its real
  artifact root has no production creator, and no post-signal or
  confirmed-success constructor, admission, recovery executor, or effecting
  consumer exists. ADR 0111 adds only a dormant exact preselection bridge:
  canonical structural request/result wire, exact WorkRequest/core/thread
  association, immutable second-consume ADR-0108 export, and one-shot ADR-0109
  host cross-binding. Its request builder now owns exact ADR-0112 pending
  loaded-wrapper authentication and immediate active consumption/revalidation,
  binds the source-derived immutable receipt snapshot to the exact request and
  bridge identity, and rejects raw/scalar/copy/replay/fork/drift substitution.
  The composite promotes only
  `decision_artifact_receipt_authenticated` and
  `historical_start_chain_authenticated` from that handoff. The host and core
  private entry points remain uncalled; authenticated transport, current
  topology and stop-authority admission, lifecycle v2, later-live at-fork
  handling, durability, outcomes, and all effects remain deferred. ADR 0116
  now freezes those deferrals as one design-only five-gate dependency order:
  lifecycle-v2-compatible transport, same-lock current topology/trusted-head/
  authority/operation admission, lifecycle v2 with a separately versioned
  request/result/host-binding family, fork-safe live ownership, and only then
  effects. The transport-authenticated v2 result stays structural until a fresh
  pre-effect ADR-0109 observation is consumed, cross-bound through the v2 host
  seam, and durably retained. Only after that binding may the supervisor stop
  precede source stop, exact container/network teardown, and both-volume
  preservation; a distinct fresh post-teardown terminal reauthentication
  through a separate v2 seam then precedes durable outcome. ADR-0110/0111 v1
  types, bytes, receipts, binders, and adapted projections remain forbidden as
  v2 inputs, every v1↔v2 mix must reject, and the historical-receipt v2 handoff
  remains an explicit schema/loader choice. Every post-reservation CALL/STORE
  ambiguity is recovery-required without automatic retry. No component of that
  design is implemented or authorized, and the stop target continues to exit 2.
  Claim persistence now uses one globally single-use fixed slot and rejects any
  current or legacy per-operation claim. An import-only coordinator checks the
  exact enrollment evidence before reauthentication and before and after claim
  retention, closes the read-only sequence-1 issuer, retains and revalidates the
  claim against its canonical owner-only artifact root, and returns only an
  unqualified handoff with an inert full-container-ID-candidate
  `docker container exec` argv. A second import-only contract validates an exact
  caller-supplied, never-started two-container topology candidate against the
  approval, immutable images/configuration, stable daemon and named-volume
  identities, two equal submitted project inventories, exact Compose roles,
  complete mounts/hardening, and all execution-bearing `created` state fields.
  It retains only digest projections and separate inert source-first
  `docker container start` argv values. A third import-only contract binds an
  exact caller-supplied staged-running-but-unreleased candidate to that prior
  snapshot. It requires exact nonterminal and unrestarted running containers, a
  healthy source, the fixed consumed-input marker, absent release and release-
  staging markers, and all four staged host inputs reported retired. It retains
  only nonsecret identities and digests. Those pure seams perform no I/O. The
  separate dormant bounded reader now owns the exact lock/daemon Docker
  observations for both topology contracts, rejects duplicate-key and otherwise
  ambiguous raw JSON, and returns only HMAC-sealed, non-authorizing provenance
  envelopes. Pure pre-claim and pre-release fence contracts now authenticate
  the created/ordinal-1 and pre-claim/ordinal-2 same-session chains respectively,
  with statuses `pre_claim_same_session_topology_fence_unqualified` and
  `pre_release_same_session_topology_fence_unqualified`. They authenticate no
  clock, claim, freshness, action-current topology, or proximity to release; a
  cached ordinal 2 is therefore valid only as inert structural evidence. The
  code-only claimed pre-release chronology contract now rejects that cached path
  by requiring a count-1 cursor/pre-claim, performing real claim retention and
  revalidation, requiring a second consecutive cursor still at count 1,
  requesting ordinal 2 from that issuer, binding pre-release, requiring a third
  consecutive cursor at count 2, and revalidating the claim. Cursors use
  contract `phase6d-post-enrollment-topology-observation-cursor-v1`; the claimed
  chronology status remains
  `claimed_pre_release_topology_fence_unqualified`. They have no direct CLI,
  Make, Compose, or ordinary-launcher wiring; only the exact one-shot host
  orchestrator composes them. The new seam
  rejects preissued ordinal 2 only within its own call; its final cursor is not
  a full topology reobservation. The new private callback seam now supplies a
  one-shot exact issuer/PID/thread/session/authentication-capability-bound lease
  only on a fresh issuer, plus one fixed absolute 600-second monotonic deadline
  with equality expired and Docker timeouts shrinking to at most two seconds.
  Raw issuer use or close during the callback poisons the issuer but cannot
  release the outer flock before unwind. The additive leased preparer
  checkpoints that token around the unchanged claimed chronology and returns
  the exact existing v1 payload; its result does not retain the token or prove
  the callback remains active. Its exact-identity-bound process-local result is
  non-copyable, nonserializable, invalid after fork, and not reloadable after a
  crash. Every failure after claim preparation begins is recovery-required,
  while no recovery command exists. The new exact claim-bound callback-local
  retention capability shares the action lease's monotonic origin. All action
  expires at equality with `start + 600 seconds`; the sole retention-only bound
  expires at equality with `start + 605 seconds` and is never reset. It may
  retain at most one content-addressed pre-release outcome under contract
  `phase6d-post-enrollment-start-retained-recovery-outcome-v1`, with status
  `recovery_required`, only when the exact retained claim receipt remains
  available. Only an already claim-bound capability survives action poison or
  the 600-second equality boundary; an `unbound` or `claim_admitted` token is
  revoked. Completion is
  bound to the exact revalidated outcome receipt and inode. Binder issuance is
  itself admitted by a one-shot claimed-fence authorization bound to the exact
  issuer, lease, capability, roots, PID, and thread; `finally` revokes any
  authorization not consumed before ordinary or asynchronous issuance failure.
  The fixed binder checkpoints those roots, the live lease, flock, and action
  deadline immediately before the claim writer's `O_EXCL` boundary and makes the
  mandatory `unbound` to `claim_admitted` transition. Binding requires that
  state, revalidates the exact claim and deadline, arms while atomically revoking
  the binder, and then revalidates the claim again. Pre-arm failure revokes and
  poisons; post-arm ambiguity is `unconfirmed`. It never unlinks, replaces, or
  retries a possibly durable outcome and never restores action authority. The
  claim, recovery, final action-topology, and controller-admission seams do not
  create or mutate topology, publish or execute the release marker, observe or
  mutate sequence 2, or grant authority. The distinct final observation
  performs one exact 16-read
  staged-unreleased pass under the same active lease after ordinal 2 and cursor
  3, and the claimed action fence consumes the claimed result's private one-shot
  issuer/lease/armed-recovery/roots/PID/thread origin tuple before binding the
  observation back to that exact process-sealed chronology. It continuously
  requires the recovery capability to remain armed under the same live lock and
  deadline, without creating ordinal 3 or cursor 4. Full origin material is
  erased at consumption; only a non-authorizing weak issuer tombstone remains
  for replay poisoning. The active-controller admission consumes the next exact
  action-fence origin tuple, repeats the claim/lease/armed-recovery/root checks,
  removes that full registration, retains a weak issuer tombstone for replay
  poison, and transfers the tuple only to its exact process-private one-shot
  controller continuation. None enters a public payload. The code-only
  effecting controller is now the sole consumer: it keeps the same callback,
  flock, roots, PID/thread, issuer session, and original deadline, refreshes the
  16-read pre-effect topology, then transitions from pre-release recovery to
  post-effect outcome retention before invoking exact release. Its 260-second
  pre-effect gate preserves the canonical shared 120-second `CLOCK_BOOTTIME`
  deadline, 115-second worker cutoff, 122-second host runtime-state command
  ceiling, then separate 130-second, 50-second, and five-second later-phase
  reserves. The two verifier calls use the issuer's exact sealed suspend-aware
  host clock and cut off at action-deadline minus 85 and eight seconds; the
  persistent pass ends with a third marker barrier, and a final at-most-two-
  second runtime-state receipt must exactly match the first before success.
  Sequence-2 successor, persistent-topology, and exclusive terminal outcome
  contracts are implemented, with post-effect failure truthful and
  non-retryable. Contract
  `phase6d-post-enrollment-start-host-orchestrator-v3` supplies the
  standalone isolated one-shot host CLI as the only
  supported composition point. It authenticates a canonical owner-only signed
  v3 envelope, exact reviewed authority Git object, nested v2 semantics, and
  base-image provenance, and rejects current-HEAD mismatch before Docker,
  issuer, runtime, or reversible preflight. Under one issuer flock it then
  completes owner-held staging, reversible diagnostics, and an independent
  fresh image witness. Under the choreography lease it prepares sequence 1 and
  an exact-empty create fence before permanently reserving and consuming the
  execution-attempt slot, storing the mutation flag, and executing only the
  prepared create. Source-first/supervisor-second/input-retirement/claim/action/
  admission/controller chronology then continues with the signer-free read-only
  sequence-1 verifier. Its action
  and recovery bounds are 600/605 seconds while the controller's 260-second
  gate is unchanged. Exact reviewed teardown is possible only before the claim
  boundary; after that boundary no automatic teardown is permitted. The CLI has
  no Make, Compose, worker, trader, ordinary launcher, shutdown, readiness,
  exposure, broker, or trading wiring. Its exact merged revision, images,
  stable provenance, and external operator-attested approval must be exact, while the
  independent image witness and operational decision must be fresh for the
  attempt. A confirmed pre-slot failure preserves that approval; any slot
  ambiguity is permanent. This implementation performed no live attempt.
  Complete that boundary before adding an
  independent watchdog, readiness,
  final new-exposure, alert, and exact-head manual re-arm consumers. The local
  evidence composition is non-authorizing and does not satisfy those deployment
  gates. ADR 0095 adds only the dormant pure candidate reducer. It never reports
  current, stopped, or stale from raw caller inputs and does not reorder
  provisioning or enrollment. ADR 0109's clean-stop-specific sealed observer is
  code-only, has no live/effect consumer except ADR 0111's dormant zero-caller
  composition, and is not a watchdog currentness issuer: no independent
  runtime, dedicated reader principal, 360-second freshness consumer, external
  failure domain, alert, deployment, drill, or exit evidence exists.
- ADR 0096's E\*TRADE live-broker selection is orthogonal to this sequence. It
  does not authorize reading local broker credentials, making a provider call,
  or skipping secure-launcher admission, first enrollment, watchdog, readiness,
  alert, new-exposure, or re-arm gates. It does not change the completed
  same-object proof result.
- Separate worker/trader roles, pools, quotas, and service identities; managed
  PostgreSQL, secret manager, object storage, restricted network, and immutable
  images/configuration.
- Separate paper and live projects, accounts, credentials, databases, and alert
  routes. No mutable paper state is promoted to live.
- Expand/migrate/contract schema procedures, trading-aware drain before deploy,
  application-version compatibility, and forward-fix strategy.
- Backup, point-in-time restore, retention, deployment rollback-to-halt, and
  disaster-recovery drills with declared RPO/RTO.
- Runbooks for startup/shutdown, database/data/broker outage, `UNKNOWN` order,
  partial/late fill, manual broker activity, mismatch, strategy crash, kill
  states, broker-dashboard intervention, and incomplete flatten.
- Daily automated reconciliation, ledger integrity check, and signed report.
- Production CSP/CSRF/session validation, table virtualization, server-side
  chart downsampling, backend SSE recovery, and Chromium/Firefox/WebKit
  end-to-end coverage at desktop viewports. Route-level lazy splitting and
  fail-closed shared-runtime bundle admission are implemented locally.

### Exit gate for paper-trading MVP

- A fresh environment deploys from immutable artifacts without manual database
  edits; restore and recovery objectives are demonstrated.
- Critical simulated failures reach the operator within the declared budget.
- Game days cover database loss, broker/data outage, clock drift, strategy crash,
  split brain, unknown order, reconciliation mismatch, and kill-state recovery.
- At least five consecutive complete market sessions finish without unexplained
  order, fill, cash, position, ledger, or reconciliation differences before the
  longer soak begins.

## Phase 7 - supervised paper soak (minimum 4-8 weeks plus evidence quotas)

### Operate and measure

- Keep two independent evidence lanes. Broker-neutral strategy and operational
  soak evidence must come from a genuine stateful paper/simulated venue; the
  existing Alpaca paper path may contribute only after its own Phase 4 gates
  pass. E\*TRADE-specific readiness separately requires sandbox protocol
  qualification, production read-only and preview-only qualification, and local
  shadow/fault evidence. Neither lane substitutes for the other.
- Run the exact signed candidate artifact/configuration during every intended
  session; strategy code remains frozen while execution defects are diagnosed.
- Compare expected and observed batches, targets, reservations, orders, fills,
  costs, positions, P&L, latency, rejects, gaps, reconnects, and reconciliations
  daily.
- Require predeclared evidence quotas: complete sessions, generated targets,
  accepted/rejected/canceled/partial orders, reconnects, risk trips, and at least
  one controlled drill of each critical recovery path. If the strategy naturally
  does not generate an event, inject it in a drill rather than waiting forever.
- Do not count E\*TRADE sandbox observations toward session, order, fill, reject,
  reconnect, reconciliation, slippage, or execution-quality quotas; its stored
  sample responses may not correspond to requests.
- Continue across representative market conditions when practical; elapsed
  calendar time alone is insufficient.

### Operational promotion gate

- Both evidence lanes are complete: broker-neutral soak/fault evidence and the
  selected E\*TRADE production read-only/preview-only plus local shadow/fault
  qualification. Sandbox success alone is never promotion evidence.
- Zero unresolved order, fill, cash, position, ledger, or reconciliation
  discrepancies.
- Every incident has a documented cause, corrective action, and regression test.
- Lease fencing, recovery, risk limits, alerts, kill states, deploy, restore,
  halt, and manual broker intervention passed their drills.
- Replay-to-paper decision differences are fully explained by availability or
  modeled execution effects.

### Strategy validation gate

- Final criteria were signed before holdout/soak results were revealed.
- Out-of-sample results remain acceptable under declared benchmark, uncertainty,
  cost, impact, and capacity stresses.
- Trial count and selection process are disclosed; paper fill profitability is
  excluded as evidence of real execution quality.
- A human signs the immutable strategy, risk, data, and runtime promotion record.

## Phase 8 - minimum-size live canary (never automatic)

### Preconditions

- The canary venue is E\*TRADE production. Bind the exact numeric account ID and
  opaque `accountIdKey`, deploy production credentials from a separate live-
  scoped secret store, and pass the OAuth lifecycle, endpoint-isolation,
  provider-ID, Preview/Place, production read-only/preview-only, request-budget,
  reconciliation, and manual `UNKNOWN` recovery drills. Reported local `.env`
  key presence is deliberately uninspected and is not admission evidence.
- Confirm brokerage permissions, market-data licenses, tax implications, and
  legal/compliance obligations for the actual operating model.
- Use the separate live environment, one strategy, the narrow allow-list, and
  the smallest sensible capital/order size with tighter limits than paper.
- Re-run live readiness, reconciliation, broker capability, market-data
  entitlement, and manual-intervention checks immediately before the session.

### Rollout

1. Reconfirm E\*TRADE production read-only and preview-only readiness without a
   Place call.
2. Live shadow mode: targets and risk decisions only.
3. One-symbol, minimum-size Preview followed by immediate full revalidation and
   one Place call under direct supervision.
4. Reconcile paginated Orders and Transactions plus Balance/Portfolio evidence
   and the independent broker dashboard within a fixed observation window.
5. Gradual universe/capital increases only after predeclared gates.
6. Any ambiguous Place becomes durable `UNKNOWN`, halts new exposure, is never
   automatically retried/resubmitted, and requires manual disposition plus
   human re-arm.
7. Any unexplained divergence immediately halts new exposure; “rollback” means
   manage existing orders/positions safely, not blindly run an older binary.

Live promotion is an operational decision, never a CI action.

## Cross-cutting definition of done

Every change includes:

- typed public contracts and documented invariants;
- unit/property tests plus integration or broker/data contract tests when a
  boundary changes;
- explicit time, retry, expiry, idempotency, deduplication, and failure behavior;
- forward-compatible migration and mixed-version deployment analysis;
- metrics/logs that diagnose failures without credentials or sensitive data;
- audit coverage for user-facing controls and configuration;
- updated ADR/runbook documentation;
- a performance measurement when the hot event loop or data scan path changes.

## Initial CI pipeline

1. Ruff format/lint, static typing, and architecture import-boundary tests over
   the configured `apps`/`packages` source roots.
2. Unit and property tests for domain, ledger, risk, and order reducers.
3. Temporal leakage, batch/incremental differential, and semantic replay tests.
4. PostgreSQL integration, migration compatibility, lease/fencing, and job tests.
5. Broker/data recorded-contract tests plus optional sandbox tests. E\*TRADE
   sandbox assertions are limited to OAuth/signing, endpoint isolation, request
   shape, raw retention, pagination field/request/response shape, and decoding;
   they never assert pagination traversal semantics, stateful lifecycle,
   economics, reconciliation convergence, or live readiness.
6. End-to-end tape -> target -> reservation -> attempt -> fill -> ledger replay.
7. Web lint, typecheck, generated-contract drift, component tests, and production
   build from Phase 0 onward; Playwright desktop-browser workflows as routes land.
8. Dependency, license, image, and secret scanning.
9. Reference backtest/live-loop performance regression test.

## Suggested first backlog (ordered)

1. Scope, event-time, data-adjustment, ledger, lease, broker, and experiment ADRs.
2. Workspace, CI, configuration, logging, health, and import boundaries.
3. One-symbol walking thread with mandatory risk and balanced ledger.
4. Stable security identity and bitemporal market-event primitives.
5. Raw/normalized Parquet publication, quality checks, and dataset manifest.
6. Corporate-action/security-lifecycle fixtures including a delisting.
7. Watermark-complete strategy batch and deterministic simulated clock.
8. Ledger, projections, target conversion, canonical order reducers.
9. Process-local and durable account coordinator lease/fencing contracts.
   **Implemented by ADRs 0031 and 0032 for deterministic simulation.**
10. Reproducible backtest report and experiment-family registry contracts.
    **Implemented for the Phase 2 golden fixture and the bounded Phase 3C
    governance registry; governed segment execution and broader research
    validity remain Phase 3.**
11. Live market-data capture, quote freshness, shadow replay, feature parity.
12. Alpaca capability matrix and recorded fixtures.
    **The bounded offline capability/translation contract is implemented by ADR
    0038, and ADR 0039 adds synthetic lookup fixtures and a bounded local
    observation profile. ADR 0040 adds exact pre-decode raw receipt durability,
    but not provider-fact identity, authenticated provider fixtures, or runtime
    transport.**
13. Additive E\*TRADE contract, OAuth/session and account binding, raw-first
    reads, provider-ID mapping, Preview/Place durability, provider-specific
    `UNKNOWN` recovery, and the ADR 0096 qualification ladder. **Architecture
    is selected. Phases 4AJ-4AL now implement the pure endpoint/request
    foundation, unauthenticated caller-declared Accounts List decoder, exact
    HMAC-SHA1 signing, and secret-free supervised-session reducer. Deployed
    secret resolution, durable replay state, authenticated OAuth responses and
    OOB handoff, all provider calls, account binding, broader reads,
    Preview/Place, recovery, and qualification remain pending.**
14. Account lease/fence and submission attempts are **implemented by ADR 0032**;
    normalized broker inbox/application and the real reconciliation barrier
    remain Phase 4 work.
15. Fault tests before enabling the first paper submission.
16. Advanced breakers, alerts, operations UI, deployment, backups, and
    runbooks. **Local risk/control, supervised-strategy, provider-neutral alert,
    tracing, authenticated operations, read-only dashboard, and control-runbook
    slices and atomic admission verification are locally implemented; approved
    external routes/exporters, authoritative deployment composition, drills,
    backups, and broader runbooks remain.**

## Decisions required before Phase 1

| Decision | Default | Why it matters |
|---|---|---|
| Instruments | Small fixed set of liquid U.S. ETFs | Minimizes security-lifecycle and liquidity state space while fixtures mature |
| Frequency | 1-minute bars or slower | Keeps v1 outside latency-sensitive/HFT architecture |
| Sessions | Regular market hours only | Avoids extended-hours order/feed/liquidity semantics |
| Direction/quantity | Long-only, whole shares | Avoids short borrow/locate and fractional-order differences |
| Orders | DAY market orders, next-event simulation | Smallest causally defensible execution slice |
| Active strategies | One per brokerage account | Defers netting, virtual sleeves, internal crosses, and fill allocation |
| Broker | E\*TRADE production live target; Alpaca paper historical qualification lane | E\*TRADE sandbox is protocol-only and every live stage remains separately gated; existing Alpaca evidence stays provider-specific and non-authorizing |
| Data | Daily-first: immutable Sharadar research capture plus Tiingo synthetic qualification, one bounded actual Tiingo capture verified and passed through the exact-retained field-contract boundary, and offline local-lineage, identity/lifecycle, and market-semantics/action-candidate contract mechanics implemented; no production identity/lifecycle or semantics/action artifact or real repeat evidence exists, and genuine raw semantics, `HistoricalBarSource`, and admission remain blocked; Massive intraday deferred | Adjustment basis, publication/vintage timing, venue/identity authorities, historical revisions/universes, licensed storage/use, and live quote scope drive validity |
| Account model | Explicit cash or margin policy | Determines settlement, buying power, ledger, and risk semantics |
| Hosting | One region, managed PostgreSQL, object storage | Reliable non-HFT footprint with separable operational/research I/O |
| UI | Desktop-browser React/Vite workspace, incremental from Phase 0 | Makes research and operations observable without adding native/mobile scope |

Options, futures, crypto, shorting, fractional shares, extended hours,
multi-strategy accounts, multi-user SaaS, or sub-second decisions each require a
fresh scope/ADR review before implementation.
