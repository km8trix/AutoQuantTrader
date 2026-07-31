# AutoQuantTrader implementation plan

## Current implementation status

The substantial local Phase 0 foundation/walking thread and bounded Phase 1A/1B
point-in-time ingestion and admission slices are implemented as a local,
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

Massive remains the deferred intraday candidate. No credential,
authorization, synthetic fixture, or capture has been
treated as admission or evidence that a vendor's real history, entitlement,
identifiers, calendars, corrections, or corporate actions have passed
qualification. The trader remains `not_ready`; no paper or live broker/data
adapter is enabled. The remaining Phase 1 vendor admission, remaining Phase 3
work, the rest of Phase 4, and Phases 5-8 below retain their exit gates,
including the Phase 4 paper-broker gate.

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
- Phase 3A and 3B remain in-memory full-tape evidence slices exercised on
  repository-owned synthetic fixtures. Phase 3C/3D do not connect to the Phase
  2 job or worker. General durable segment execution and process isolation,
  separately queryable feature/target transcripts, arbitrary or fitted
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
- A durable bounded experiment registry records every stable attempted, failed,
  canceled, abandoned, and completed trial through append-only lifecycle
  evidence. The bounded reference completion path now requires exact
  configuration-derived target-parity evidence and running actor-identifier
  continuity.
  General worker scheduling, worker-process concurrency, and resource quotas
  remain pending.
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
- CLI- and browser-accessible provenance/performance reports, experiment
  comparison, feature lineage, captured-tape playback, feed freshness, and
  replay-versus-shadow views.

### Exit gate

Status: **open**. The Phase 3A and 3B reference slices supply exact local
feature-snapshot and feature-derived target parity evidence, and Phase 3C
supplies a durable bounded governance registry and opaque pre-reveal holdout
commitment. Phase 3D binds that target parity to an exact governed
configuration and running attempt. These slices do not satisfy the
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

## Phase 4 - paper broker execution, recovery, and trading UI (weeks 10-12)

### Sequencing and current status

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
  supervisor. All slices remain non-authorizing. A deployed
  secret resolver, general
  security-master publication, runtime
  calendar/quote/reduce-only validation, end-to-end order request-budget
  enforcement, authenticated deployed lookup supervision, deployed traversal
  scheduling, stalled-capture recovery, streams, the general
  cross-channel identity/deduplication profile, decode quarantine,
  authoritative fact application, reconciliation, coordinator dispatch, and
  paper startup remain disabled.
- Phases 4A through 4AI are complete only as bounded local contract,
  persistence, and authenticated read-runtime slices with the explicit limits
  described above. Phase 4 and its exit gate remain open. These slices are
  local worktree changes and do not authorize paper or live trading.
  Phase 3's captured-tape, reconnect, shadow, economic
  segment-execution,
  traceability, and reporting gates also remain open and are not bypassed by
  starting Phase 4 work.

### Build

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
- Immutable submission attempts with payload hash and deterministic client order
  ID. On ambiguous responses, enter `UNKNOWN`, perform bounded delayed lookup by
  the same client ID, and never blindly resubmit. The offline result vocabulary,
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

- Paper lifecycle works for accepted, rejected, partial, filled, canceled,
  cancel-rejected, expired, late-fill, bust/correction, and provider-specific
  status events.
- Two normal trader processes and rolling-deploy overlap cannot both remain
  authorized. Lease or database loss fails closed; forced/manual takeover is
  quarantined and reconciled before it may submit.
- Killing the process at every submission boundary never creates an untracked
  duplicate; delayed client-ID visibility and transient “not found” are safe.
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

Phase 6A now begins operational hardening with a provider-neutral, in-memory
trusted-time evidence contract and one injected probe step. It binds exact
source/authority, host, monitor-epoch, UTC, monotonic, sequence, and source
evidence; derives rather than accepts the signed offset; preserves the reviewed
`<250 ms` healthy, inclusive `250-1,000 ms` warning, and `>1,000 ms`
hard/latching bands; and proves strict sample freshness, 30-second replacement
cadence, and a continuous 60-second healthy recovery interval. The public
reducer pins that policy and seals/recomputes derived state. The probe passes a
fixed one-second monotonic deadline to its injected source and rejects
successful overruns or UTC/monotonic elapsed divergence above 250 milliseconds.
Identity-conflicting bindings fail before source I/O and cannot self-establish
a recovery chain.
`clock_recovery_qualified` is evidence only and never automatically re-arms.
The selected adapter must enforce the deadline; no source, watchdog, scheduler,
persistence, readiness or control wiring, API, deployment, or paper authority
is implied. Deployment still requires an authenticated trusted head and a
reviewed source-uncertainty bound. See
[ADR 0086](adr/0086-provider-neutral-trusted-time-monitor.md).

Phase 6B begins desktop-browser bundle splitting. Feature routes now load
through distinct React lazy chunks behind one accessible, polite loading
fallback; the local placeholder-only trading routes remain synchronous. The
production build proves separate data, research, operations, risk, audit,
reconciliation, and settings route artifacts. The shared React/MUI application
shell is still a reviewed follow-on optimization, and this slice adds no CSP,
production session, table-virtualization, chart-downsampling, backend SSE, or
multi-browser end-to-end claim.

## Phase 6 - deployment, browser security, and operational hardening (weeks 16-18)

### Build

- Compose ADR 0086 with an approved authenticated time source, durable sample
  retention, startup and at-most-30-second in-session scheduling, arming and
  final new-exposure gates, alerting, and exact-head manual re-arm evidence.
  The checked-in provider-neutral probe is non-authorizing and does not satisfy
  this deployment work.
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
- Production CSP/CSRF/session validation, remaining shared-runtime bundle
  optimization, table virtualization, server-side chart downsampling, backend
  SSE recovery, and Chromium/Firefox/WebKit end-to-end coverage at desktop
  viewports. Route-level lazy splitting is implemented locally.

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

- Run the exact signed candidate artifact/configuration during every intended
  session; strategy code remains frozen while execution defects are diagnosed.
- Compare expected and observed batches, targets, reservations, orders, fills,
  costs, positions, P&L, latency, rejects, gaps, reconnects, and reconciliations
  daily.
- Require predeclared evidence quotas: complete sessions, generated targets,
  accepted/rejected/canceled/partial orders, reconnects, risk trips, and at least
  one controlled drill of each critical recovery path. If the strategy naturally
  does not generate an event, inject it in a drill rather than waiting forever.
- Continue across representative market conditions when practical; elapsed
  calendar time alone is insufficient.

### Operational promotion gate

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

- Confirm brokerage permissions, market-data licenses, tax implications, and
  legal/compliance obligations for the actual operating model.
- Use the separate live environment, one strategy, the narrow allow-list, and
  the smallest sensible capital/order size with tighter limits than paper.
- Re-run live readiness, reconciliation, broker capability, market-data
  entitlement, and manual-intervention checks immediately before the session.

### Rollout

1. Live shadow mode: targets and risk decisions only.
2. One-symbol, minimum-size canary with direct supervision.
3. Fixed observation window and post-session reconciliation/report.
4. Gradual universe/capital increases only after predeclared gates.
5. Any unexplained divergence immediately halts new exposure; “rollback” means
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

1. Ruff format/lint, static typing, and architecture import-boundary tests.
2. Unit and property tests for domain, ledger, risk, and order reducers.
3. Temporal leakage, batch/incremental differential, and semantic replay tests.
4. PostgreSQL integration, migration compatibility, lease/fencing, and job tests.
5. Broker/data recorded-contract tests plus optional sandbox tests.
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
13. Account lease/fence and submission attempts are **implemented by ADR 0032**;
    normalized broker inbox/application and the real reconciliation barrier
    remain Phase 4 work.
14. Fault tests before enabling the first paper submission.
15. Advanced breakers, alerts, operations UI, deployment, backups, and
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
| Broker | Alpaca paper | Paper-first API; capability contract preserves future portability |
| Data | Daily-first: immutable Sharadar research capture plus Tiingo synthetic qualification, one bounded actual Tiingo capture verified and passed through the exact-retained field-contract boundary, and offline local-lineage, identity/lifecycle, and market-semantics/action-candidate contract mechanics implemented; no production identity/lifecycle or semantics/action artifact or real repeat evidence exists, and genuine raw semantics, `HistoricalBarSource`, and admission remain blocked; Massive intraday deferred | Adjustment basis, publication/vintage timing, venue/identity authorities, historical revisions/universes, licensed storage/use, and live quote scope drive validity |
| Account model | Explicit cash or margin policy | Determines settlement, buying power, ledger, and risk semantics |
| Hosting | One region, managed PostgreSQL, object storage | Reliable non-HFT footprint with separable operational/research I/O |
| UI | Desktop-browser React/Vite workspace, incremental from Phase 0 | Makes research and operations observable without adding native/mobile scope |

Options, futures, crypto, shorting, fractional shares, extended hours,
multi-strategy accounts, multi-user SaaS, or sub-second decisions each require a
fresh scope/ADR review before implementation.
