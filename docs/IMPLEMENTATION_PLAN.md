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

Massive remains the deferred intraday candidate. No credential,
authorization, synthetic fixture, or capture has been
treated as admission or evidence that a vendor's real history, entitlement,
identifiers, calendars, corrections, or corporate actions have passed
qualification. The trader remains `not_ready`; no paper or live broker/data
adapter is enabled. The remaining Phase 1 vendor admission and Phases 3-8 below
retain their exit gates, including the Phase 4 paper-broker gate.

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

### Build

- Versioned feature artifacts with input lineage, lookback/publication lag,
  missing-data policy, fitted training window, and immutable fitted state.
- Batch and incremental feature implementations with differential replay tests.
- Experiment families that record every attempted, failed, canceled, and
  completed trial; bounded worker-process concurrency and resource quotas.
- Chronological and nested walk-forward evaluation, purging/embargo for
  overlapping labels, benchmark/cost stress, parameter stability, uncertainty,
  and declared multiple-testing treatment.
- Audited final-holdout access and promotion criteria frozen before reveal.
- A live market-data adapter with feed-entitlement metadata, quote/NBBO support,
  per-symbol freshness, gap backfill, reconnect watermarking, and captured event
  tapes. Run the candidate in shadow mode without any broker submission.
- CLI- and browser-accessible provenance/performance reports, experiment
  comparison, feature lineage, captured-tape playback, feed freshness, and
  replay-versus-shadow views.

### Exit gate

- Batch and incremental features/targets agree on the same captured tape.
- A reconnect backlog cannot emit one fresh intent per stale bar; expired targets
  are discarded and audited.
- Any trade can be traced to its availability-time inputs, feature artifacts,
  target, risk snapshot, code/image digest, and configuration.
- Parameter sweeps cannot inspect the final holdout or mutate shared run state.
- Reports label exploration, validation, and confirmation evidence and declare
  return, annualization, benchmark, cash-flow, cost, and uncertainty conventions.

## Phase 4 - paper broker execution, recovery, and trading UI (weeks 10-12)

### Build

- Alpaca paper adapter plus explicit capability matrix for order types, TIF,
  sessions, tick/lot/fraction rules, client IDs, status mapping, pagination,
  data feed, and request budgets.
- Database-enforced account lease and monotonically increasing fencing
  generation, revalidated immediately before every broker side effect. Disable
  automatic failover because the broker cannot enforce the fence; manual
  takeover uses lease expiry, an in-flight safety interval, prior-runtime stop
  confirmation where possible, and the reconciliation barrier.
- Immutable submission attempts with payload hash and deterministic client order
  ID. On ambiguous responses, enter `UNKNOWN`, perform bounded delayed lookup by
  the same client ID, and never blindly resubmit.
- Inbound inbox/deduplication for at-least-once broker stream and snapshot events.
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

### Build

- Versioned advanced risk rules for session loss/drawdown, concentration,
  leverage, volatility, spread/slippage, reject rate, rate limits, clock/data
  health, unknown duration, and reconciliation duration.
- Circuit breakers that default to no new exposure and never auto-resume.
- React/Vite dashboard for environment identity, freshness, coordinator owner,
  strategy/deployment state, orders, fills, account/ledger positions, risk
  reservations/decisions, reconciliation differences, alerts, and audited
  controls.
- OpenTelemetry correlation across market batch, target, reservation, attempt,
  broker event, fill, ledger posting, and reconciliation.
- Alerts for every critical failure with delivery checks and escalation policy.
- Supervised strategy subprocess with deadline/resource enforcement; timeout or
  crash pauses new entries while order/risk/reconciliation handling continues.

### Exit gate

- Every broker call is traceable to a current fence and single-use risk approval.
- Boundary/property tests prove configured limits including pending-cancel and
  unknown-order exposure.
- Kill-state matrix drills are timed and audited; drain and flatten report
  explicit completion or residual exposure rather than assuming success.
- Strategy timeouts, alert-channel failures, data gaps, broker disconnects, and
  risk trips produce the intended state and require manual re-arm.
- The UI cannot call the broker directly and remains an observational/control
  client over durable commands.

## Phase 6 - deployment, browser security, and operational hardening (weeks 16-18)

### Build

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
- Production CSP/CSRF/session validation, desktop-browser bundle splitting,
  table virtualization, server-side chart downsampling, SSE recovery, and
  Chromium/Firefox/WebKit end-to-end coverage at desktop viewports.

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
    **Implemented for the golden fixture; broader research validity remains
    Phase 3.**
11. Live market-data capture, quote freshness, shadow replay, feature parity.
12. Alpaca capability matrix and recorded fixtures.
13. Account lease/fence and submission attempts are **implemented by ADR 0032**;
    broker inbox and real reconciliation barrier remain Phase 4 work.
14. Fault tests before enabling the first paper submission.
15. Advanced breakers, alerts, complete operations UI, deployment, backups, and
    runbooks.

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
