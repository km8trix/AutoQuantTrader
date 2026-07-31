# Operational budgets

- Status: Initial baseline; not paper- or live-qualified
- Effective date: 2026-07-15
- Scope: one-minute-or-slower, regular-hours, long-only U.S. ETF v1 path

These values turn undefined timing and recovery expectations into explicit
fail-closed contracts. They are conservative starting points, not evidence that
the current Phase 0 walking thread is ready for paper or live trading. The
admission table below distinguishes checked-in behavior from future enforcement.

## Measurement rules

- Use a monotonic clock for elapsed process-local deadlines. Use timezone-aware
  UTC timestamps for durable records and cross-process correlation.
- A deadline or approval is invalid when `now >= expires_at`; boundary equality
  never grants more authority.
- Measure warning objectives at p99 over complete market sessions. A hard limit
  is evaluated for every affected event and fails closed immediately.
- `No new exposure` still permits reconciliation, broker-event ingestion,
  cancellation, and separately authorized risk-reducing actions.
- Broker request admission is consumed when its durable permit is issued.
  Expiry or local abandonment never refunds capacity because external dispatch
  may be ambiguous after a process failure.
- Environment overrides may tighten a safety limit. Loosening requires a
  versioned review with recorded evidence; it cannot be an ad hoc runtime edit.

## Initial values

| Budget | Initial value | Measurement point | Hard-limit behavior | Owner |
|---|---|---|---|---|
| Complete-bar data age | Warn at 5 s; hard limit 15 s after the expected one-minute interval close | Decision start minus the latest complete bar interval end, using the exchange calendar | Do not create new-exposure targets; record the stale symbols and remain paused until a watermark-complete fresh batch exists | Data plane |
| Supervised strategy start, decision, cleanup, and recovery | A winning durable claim must reach the child boundary in `<1 s`; warn at 2 s and decide in `<5 s` from the pre-spawn monotonic sample; all cleanup shares one absolute `8 s` deadline from that sample; orphan recovery begins at claim time `+9 s` (`1+5+3`) | Trusted UTC under account serialization for claim/start/recovery boundaries; one monotonic origin immediately before `Popen` for decision plus cleanup | Consume winning start authority before fallible work; never reissue it. Reject start at one-second equality, terminate at five-second equality, grant cleanup no fresh interval, and recover a retained orphan without rerunning; pause new exposure while protected loops continue | Trading runtime |
| Persisted risk-approval TTL | 30 s maximum from the durable approval commit; shorter intent expiry wins | Durable commit time through atomic consumption immediately before dispatch | Reject when expired, consumed, policy-mismatched, or payload-mismatched; never refresh an approval implicitly | Risk |
| Clock drift | Warn at 250 ms; hard limit 1 s absolute offset from a trusted time source | Host UTC offset sampled at startup and at least every 30 s while armed | Block arming and new exposure; require healthy samples for 60 s plus explicit re-arm | Platform operations |
| Broker submission uncertainty | 3 s request deadline; first local client-ID lookup eligibility 1 s after durable `UNKNOWN` recording; unresolved hard budget 60 s from dispatch | Monotonic time from dispatch for the request and unresolved deadlines; durable UTC `UNKNOWN recorded_at` to first scheduler eligibility; lookup receipts alone do not stop the unresolved clock | Persist `UNKNOWN`, block new exposure for the account, query by the same deterministic client ID, and never retry the submit blindly; alert at 60 s and remain blocked | Execution |
| Broker Trading API request capacity | Reviewed 200-request account ceiling over a 60 s provider window; stop submissions at 160 accounted permits, UNKNOWN lookups at 180, and reserve the final 20 for cancel/reconciliation; permit freshness 3 s produces a conservative 63 s local accounting horizon | Durable account-local permit issue through `expires_at + 60 s`, inclusive at equality; every purpose compares the same total accounted-permit count | Deny the request locally without refunding prior permits; lower-priority exhaustion leaves protected recovery/control capacity available | Execution |
| Reconciliation | Run as a blocking startup/reconnect barrier; require two matching views at least 2 s apart; 120 s convergence budget; periodic check every 60 s while armed | Monotonic time from barrier start through the second converged broker/local view | Do not enter or remain `RUNNING`; classify and expose every economically relevant difference and require operator resolution | Reconciliation |
| Critical-alert delivery | Enqueue within 1 s, primary delivery confirmation within 15 s, fallback confirmation within 30 s | Monotonic time from durable critical event creation to provider acknowledgement | Mark alerting degraded at 15 s; invoke the independent fallback route and block new exposure if no route confirms by 30 s | Platform operations |
| Reference backtest | 98,280 deterministic events (one ETF, 252 sessions, 390 one-minute bars), one strategy/risk/ledger path; warm runtime <= 10 s and peak RSS <= 512 MiB on a 2-vCPU, 2-GiB Linux runner | End-to-end process runtime and peak resident memory after one untimed warm-up; semantic digest compared across two runs | Fail the performance gate on a >20% runtime regression from the accepted rolling baseline, any memory breach, or any semantic-digest difference | Research platform |

## Owner-approved Phase 5B moderate paper envelope

ADR 0068 freezes the following owner-chosen engineering limits for the exact
paper-only DIA/IWM/QQQ/SPY, regular-hours, long-only cash-account scope. The
values do not come from a regulator, broker, or vendor and do not activate a
runtime account. Equality remains within a magnitude limit; causal freshness
still requires `age < maximum_age`.

| Rule | Measurement/window | Hypothetical new exposure | Current/committed runtime |
|---|---|---|---|
| Session loss | Flow-adjusted equity versus positive regular-session opening equity | Operational state denies after a trip | `>2%` and `<=3%` pauses; `>3%` halts |
| Session drawdown | Flow-adjusted equity versus durable session high water | Operational state denies after a trip | `>2.5%` and `<=4%` pauses; `>4%` halts |
| Instrument concentration | Current marked long value plus every unreleased remaining buy exposure, divided by positive current equity | `>35%` rejects only the exact batch | `>35%` and `<=50%` pauses; `>50%` halts |
| Gross/absolute-net leverage | Current exposure plus unreleased buys, divided by positive current equity | `>1.00x` rejects only the exact batch | `>1.00x` and `<=1.10x` pauses; `>1.10x` halts; the upper tier grants no margin authority |
| One-minute volatility | Maximum absolute simple return from 30 returns over 31 consecutive complete RTH bars | `>1.5%` rejects only the exact batch | `>1.5%` and `<=3%` pauses; `>3%` halts for an exposed instrument |
| Full SIP NBBO spread | `10,000 * (ask-bid)/mid`; quote event and receive ages each `<5 s` | `>20 bps` rejects only the exact batch | `>20` and `<=50 bps` pauses; `>50 bps` halts for an exposed instrument |
| Modeled execution cost | SIP half-spread plus a distinct versioned non-spread latency/impact estimate | `>25 bps` rejects only the exact batch | No breaker from a hypothetical model |
| Realized adverse slippage | Arrival-notional-weighted latest 20 eligible fills in the left-open trailing 30 minutes | Not applicable | `>15` and `<=30 bps` pauses; `>30 bps` halts |
| Broker business-reject rate | Definitive correlated new-entry outcomes in the left-open trailing 10 minutes | Not applicable | With at least 10 outcomes: at least 3 rejects and `>10%` pauses; at least 5 and `>25%` halts; 3/5 consecutive definitive rejects pause/halt independently |

`REJECT` is hypothetical-only and writes no control transition. Runtime
`PAUSED`/`HALTED` actions use the durable Phase 5A breaker path, never
auto-resume, and never imply cancellation or liquidation. Required incomplete
source evidence denies the exact batch and requests a source/data-health pause;
it is never assigned a fabricated numeric value. Fees and admitted dividends
remain in account performance, external contributions/withdrawals are
neutralized, pending-cancel sells never reduce exposure, and unresolved buys
retain their remaining conservative exposure. The complete source,
classification, arithmetic, atomic-sidecar, and cutover contract is
[ADR 0068](adr/0068-owner-approved-moderate-paper-risk-policy.md).

The submission request deadline does not mean the broker rejected the order. A
timeout is ambiguous and enters `UNKNOWN`; only later authenticated
reconciliation and application of authoritative broker evidence may resolve
it. A client-ID lookup receipt alone does not. Likewise, exceeding
reconciliation or alerting budgets never causes automatic resume or failover.

## Ownership and tuning

The listed owners are responsibility boundaries even while one engineer fills
all roles:

- **Data plane:** vendor availability timestamps, exchange calendars,
  watermarks, gap detection, and per-symbol freshness.
- **Trading runtime:** strategy supervision, decision timing, target validation,
  and preserving order/reconciliation loops during strategy failure.
- **Risk:** policy versions, atomic reservations, payload-bound single-use
  approvals, and expiry semantics.
- **Execution:** submission attempts, deterministic client IDs, broker lookup,
  deduplication, and unknown-order containment.
- **Reconciliation:** broker/local comparison, convergence, mismatch
  classification, and the readiness barrier.
- **Platform operations:** trusted time, alert routes, delivery probes,
  dashboards, and incident evidence.
- **Research platform:** deterministic reference fixtures, benchmark runner,
  hardware metadata, and semantic/performance regression reports.

Before any limit is loosened, capture p99 and maximum observations from at least
five complete representative paper sessions plus the relevant failure drill.
Record the old value, proposed value, evidence window, incident impact, owner,
reviewer, and rollback threshold. A safety incident may tighten a limit
immediately, but the change still receives a versioned follow-up. Reference
backtest runtime is normalized only against the declared runner class; changing
hardware creates a new baseline rather than silently erasing a regression.

## Implementation and admission status

| Contract | Phase 0 status | Required admission evidence |
|---|---|---|
| Approval TTL, reservation, and single-use binding | Implemented for the deterministic walking thread with trusted clocks, atomic SQL account guards, strict persisted evidence, and a durable pre-order submission attempt; still simulation-only | PostgreSQL race coverage is checked in; paper admission still requires policy-version compatibility and kill-at-every-dispatch-boundary fault evidence |
| Data-age and strategy deadlines | Complete-bar age values remain specified without deployed live-feed supervision. The local supervised subprocess enforces sealed winner-only start authority, a strict one-second start window, the five-second decision boundary, one absolute eight-second decision-plus-cleanup deadline, and deterministic no-rerun recovery at nine seconds. | Captured-tape gap, stale-bar, and reconnect-backlog tests; PostgreSQL claim/start/recovery races; kill-at-every-boundary and deployed wall-clock/process-isolation drills |
| Clock drift | ADR 0086 locally implements reducer-sealed deterministic provider-neutral samples, a pinned policy, strict UTC/monotonic continuity, `<250 ms` healthy, inclusive `250-1,000 ms` warning, `>1,000 ms` hard/latching classification, strict `<30 s` sample age, replacement cadence through 30-second equality, and a non-authorizing 60-second healthy-chain proof. Identity conflicts cannot become the retained baseline. ADR 0090 adds fresh non-resumable epochs, immutable success/failure attempt history, public-reducer replay, stale-process fencing, and an exact host-head compare-and-swap around source I/O. That local history is tamper-evident but has no authenticated external anchor or rollback protection. Owner-approved migration 0034 was applied to runtime Supabase on 2026-07-31; all three tables were empty and the operational integrity gate passed. It still selects no actual source and has no adapter timeout/watchdog, reviewed source-uncertainty bound, scheduler, readiness/control wiring, or re-arm authority. | Select and authenticate a deployment source and host/failover binding whose adapter enforces the supplied deadline and provides a reviewed uncertainty bound; anchor the exact head outside the mutable database trust boundary; run startup and in-session probes at the required cadence; atomically gate arming/new exposure and exact-head manual re-arm; then capture drift, source-stall, source-failure, restart, corruption, concurrent-probe, and recovery evidence in the deployed topology |
| Operational control and manual re-arm | Phase 5A locally implements immutable account/actor-idempotent commands, the fixed `RUNNING < PAUSED < DRAINING < FLATTENING < HALTED` precedence, fail-closed absence, durable breaker trips, authenticated heads, and explicit drain/flatten completion or residual facts. No timer, health recovery, process restart, or breaker reset can resume state. The compatibility projection keeps the existing batch-risk vocabulary unchanged. | Compose authoritative readiness, data/clock health, reconciliation, outstanding-order, blocker-disposition, and operator-authentication evidence inside the exact-head re-arm transaction; wire the head into every risk/dispatch boundary; exercise PostgreSQL severity races plus timed pause/drain/flatten/halt, incomplete-flatten, restart, corruption, and manual re-arm drills. |
| Advanced-risk policy envelope | The moderate paper-only policy semantics and action matrix are owner-approved in ADR 0068. Migrations 0026 and 0030, immutable policy/assignment/evidence/assessment/outcome persistence, source-shape adapters, greatest-severity breaker binding, additive cutover, exact retry/rollback, legacy-writer lockout, startup integrity, and final dispatch reauthentication are locally implemented and verified. The path remains disabled by default; no deployed assignment, authoritative producer, or paper authority exists. | Authenticate an exact account assignment only after authoritative session/SIP/broker producers exist; validate the quiesced cutover and final dispatch boundary in the deployed PostgreSQL topology; then pass timed source-failure, restart/corruption, equality/window, concurrency, and dispatch drills. |
| Submission uncertainty | Policy, one authenticated raw-first historical lookup for an exact current UNKNOWN-at-send, and a durable bounded local schedule are implemented. Phase 4J freezes six one-shot eligibility offsets after the UNKNOWN commit, coalesces missed slots, and stops issuance at the original dispatch's 60-second deadline. Phase 4K retains normalized historical evidence, and Phase 4L durably accounts for each source-scoped request with an explicit non-application receipt. The submission remains UNKNOWN for every outcome, and no deployed worker, resolving application, or paper/live submission adapter is enabled | Exercise the schedule through deployed trusted-time supervision and alert delivery, then add provider-qualified revision/execution/correction identities, authoritative reconciliation/application, and kill-at-every-submission-boundary fault tests |
| Broker request capacity | Durable concurrent admission, protected purpose ceilings, exact-retry lookup idempotency, new-only transport admission, and account-local permit integrity are implemented. Phase 4G's account read and Phase 4H's exact candidate-asset read durably revalidate reconciliation-purpose permits; Phase 4I's client-order read consumes protected UNKNOWN-lookup capacity and rechecks the exact UNKNOWN head, terminal provider-account identity continuity, and current recovery fence across raw-first transport. Phase 4J derives a distinct request and delivery identity for each durably consumed schedule slot; a crash never reuses that identity or permit. Phase 4M derives a distinct reconciliation demand for each of at most eight order pages, Phase 4N compares already supplied captures without capacity, and Phase 4O prepares and authenticates exactly one page before consuming a fresh reconciliation permit. Its first durable preparation is a single-use claim; overlapping or restarted callers fail before credentials, permit issuance, or transport. Phase 4P only reloads and compares already committed sources, so it consumes no additional provider capacity. Phase 4Q invokes at most one Phase 4O page per call and consumes no provider capacity when waiting or recording Phase 4P. Phase 4Z requires Q's state, page, and comparison ports to identify one process-local durable store before any source read or effect, so split-store wiring cannot spend a permit before an inevitable reload failure. Phase 4AA registers the exact same-store pair and atomically consumes each gap-free page claim with the unchanged Phase 4O preparation under the account lock. A losing direct path fails before credentials, permit issuance, or transport, and a crash after consumption remains stalled without resend. Phase 4AB claims the exact Q-selected prefix and source head, consumes that claim before secret or permit access, and pins the selected page's own consumption lease through the unchanged Phase 4O request and commit path. It still executes at most one page per invocation and allocates no capacity while waiting or comparing. Phase 4R only describes and decodes an already supplied raw-first position response, and Phase 4S only compares two such sources; neither allocates a permit or transport. Phase 4T requires a fresh single-use preparation before consuming one new reconciliation permit for one strict position request; a stalled, completed, overlapping, or restarted capture cannot allocate another permit or resend. Phase 4U implements the immutable claim and one-to-one receipt under the account lock, so restart cannot turn a consumed capture into new capacity. Phase 4V compares only existing receipts and consumes no provider capacity. Phase 4W can invoke at most one Phase 4T capture per call and consumes none while waiting or recording Phase 4V; an initially observed stalled claim fails before another permit, while a concurrent unselected mutation is rejected after that one bounded read. Phase 4X registers both position-pair members before preparation and atomically consumes a same-lease role claim with the unchanged Phase 4U plan, so the losing unscoped path allocates no permit or transport. Phase 4Y carries that exact claim lease through unchanged Phase 4T execution, permits at most one selected GET per invocation, and consumes no provider capacity while waiting or recording Phase 4V. A stale lease fails before transport, a post-consumption crash cannot resend, and a lease change after the first check can retain one raw-first response but cannot commit Phase 4U. The account continuity check does not claim fresh account status, and no lookup, schedule, page-chain receipt, comparison result, supervisor stage, transition claim, or position view can apply a recovery decision | Extend the same new-only, fresh, purpose-matched enforcement to deployed traversal scheduling, submission, reconnect bursts, cancellation, and every remaining paper request inside its final account-fenced boundary |
| Reconciliation | Phase 4K durably authenticates historical lookup evidence, Phase 4L retains source-scoped normalized requests, account-local source links, and fixed-policy non-application receipts, and Phase 4M defines a bounded raw-first descending order-page chain. A short page proves only cursor exhaustion and a full eighth page is bounded truncation. Phase 4N purely compares two distinct, source-ordered captures with the same traversal profile and disjoint raw receipts. It reports page-independent added, removed, and changed order IDs, but classifies a separated difference or match only after the minimum two-second observed interval; truncation remains incomplete, too-close inputs remain waiting, and an exact match is explicitly unqualified with `converged=false`. Phase 4O adds authenticated restart-safe committed prefixes one page at a time, with durable preparation, fresh budget/fence/account identity checks, and raw-first retention. Phase 4P durably reauthenticates two exact ended prefixes and appends the recomputed comparison under a transaction-internal fence and account-local integrity chain. Phase 4Q derives one restart-safe action from those sources, advancing at most one exact page, waiting without I/O for the later-start boundary, or recording the terminal pair; it adds no loop or resend policy. Phase 4Z makes that Q path reject split-store O/P composition before source access or effects. Phase 4AA adds durable ordered-pair membership, gap-free per-page claims, atomic preparation consumption, exact preparation projection/backfill, and transition-aware readiness. Phase 4AB composes that history through Q/O/P: every page load authenticates its exact claim, consumption, unchanged preparation, receipt, and page-local lease; stale selected state fails under the account lock; and comparison authenticates both complete histories without creating a claim. Phase 4R retains and strictly decodes one bounded historical open-position array, but the live mark-to-market endpoint supplies no timestamp, isolated snapshot, or canonical account truth. Phase 4S compares two source-ordered arrays by exact sorted asset views; too-close sources wait and even separated equality remains unqualified. Phase 4T authenticates one freshly claimed raw-first position request under a stable provider-account identity and account fence, and Phase 4U makes its exact claim/receipt restart-durable without granting retry. Phase 4V durably reauthenticates and recomputes the exact pair under a current fence while retaining signed receive-time separation, Phase 4W derives one restart-safe capture, wait, or comparison action from unclaimed/stalled/complete state, Phase 4X adds durable exclusive position-pair transition admission, and Phase 4Y composes that admission through one exact-lease Phase 4T execution while authenticating every W/V source. Phases 4AD-4AI add bounded raw-first FILL-activity traversals, authenticated one-page persistence/runtime, exact pure and source-authenticated comparisons, durable comparison history, and one-effect restart-safe supervision. Equality remains nonconvergent and noncanonical. These records provide no cross-channel deduplication, provider revision/execution/correction identity, fact application, UNKNOWN resolution, or broker reconciliation barrier | Add provider-qualified stream/snapshot overlap and identities, execution/bust/correction identity, decode quarantine, duplicate/out-of-order and manual-activity handling, authoritative application, and qualified two-view convergence tests |
| Alert delivery | ADRs 0072, 0078, and 0085 locally implement source-idempotent durable incidents, claim-before-effect single-use provider attempts, sanitized terminal results, strict UTC plus monotonic one-/15-/30-second milestone evidence, same-key concurrency convergence, bounded history-first supervision, explicit total-failure evidence, and startup corruption checks. Migration 0032's same-store atomic binder accepts only durable replay-terminal failure or an unresolved escalation at its deadline, then appends one fixed severity-preserving `PAUSED` transition and exact source receipt. The legacy split writer is disabled. Abstract route classes still select no provider or recipient, and the fixed policy is not activated in a deployment. | Owner-approved primary/fallback providers, destinations, recipients, escalation roster, secret references, and activation of the fixed policy with its exact actor/authority digest; deployed worker and channel probes; PostgreSQL concurrency plus timed primary-failure, fallback-confirmation, restart, and operator-escalation drills |
| Reference backtest | Workload and thresholds specified; benchmark fixture/runner is not implemented | Checked-in deterministic fixture, semantic digest, runner metadata, and CI regression history |

Paper eligibility requires executable enforcement and evidence for every row
that can affect the paper environment. Live eligibility additionally requires
the supervised paper soak and minimum-size canary gates in the implementation
plan; this document alone grants no trading authority.
