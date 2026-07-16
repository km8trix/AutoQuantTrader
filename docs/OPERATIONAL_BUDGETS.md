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
- Environment overrides may tighten a safety limit. Loosening requires a
  versioned review with recorded evidence; it cannot be an ad hoc runtime edit.

## Initial values

| Budget | Initial value | Measurement point | Hard-limit behavior | Owner |
|---|---|---|---|---|
| Complete-bar data age | Warn at 5 s; hard limit 15 s after the expected one-minute interval close | Decision start minus the latest complete bar interval end, using the exchange calendar | Do not create new-exposure targets; record the stale symbols and remain paused until a watermark-complete fresh batch exists | Data plane |
| Strategy decision deadline | Warn at 2 s; hard deadline 5 s per watermark-complete batch | Monotonic time from strategy invocation through validated target return | Terminate or quarantine the strategy invocation and pause new exposure; order, risk, broker-event, and reconciliation loops continue | Trading runtime |
| Persisted risk-approval TTL | 30 s maximum from the durable approval commit; shorter intent expiry wins | Durable commit time through atomic consumption immediately before dispatch | Reject when expired, consumed, policy-mismatched, or payload-mismatched; never refresh an approval implicitly | Risk |
| Clock drift | Warn at 250 ms; hard limit 1 s absolute offset from a trusted time source | Host UTC offset sampled at startup and at least every 30 s while armed | Block arming and new exposure; require healthy samples for 60 s plus explicit re-arm | Platform operations |
| Broker submission uncertainty | 3 s request deadline; first client-ID lookup within 1 s; unresolved hard budget 60 s | Monotonic time from dispatch until authoritative acceptance, rejection, or lookup result | Persist `UNKNOWN`, block new exposure for the account, query by the same deterministic client ID, and never retry the submit blindly; alert at 60 s and remain blocked | Execution |
| Reconciliation | Run as a blocking startup/reconnect barrier; require two matching views at least 2 s apart; 120 s convergence budget; periodic check every 60 s while armed | Monotonic time from barrier start through the second converged broker/local view | Do not enter or remain `RUNNING`; classify and expose every economically relevant difference and require operator resolution | Reconciliation |
| Critical-alert delivery | Enqueue within 1 s, primary delivery confirmation within 15 s, fallback confirmation within 30 s | Monotonic time from durable critical event creation to provider acknowledgement | Mark alerting degraded at 15 s; invoke the independent fallback route and block new exposure if no route confirms by 30 s | Platform operations |
| Reference backtest | 98,280 deterministic events (one ETF, 252 sessions, 390 one-minute bars), one strategy/risk/ledger path; warm runtime <= 10 s and peak RSS <= 512 MiB on a 2-vCPU, 2-GiB Linux runner | End-to-end process runtime and peak resident memory after one untimed warm-up; semantic digest compared across two runs | Fail the performance gate on a >20% runtime regression from the accepted rolling baseline, any memory breach, or any semantic-digest difference | Research platform |

The submission request deadline does not mean the broker rejected the order. A
timeout is ambiguous and enters `UNKNOWN`; only an authoritative broker event or
client-ID lookup resolves it. Likewise, exceeding reconciliation or alerting
budgets never causes automatic resume or failover.

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
| Data-age and decision deadlines | Values specified; live feed supervision is not implemented | Captured-tape gap, stale-bar, reconnect-backlog, timeout, and process-isolation tests |
| Clock drift | Value specified; trusted-time monitoring is not implemented | Startup and in-session drift injection with fail-closed and manual re-arm evidence |
| Submission uncertainty | Policy specified; no paper/live broker adapter is enabled | Recorded broker-contract tests and kill-at-every-submission-boundary fault tests |
| Reconciliation | Policy specified; no broker reconciliation barrier is enabled | Pagination, stream/snapshot overlap, duplicate/out-of-order, manual-activity, and two-view convergence tests |
| Alert delivery | Value specified; independent alert routes are not configured | Primary-route failure, fallback confirmation, delivery-probe, and operator escalation drills |
| Reference backtest | Workload and thresholds specified; benchmark fixture/runner is not implemented | Checked-in deterministic fixture, semantic digest, runner metadata, and CI regression history |

Paper eligibility requires executable enforcement and evidence for every row
that can affect the paper environment. Live eligibility additionally requires
the supervised paper soak and minimum-size canary gates in the implementation
plan; this document alone grants no trading authority.
