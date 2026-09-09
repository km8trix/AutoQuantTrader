# Personal-v1 operational budgets

Status: target specification with Wave 0 engineering defaults frozen 2026-09-08; no operational profile is qualified or activated by this edit. [ARCHITECTURE.md](ARCHITECTURE.md) owns design and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) owns delivery gates. This file replaces the old mixed one-minute/Alpaca/native-time future budget specification; historical values/approvals remain scoped to their old profiles in Git and ADRs.

The [scope/default contract](contracts/personal-v1/scope-defaults.md) freezes research resources/schedule; [account/runtime](contracts/personal-v1/account-runtime.md) freezes synthetic daily risk and producer rules. These are development defaults awaiting implementation/measurement; actual provider delivery/quotas, quote entitlement and live financial limits remain unqualified owner inputs.

## Measurement rules

Use aware UTC for durable time, database authority for leases and monotonic clocks for elapsed deadlines. Expiry equality fails (`now >= expires_at`). Record actual source timestamps, local receive time and measurement availability separately. A missing mandatory measurement fails closed. A claimed p99 requires a recorded sample population and cannot replace per-event hard limits.

The following are design targets to validate in Waves 0–6, not broker guarantees. Tightening is allowed in a reviewed configuration. Loosening or changing semantics requires a versioned policy decision and affected evidence requalification. No paper number automatically becomes a live financial limit.

| Concern | Proposed target / required decision | Failure behavior |
|---|---|---|
| Daily source availability | Freeze provider-specific expected delivery and latest acceptable decision cutoff in W1; measure actual publication/receipt coverage | Skip stale/missing-session decision, alert, no catch-up order backlog |
| Execution quote freshness | Start with `<5 s` source age and bounded receive/processing delay; verify actual source timestamp/entitlement semantics in W1; no unproved NBBO label | Block new exposure; current quote never guarantees fill price |
| Strategy execution | Warn at 2 s, reject at 5 s, bounded cleanup by 8 s from one monotonic origin; validate resources on target host | Reject late output, pause new exposure; continue coordinator control/observation |
| Risk approval | At most 30 s from durable approval and no later than intent/quote/preview validity; exact policy/payload binding | Reject expired/changed approval; never extend it implicitly |
| E*TRADE preview | Local TTL at most 30 s, stricter than documented provider window; all other freshness gates still apply | Discard stale preview; fresh workflow only if no Place could have occurred |
| Clock health | Warn at 250 ms absolute drift; block at 1 s; sample at startup and at least every 30 s while armed; check suspension/regression before effects | Pause/halt new exposure; 60 s healthy history and owner re-arm after recovery |
| Broker request deadline | Initial 3 s end-to-end request budget, including connection/read; qualify on actual transport in W1/W5 | Effect-specific result: bounded read retry; ambiguous Place/Cancel retains uncertainty and capacity |
| API request capacity | Select current E*TRADE account/endpoint limits and conservative local ceilings in W1; reserve capacity for cancellation/reconciliation | Deny lower-priority work; honor rate-limit responses; no inherited Alpaca 200/min assumption |
| Reconciliation | Startup/reconnect barrier; initial 120 s convergence budget and periodic checks at least every 60 s; order polling cadence separately fits real provider quota | Remain non-running on unresolved differences; matching views alone are insufficient |
| UNKNOWN | New exposure halted immediately; begin evidence gathering/owner warning immediately; escalate by 60 s unresolved | Never clear merely because a timer expires or lookup is empty |
| Pause application | Target durable acknowledgement within 1 s when database/coordinator healthy; serialize against new send claims | UI distinguishes requested/applied/failed; already in-flight effects remain tracked |
| Operator cancel/flatten | Freeze per-operation timeout and permitted residual handling by W5 for current session/liquidity | Report incomplete orders/positions; never label process shutdown as flatness |
| Critical alert | Target durable incident within 1 s, primary provider acceptance within 15 s, fallback/visible failure by 30 s | Record deduplicated attempts; delivery acceptance is not proof owner saw it; halt/pause per incident policy |
| Host heartbeat | Initial every 30 s, external stale threshold 90 s; qualify while host is stopped | Independent owner warning; monitor grants no automatic recovery authority |
| Backups and restore | Research RPO target 24 h; live journal backup/PITR target at most 5 min and restore/reconcile RTO target 60 min, validated before unattended use | Restore halted; rebuild missing brokerage facts; unresolved gap prevents re-arm regardless of RTO |
| Storage/resources/cost | Freeze dataset retention, worker CPU/memory/job concurrency, disk watermark and monthly cost ceiling before deployment | Stop new research at capacity; preserve execution/ledger/alert resources; never discard financial history silently |

Backup targets are recovery objectives, not a claim that accepted orders can be lost safely. Broker records and independent statements must cover the restore gap. If the chosen storage plan cannot meet these requirements, keep unattended live disabled or choose a qualified plan; do not assume free-tier backups/PITR.

## Financial profile and qualification record

Daily-v1 simulation risk gets explicit concentration, exposure, settled-cash, shares, order/batch notional, order count, loss and drawdown limits with documented measurement conventions. Implement pure rules in W2 and durable runtime producers/cutover in W4. Preserve the old ADR 0068 paper profile as historical; it has different intraday/SIP dependencies. Choose live capital, shares/notional and loss limits in the W6 dossier, obtain owner approval before W7, and persist the exact policy assignment.

The orchestrator records each qualified budget's policy version, source, measurement population, measured result, failure drill, reviewed revision and deployment environment. Every budget affecting execution must have a supported producer and observed failure behavior before that environment is armed. Operational targets, paper performance and this document confer no live authorization.
