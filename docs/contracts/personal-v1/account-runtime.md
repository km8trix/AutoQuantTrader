# Personal-v1 account, broker and runtime contract

Contract ID: `personal-v1-account-runtime-1`. Frozen for Wave 0 against code `107fa791bb52e9fa42cbce65992ea1ce9168834e` and the consolidated 2026-09-08 target documents. This is a supporting specification for the one [architecture](../../ARCHITECTURE.md) and [implementation plan](../../IMPLEMENTATION_PLAN.md), not another roadmap. Requirements below describe replacement behavior; they do not claim it is implemented or authorize provider calls, credentials, deployment or live capital.

## 1. Scope and shared identities

One application-exclusive USD cash account, one strategy, whole-share long-only DIA/IWM/QQQ/SPY, regular-session DAY market orders. Replacement, margin, fractions, options and extended hours fail explicitly. Stateful forward simulation and E*TRADE sandbox are separate environments. Production Place/Cancel execution remains disabled through Wave 6; separately scoped read/preview qualification does not grant order authority.

Daily decision attempt is 20:00 America/New_York after the completed session. Missing required data may arrive until 09:00 of the next regular session; cutoff equality skips the decision. Execute only during 09:35 inclusive–09:40 exclusive of that later regular session using actual eligible observations. Calendar version controls holidays, half-days and DST. Late restart skips missed decisions rather than accumulating orders. The separately named daily-history next-open proxy cannot establish 09:35 execution or quote evidence. Root's engine contract owns historical availability and evaluation mechanics.

All domain decimals are finite canonical Decimal values; quantities are nonnegative whole shares. UTC timestamps are aware, expiry equality fails, and null means unavailable. Stable IDs and versions bind account state and effects:

| Object | Required identity and immutable bindings |
|---|---|
| Account binding | Internal account ID, provider `etrade`/`simulator`, environment, opaque broker account ID/key reference, USD cash eligibility, exclusive-use declaration, binding version and evidence digest; account labels are display only |
| Snapshot | Account/binding, ledger revision, position/settlement/mark revisions, commitment universe digest, control revision, policy assignment version, lease generation, reconciliation result ID, causal `as_of`, freshness measurement |
| Decision batch | Trigger/run/strategy/configuration/target digest; snapshot, policy and active commitment identities; stable sorted per-rule results with observed value/limit/source; all-or-none result and validity |
| Order intent | Deterministic ID from account+trigger+target revision+instrument+side+quantity+window+economic payload; explicit signed outstanding commitment adjustment; no strategy-supplied broker ID |
| Reservation | Reservation/decision/intent IDs, policy at approval, unfilled buy cash and exposure, unfilled sell quantity, release events and remaining balances; UNKNOWN parent freeze |
| Submission attempt | Independent attempt ID, intent/decision/reservation/fence/control versions, exact payload hash, immutable client ID mapping, preview identity, single-use send-claim identity, request and receipt journal IDs |
| Broker fact | Provider+environment+account namespace; authoritative provider execution/activity/order ID and revision/correction linkage; source occurrence, source receipt, normalization version, raw non-secret evidence digest |
| Reconciliation | Account, expectation ledger revision, observation coverage/watermark, page/run IDs, identity evidence, differences, disposition, completeness and completion instant; old result cannot certify newer unresolved effects |
| Owner command | Account+environment, authenticated actor, request ID/idempotency key, exact action+scope digest, requested/applied/control revisions, progress and terminal result; same key with changed body rejects |

Persist raw non-secret response evidence before publishing normalized economic facts. Credentials, authorization headers, OAuth token bodies and verifier codes never enter that journal. Account numbers are private; UI and portable evidence use sanitized labels/digests.

## 2. One pure daily risk entry point

`evaluate_daily_risk(policy, snapshot, target_batch, evidence, evaluated_at) -> DailyRiskDecision` is a deterministic, I/O-free domain operation shared by historical, simulated-forward and eventual connected compositions. It replaces the product choice between narrow Phase 0 risk, Phase 2 batch risk and the intraday moderate profile. It reuses batch reservation mathematics and the ledger; it must not weaken those implementations in place. The persistence application validates the same inputs again under the account lock, then atomically stores the full decision, reservations and durable outbound work. Broker I/O is outside that transaction.

Every input names its producer and time/data class. A missing mandatory rule input yields `UNAVAILABLE` and rejects new exposure; it never becomes `PASS` or a zero metric. Static instrument/account eligibility and operational permissions remain distinct. Historical mode uses explicitly simulated operational/session facts, never claims observed broker readiness. Decision-stage completed-bar freshness and execution-stage quote freshness are separate rules, avoiding the inherited same-session five-minute price rule being applied to overnight signals.

The following is `daily-v1-simulation-1`, an engineering default for synthetic USD 10,000 research capital, not an investment recommendation or live policy. Percent limits use the latest complete causal marked NAV. NAV must be positive. Tightening/configuration changes create a new policy digest and run identity. Defaults do not inherit ADR 0068's paper-only values.

| Rule / default | Historical producer | Forward/runtime producer and consequence |
|---|---|---|
| Account, strategy, universe, order subset | Frozen simulated account/instrument/strategy manifests | Qualified account binding, approved strategy artifact, current eligibility/restrictions; reject mismatch |
| Session and one daily trigger | Calendar+data availability policy+run trigger registry | Calendar+session timer+durable consumed trigger registry; one decision batch per source session; missing cutoff skips |
| Decision data complete and causal | Engine data view limited by factual/declared simulated availability | Validated captured source and receipt history; required session unavailable/stale rejects |
| Execution inputs | Named later-event execution model; next-open proxy has explicit assumed freshness and is exploratory | Source quote age `<5 s`, receive-to-check `<1 s`, nonfuture source time, source/account/entitlement match; unknown/delayed source rejects; no invented NBBO |
| Account/reconciliation/mark freshness | Current event-loop ledger, simulator reconciliation and causal marks | Ledger + applied broker facts; current reconciliation age `<60 s` and no later unresolved effects; current held-instrument marks and snapshot built `<5 s` ago at dispatch |
| Settled cash and shares | Settlement/action-aware account projection | Expected account ledger reconciled with broker field semantics; reserve buys independently of sell receipts; unknown availability rejects |
| Cash reservation | Buy quantity × reference price × 1.01 + configured fixed/per-share fees | Same estimate using fresh qualified price; estimate is no maximum execution price. Reserve at least this amount, also respecting provider-reviewed estimate when larger |
| Per-order quantity/notional | At most 1,000 shares and gross notional `<=25% NAV` | Same pure check, with account-approved live numbers required before any live assignment |
| Batch gross notional | Sum absolute proposed buy/sell reference notionals `<=95% NAV` | Atomic full-batch approval; splitting to evade daily intent caps is forbidden |
| Per-instrument concentration | Current marked long value + all remaining buy commitments + proposed buys `<=25% NAV` | Pending sells do not reduce the conservative numerator until fills; price drift can breach and stops new exposure |
| Account gross exposure | Current marked long value + remaining buy commitments + proposed buys `<=95% NAV` | No netting pending sells against buys; existing holdings remain observed on breach |
| Capacity and duplicate targets | Filled positions plus remaining signed commitments; one active intent per instrument, at most 4 outstanding intents account-wide | Approved-unsent, send-claimed, UNKNOWN, working, partial and pending-cancel count until authoritative release; target replay is idempotent |
| New intent count | At most 8 newly accepted intent IDs per exchange session | Durable distinct accepted intent IDs, counting terminal rejections/cancels once accepted; retries do not reset count; no double count of active+already-counted IDs |
| Daily loss | Flow-neutral cumulative wealth return from previous regular-session close `<=-3%` blocks new exposure | Same event/ledger-derived measure with complete current marks; contributions cannot reset loss; missing valuation rejects |
| Peak drawdown | `1 - current flow-neutral wealth index / prior-or-current peak >=15%` blocks new exposure | Peak persists across restarts and policy transitions; no reset by re-arm; missing history blocks; historical run/fold reset follows explicit engine contract |
| Request capacity | Deterministic simulator budget: rolling 60 s ceiling 20, low-priority ceiling 10 | W1 freezes actual endpoint/account quotas and local ceilings; reserve capacity for reconciliation/cancel; absent real quota prevents connected admission |
| Health, ownership and controls | Declared simulated health/lease/control events | Current lease generation, healthy clock/process, no control latch, current authorization; DB loss or unresolved UNKNOWN blocks |

No simultaneous proposed sell receipt funds a buy. Compute available cash as settled cash less executed-but-unsettled buy payables and other actual restrictions, then subtract only still-unfilled reservations; do not subtract a filled commitment again after it has become a payable. Available sell shares similarly exclude already allocated unfilled sells. Fees are expensed once according to the engine/accounting contract. Actual supported broker fills are booked even if they overshoot estimates or approved risk; halt and reconcile instead of discarding facts.

The 25% symbol cap applies to reference strategies too: a single-symbol reference holds at most 25% NAV and the rest cash; a four-ETF reference may target 23.75% each before buffers/rounding. An allocation does not receive an automatic safety exemption. A reduction of an existing breach may be admitted only through an explicit reduce-only scope, verifying that it cannot increase any exposure or oversell; loss/limit breaches never auto-flatten.

Deferred rules in this version: SIP/NBBO claims, one-minute volatility, spread/market-impact inference from daily OHLC, VaR, correlation and sophisticated participation/capacity. Their absence is stated in every policy/report; no connected quote substitute is relabeled SIP. Existing ADR 0068 policy/history/reservations remain interpretable. Cutover is paused, reconciled and serialized, preserving all old policy bindings and unresolved holds; only new decisions use the daily policy.

## 3. Reconciliation and UNKNOWN

Keep expected ledger state and independently observed broker state separate. The coordinator is the sole writer; reconciliation is an independently scheduled module operating through its account transaction. Startup/reconnect/restore starts `RECONCILING`, never `RUNNING`. Initial convergence budget is 120 seconds with periodic checks at least every 60 seconds; exhaustion retains the block.

| Coverage or comparison | Frozen v1 rule |
|---|---|
| Account scope | Check environment, account key/ID relationship and USD cash status on every observation group. Request all positions and all open/pending orders, including foreign orders |
| Lookback | Query supported order/activity history from the earlier of last fully reconciled watermark minus 7 calendar days or earliest unresolved attempt minus one regular session; first enrollment/restore must cover opening ledger boundary and full restore gap. Longer supported history/statement evidence is required if that interval is insufficient |
| Pagination | Retain exact query bounds, page IDs/markers, page digests, first/last receipt times and documented terminal-page evidence. Repeated/cyclic/missing pages, unknown truncation or unsupported range makes coverage incomplete |
| Convergence | Repeat balances/positions/order/activity comparisons across at least two complete observation rounds with intervening facts applied; bounded provider lag remains explicit. Equal pages or views alone do not prove an atomic snapshot or fill coverage |
| Execution identity | Require stable individual execution/activity identity and demonstrated correction semantics. Deduplicate exact identity/revision, reject conflicting same-identity content, append reversals/corrections. Cumulative quantity/average is a consistency check, not invented individual fills |
| Position quantity | Exact whole-share equality per stable instrument; zero quantity tolerance. Unexpected fractional holdings/actions make scope unsupported |
| Cash/fees | Exact Decimal posting internally. Compare corresponding qualified USD cash fields at declared precision. Initial aggregate display-rounding tolerance `<=USD 0.01` per field only with documented rounding explanation; never spend tolerance or use it to hide a missing activity |
| Ledger/P&L | Exact transaction amounts, fees, shares and supported action entitlement; timing differences must name pending settlement/action facts and expiry, not unexplained balancing entries |
| Marks/market value | Price-dependent aggregate valuation is diagnostic unless same price basis/time is established. No percentage tolerance can clear a share/cash/fill discrepancy |
| Commitments | Every local active/UNKNOWN/pending-cancel obligation is covered. Terminal status does not release capacity until known fills/corrections are applied and the remaining obligation is authoritatively absent |
| External activity | Default halt in the exclusive account. Owner adoption creates an evidenced external trade, flow, action or correction with origin; no direct overwrite of cash/positions or delete-and-rebuild erasure |
| Statement comparison | Independently reconcile official statements against API-derived facts and the restore gap before live/restore readiness. Missing historical activity coverage cannot be fixed by a current balance match |

Economic discrepancy classes are `EXPECTED_BOUNDED_LAG`, `MISSING_EXECUTION`, `DUPLICATE_OR_CONFLICT`, `EXTERNAL_TRADE`, `EXTERNAL_CASH_FLOW`, `CORPORATE_ACTION`, `UNKNOWN_ORDER`, `UNSUPPORTED_ACTIVITY`, `COVERAGE_GAP`, and `UNEXPLAINED_CASH_OR_POSITION`. Only explained lag within a recorded bound can remain temporarily pending; new exposure remains blocked when current economic completeness cannot be established.

An ambiguous Place atomically marks the attempt `UNKNOWN`, freezes its parent capacity and latches HALTED for new exposure. A crash after durable send claim is treated the same unless definitive acceptance/rejection evidence exists; absence of a network log is not proof of non-send. Similar symbol/quantity/time matches and empty lookup cannot establish identity or nonacceptance.

Recovery records overlapping order/activity/balance/position evidence, exact candidate IDs, broker confirmation where necessary and an authenticated owner disposition: confirmed accepted with authoritative mapping; confirmed rejected/not sent with authoritative evidence; or unresolved. Acceptance adopts the real order/fills without another Place. A disposition is durable and references evidence; a bare owner assertion never fabricates execution identity or absence. Unresolved remains blocked. Capacity release and re-arm are separate later transactions after fresh full reconciliation. Manual brokerage access is the fallback; this contract promises no automatic UNKNOWN resolution for E*TRADE.

Current `packages/persistence/submission_attempt.py:2004` always rejects `resolve_unknown`; current `packages/domain/broker_reconciliation.py` is non-applying evidence. Those are explicit W4/W5 integration gaps. The Alpaca-specific `lookup_unknown_by_client_order_id` scheduler in `packages/domain/unknown_submission_recovery.py` cannot become the E*TRADE recovery producer by renaming the provider.

## 4. Command, dispatch and owner actions

The account's database serialization boundary orders command application, ownership/control revisions, risk/reservation writes and send claims. API receipt means REQUESTED. Applying pause/halt commits the new control revision under that lock. A later send claim sees that revision and fails; a claim committed earlier remains in-flight and may complete or become UNKNOWN. Immediately before network dispatch, check current ownership/control and validity again. There remains a non-atomic gap between local checking and remote receipt; no exactly-once claim is made.

Owner commands are authenticated, bounded, durable and idempotent. Their status is REQUESTED → APPLIED → IN_PROGRESS → COMPLETED / INCOMPLETE / FAILED as appropriate, with timestamps, per-order results and residual exposure. Automatic health incidents may tighten control, never re-arm or initiate a liquidation.

| Action | Permission and completion |
|---|---|
| Pause new risk | Durable no-new-exposure latch; continue ingestion/reconciliation and explicitly allowed recovery. Applied target within 1 s on healthy coordinator/DB |
| Halt | Latched no-new-exposure; record cause and preserve all holds. Does not imply broker cancellation or flattening |
| Cancel/drain | Explicit bounded open-order scope, exact broker identity and separate cancel attempts. Completion requires terminal broker evidence for each order plus applied late fills; unresolved remains INCOMPLETE |
| Flatten | Separate owner request authorizing a reviewed reduce-only workflow. Cannot silently bypass shares/session/freshness/identity/uncertainty gates. Report positions and orders that remain |
| Stop process | Ordinary supervisor stop works while clock, provider or data is unhealthy. Stop local dispatch, record best-effort final state, terminate local worker, report possible broker exposure; it does not wait indefinitely for remote reconciliation |
| Re-arm | Explicit owner action with current account binding, session, lease/process, clock history, full reconciliation and disposition of every blocker. Old approval, restart, CI or expiry of a timer cannot re-arm |
| Policy/strategy/session change | Pause, quiesce and enumerate in-flight effects, reconcile, preserve original reservations/history; bind only new decisions to new versions. Session renewal alone grants no trading authority |

Process replacement requires confirmed old-process termination and review of already-claimed effects; no automatic failover. Lease expiry alone does not prove an old worker cannot send to a retail broker. If old-process termination cannot be established, remain halted and use owner recovery.

## 5. Effect-specific retry contract

Each attempt has a new journal identity, bounded deadline and incident linkage. Retry never overwrites an uncertain attempt, extends a stale approval or reuses a permit/nonce. Default request deadline is 3 s end-to-end. Read episode default is at most 3 attempts with 1 s then 2 s backoff, bounded by 15 s total and actual provider quotas/Retry-After; health/session checks repeat. This is a local default, not a provider guarantee.

| Effect | Permitted recovery |
|---|---|
| Read-only account/quote/order/activity GET | Bounded retries on transport/timeout/429/selected transient server failures. Journal unsuccessful attempts; new page fetch shares the declared coverage run. Invalid auth triggers session handling, not infinite retry; deterministic malformed/schema failures block normalization |
| OAuth token acquisition/exchange | Credential effect, not financial order. Preserve session attempt state and secret-store outcome; ambiguous exchange is not reused blindly. Owner may restart authorization through a new session attempt after disposition; no secrets in ordinary evidence |
| OAuth renew | At most one bounded retry with fresh nonce after session-coordinator validation; ambiguous outcome leaves session unqualified until authorized harmless read or renewed session proves usable. Midnight expiry requires new owner authorization |
| OAuth revoke | Immediately invalidate local usable-session state; record unresolved remote revocation and permit bounded operator retry. Remote failure never prevents local stop or reinstates a token |
| Preview | Fresh bounded attempt after full validation only when durable history proves no Place was claimed/could have occurred. Refresh quote/risk/permit/payload bindings; local TTL `<30 s`; unknown business warning blocks Place |
| Place | One dispatch per durable attempt. Definitive rejection may terminate; timeout/crash/ambiguous result becomes UNKNOWN. Never automatic resubmit, including by making a new intent or preview |
| Cancel | One dispatch per authorized cancel attempt; ambiguous result remains pending-cancel with held capacity. V1 has no automatic reissue; reconcile late fills, then owner disposition/new specifically permitted action |
| Alert/heartbeat | Retry with incident deduplication; duplicate warning is acceptable. Persist incident within 1 s, primary acceptance target 15 s, fallback/visible failure 30 s; provider acceptance is not proof owner saw it |
| SQL transaction | Retry only known-aborted serialization/deadlock transactions with original logical ID and fresh state. After uncertain commit read durable identity first. Never wrap broker I/O in transaction retry |
| Local file/report publication | Atomic publication by immutable content digest; verify prior artifact after uncertain completion. Never duplicate accounting to make a report succeed |

## 6. Standard clock, process and secret boundary

`Clock.now() -> aware UTC` remains the simple compatibility port. Replacement runtime adds `monotonic_ns()`, `health_snapshot()` and a boot/process epoch. Health evidence carries source identity, UTC observation, local monotonic observation, measured offset plus source uncertainty, sampling duration, sample sequence and status/reasons. Historical runs use deterministic simulated clocks and labelled simulated health; they need no native signer or online time source.

Runtime target: warn at absolute offset+uncertainty `>=250 ms`, block at `>=1 s`; sample at startup and every at most 30 s while armed; sample age `>=30 s` blocks; regression, missing source, boot/process change or suspend gap blocks before any effect. Use aware UTC for durable facts, monotonic for elapsed budgets, database time for lease authority. Cross-check UTC-vs-monotonic elapsed delta and host suspend/wake indications. All deadlines are bounded; source measurement unavailable is not zero drift. A blocked condition requires 60 s continuous healthy observations and explicit owner re-arm. This equality convention is versioned: the historical trusted-time reducer's boundary semantics must be tested/migrated explicitly rather than silently changed.

Use the existing pure `packages/domain/trusted_time.py` reducer and monitor concepts where practical, with a standard OS time-health producer and ordinary process supervisor. The target assumes an owner-controlled host and reviewed strategy code. It does not promise cryptographic host integrity or adversarial rollback prevention. Preserve useful temporal regression/freshness tests and immutable audit bindings; native seals/signatures/remote anchors are separate historical evidence.

API/UI stores authenticated owner commands and sanitized reads; it cannot obtain broker order credentials. Research process gets no production broker secret or active-account write role. Strategy subprocess receives only bounded snapshot/config and returns a bounded target: no SQL/broker/network access or secrets. Strategy budget is warning 2 s, reject 5 s, cleanup 8 s from one monotonic origin. Root's resource defaults are one job, 2 CPU, 4 GiB, 30 min, 1 GiB output. Separate research and account database pools/roles protect coordinator control capacity.

Coordinator-owned session helper uses a versioned OS secret-store reference and ephemeral verifier transfer. Keep sandbox and production key/token/account namespaces separate. No account token is copied to frontend bundles, run artifacts, query strings, logs or `.env` inference. Secret-store failure blocks new effects; necessary observations already received are still journaled. Supervision restarts halted, does not re-arm or flatten. A dedicated awake host/external heartbeat/off-host restore qualification is required before unattended execution; development on the owner's Mac is supervised.

## 7. E*TRADE capability and qualification matrix

Public official docs were checked during Wave 0 on 2026-09-09 UTC. These facts are documentary, not verified account access. OAuth1.0a uses owner authorization; the guide describes inactivity after two hours, renewal of the same token, and default midnight US Eastern expiry. Sandbox returns stored examples rather than a stateful trading simulation. [Developer guide](https://developer.etrade.com/getting-started/developer-guides)

| Capability | Documentary fact / implementation contract | Required actual qualification |
|---|---|---|
| OAuth/session | Account-scoped environment binding, durable session lifecycle and secret-store helper | Individual production key/access, exact privileges, cash account eligibility, renewal/reauthorization behavior and owner participation schedule |
| Account discovery | Existing recorded account-list parser/binding seam | Authorized account-list capture, accountId↔accountIdKey mapping, selected account restrictions and exclusive-use commitment |
| Balances | API exposes multiple cash/buying-power views; adapter must preserve meanings instead of treating all as settled cash. [Balances API](https://apisb.etrade.com/docs/api/account/api-balance-v1.html) | Verify cash-account fields, settlement and restrictions under actual account permissions |
| Portfolio | Paginated portfolio endpoint gives observed positions; not a substitute for executions. [Portfolio API](https://apisb.etrade.com/docs/api/account/api-portfolio-v1.html) | Quantity basis, action/fraction behavior, completeness and latency |
| Quotes | Quote API supplies source-specific quote/time/status fields; no universal NBBO assertion. [Quotes API](https://apisb.etrade.com/docs/api/market/api-quote-v1.html) | Retention/use rights, realtime entitlement, timestamps, delay flags, coverage and freshness at 09:35 |
| Orders/Preview/Place/Cancel | Order API provides these surfaces; account-unique alphanumeric client ID has maximum 20 characters and is documented absent from responses; preview must be used within 3 min. Local contract is stricter and replacement is disabled. [Order API](https://apisb.etrade.com/docs/api/order/api-order-v1.html) | Actual order IDs, individual fills, messages, partial/cancel behavior and endpoint quotas. Read qualification W1, restricted transport W5, scoped preview evidence later, actual live orders separately authorized |
| Activity/corrections | Transactions expose transaction IDs and details, with pagination and transaction/settlement fields. These fields do not establish unique execution/correction coverage by themselves. [Transactions API](https://apisb.etrade.com/docs/api/account/api-transaction-v1.html) | Stable IDs across pages/retries, fill-to-order linkage, fees, reversals/corrections, settlement, actions and complete recoverable history |
| UNKNOWN identity | No documented client-ID response/lookup guarantee is assumed | Broker/owner-supported authoritative resolution path. If exact order linkage or reliable nonacceptance evidence is unavailable, stay halted; never use fuzzy match or empty search to retry |
| Stateful testing | Local simulated broker supplies controllable execution/recovery faults | Sandbox protocol success, local simulated economics, production reads/previews and live evidence remain four separately labelled evidence classes |

Missing actual access, rights, quote semantics, provider quota/time-health measurement, account eligibility, activity recovery evidence and owner live limits are future qualification inputs. They do not block freezing this contract. They do block the corresponding connected lane or live gate; a key's existence would not remove that distinction.

## 8. Migration ownership and acceptance obligations

| Boundary | Current modules/callers | Exclusive owner and replacement acceptance |
|---|---|---|
| Pure daily risk | `packages/domain/risk.py`, `batch_risk.py`, `advanced_risk*.py`; engine, supervised strategy and persistence consumers | W2 engine/risk lane. One canonical entry point, independent boundary arithmetic, missing-producer/future-row tests; legacy contracts retained until consumers migrate |
| Atomic reservations/lease/control | `packages/persistence/batch_risk.py`, `advanced_batch_risk.py`, `account_coordinator.py`, `operational_control.py`, `reservation_lifecycle.py`; API and coordinator | W4 account lane; orchestrator alone owns shared schema/migrations and canonical composition files. Contention, policy cutover, no double spending/release, pause-vs-claim and crash cases |
| Reconciliation/OMS/UNKNOWN | `packages/domain/broker_reconciliation.py`, `submission_attempt.py`, `unknown_submission_recovery.py`; persistence twins, broker inbox, historical Alpaca recovery pipelines | W4 account lane, W5 broker/control lane consumes frozen applied contract. Duplicate/correction/coverage/late fill, uncertain claim and manual disposition tests; no E*TRADE client-ID lookup fiction |
| E*TRADE session/read boundary | `packages/adapters/broker/etrade.py`, `etrade_accounts.py`, `etrade_oauth.py`; `packages/application/etrade_oauth_token_runtime.py`, persistence coordinator | W1 broker lane; later restricted order adapter W5 broker lane. Recorded fixture recovery, environment/secret isolation, then separately authorized actual reads |
| Time/process/packaging | Clock/monitor, supervisor, build and Compose dependencies in [native map](native-dependency-map.md) | W1 runtime lane with orchestrator serialization of Make/CI/pyproject/architecture/schema; W5 integrated failure drills |
| API/UI and operations | `apps/api/main.py`, operations views, `packages/application/local_operations.py`, `packages/persistence/local_operations.py`, web operations feature | W5 controls/UI lane. Durable requested/applied/result semantics, account/environment banners, real persisted residuals and authenticated re-arm |
| Research consumers | Backtest reports/jobs, simulated account/risk producers, dataset/run manifests | W2 engine and W3 research lanes; frozen account snapshot/decision/report interfaces shared once, no runtime credentials or live authorization inheritance |

Tests to preserve include `test_batch_risk`, `test_risk_and_execution`, `test_submission_attempt`, `test_unknown_submission_recovery`, `test_account_coordinator`, `test_operational_control`, `test_trusted_time`, `test_trusted_time_monitor`, E*TRADE fixture/OAuth tests, and PostgreSQL risk/submission/reservation/lease/control integration suites. Exact existing file names and callers are in the dependency inventory and root baseline record. Current passing tests certify their current bounded contracts, not completion of the new runtime. No source, schema or behavior changed in Wave 0.
