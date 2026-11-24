# Wave 4 lane A — applied reconciliation preflight

Read-only proposal against canonical `adf39a99d3717d6800186dabd532399534bfe65c` (2026-09-10). W3 merge verification remains a prerequisite; this is not W4 implementation or provider authorization. Sources: `docs/IMPLEMENTATION_PLAN.md` section 8, `docs/ARCHITECTURE.md` sections 6–9, and the frozen personal-v1 contracts with `account-eligibility-amendment.md` applied.

## Smallest useful change

Add a versioned, one-round reconciliation service that retains independent observations, admits only evidenced facts, asks the sole coordinator to apply them atomically, and produces an explained comparison against the resulting ledger. It must never replace cash/positions with a broker snapshot, run another strategy loop, dispatch an order, release a reservation, or re-arm the account. Start with independently recorded stateful-simulator facts; E*TRADE parsing can produce observations and explicit blockers until actual financial identities/semantics are qualified.

Keep the existing Phase 4K reconciliation and inbox modules unchanged. Their types explicitly mean non-applying historical evidence, with application, UNKNOWN resolution and trading authority false. Do not upgrade their hashes, source-scoped identities or authority properties. A new application receipt can reference an old observation without changing its meaning or treating it as execution proof.

## Reuse and concrete gaps

| Existing implementation | Reuse boundary |
|---|---|
| `domain/broker_ingress.py`, `persistence/broker_ingress.py` | Raw-before-decode delivery identity, separate receipts for separate identical deliveries, hash chains and immutable read-back. Historical SQL stores response bodies; decide the new private object-reference format separately rather than relabelling a research archive or exposing broker payloads. |
| `domain/broker_reconciliation.py`, persistence twin; `domain/broker_inbox.py`, persistence twin | Preserve authenticated source linkage, quarantine and deterministic evidence patterns. Current lookups require local attempt/order/client IDs and intentionally cannot authorize application. They are not a general external-activity inbox. |
| `application/etrade_session.py`, `adapters/broker/etrade_readonly.py` | Existing bounded fixed-GET capture, exact account binding, retained query/page/receipt evidence, pagination failure detection and separate cash/margin observations. `EtradeReadCapture.traversal_complete` is transport traversal, not coverage or reconciliation proof. Reuse through injection; A need not edit transport or credential code. |
| `domain/order_reducer.py`, `ledger_reducer.py`, `account_projection.py`, `settlement_ledger.py`, `corporate_action_ledger.py` | Existing exact execution/revision conflicts, append-only balanced postings, reversal/correction lineage, FIFO and settlement/action economics. `persistence/phase2_ledger.py:persist_phase2_ledger_entry` already accepts the caller's transaction. No new financial calculator. |
| `domain/accounting_contracts.py`, `backtest/personal_accounting.py` | Reuse one-step accounting semantics through root's forward bridge. Current `_event` requires an installed order/commitment; terminal status zeroes modeled reserves. Neither behavior establishes durable provider hold release. External-order adoption and independently confirmed settlement need explicit integration. |
| `persistence/account_coordinator.py`, submission/reservation repositories | Retain in-transaction fence validation, commit revalidation and UNKNOWN freezing. `submission_attempt.resolve_unknown` still rejects unconditionally; root owns any reviewed resolver change. The pure resolver alone is not authenticated recovery. |

## Proposed shared records and ports

Root should freeze a small new `personal-applied-reconciliation/1` contract, preferably in root-owned `packages/domain/reconciliation_contracts.py`, before A/B/C implement consumers. All records are immutable, bounded, exactly serialized and content-addressed; versions participate in identities. IDs are scoped by provider, environment and account binding. Private payload references are not paths or credentials.

- **`ObservationRoundV1`**: `round_id`, account/provider/environment/binding hash, producer and qualification-reference hashes, requested opening/history boundary, typed balances/positions/orders/activity observations, ordered page receipts, first/last actual receipt times and completion time. Each page retains exact query/filter/window, ordinal, request/response hashes, private body reference, predecessor/continuation markers and terminal-response evidence. Provider effective/publication/revision/sequence fields remain nullable when absent. A local receipt ordinal is explicitly local and never a provider sequence. No caller-set `complete=True` can replace derived coverage checks.
- **`AppliedFactCandidateV1`**: provider fact identity and revision, predecessor identity for a correction, account/instrument/order mapping references, source receipt IDs, origin (`application` or `external`), factual effective/receipt times, and a narrow canonical payload or an unsupported reason. Supported payload union is `BrokerOrderEvent | LedgerCashFlow | StockSplitAction | CashDividendAccrual | CashDividendPayment | ExecutionSettlementConfirmation`; missing prerequisites prevent conversion. Exclude strategy targets, `InstallCommitment`, model observations/dispositions and control commands from this port. Candidate records confer no authority by themselves.
- **`OwnerDispositionV1`**: authenticated actor/action ID, exact account/attempt or external-activity identities, evidence references, disposition (`adopt_external`, `confirmed_accepted`, `confirmed_rejected_or_not_sent`, `unresolved`) and factual recorded time. Authentication/evidence validation is supplied by root; a bare owner assertion cannot supply missing fills, broker IDs or authoritative absence.
- **`ReconciliationRequestV1`**: request ID, retained round reference/hash, expected account revision vector, candidate references and applicable disposition references. The revision vector binds ledger, order/attempt, commitment, control, policy, lease generation and prior reconciliation cursor. No capability to overwrite a projection is included.
- **`AppliedRoundV1`**: request/round IDs, prior/after revision vectors, individually applied/duplicate/deferred/quarantined fact IDs, journal/order application links, immutable comparison, blocking discrepancy codes, exact unresolved obligation set, compared observation bounds, previous result and advanced watermark if justified. `comparison_status` is `blocked | pending_bounded_lag | converged`; it is separate from execution eligibility and always grants no trading/re-arm authority. UNKNOWN disposition and later capacity release have separate receipts.

Concrete narrow signatures (records above are root-owned; frozen existing types are reused):

```python
normalize_etrade_round(
    round: ObservationRoundV1, *, qualification: ProviderQualificationV1
) -> tuple[AppliedFactCandidateV1, ...]

compare_reconciled_account(
    *, expected: AccountSnapshot, observed: ObservationRoundV1,
    obligations: tuple[UnresolvedObligationV1, ...],
    previous: AppliedRoundV1 | None, policy: ReconciliationPolicyV1,
    now: datetime,
) -> ReconciliationComparisonV1

class ReconciliationAccountPort(Protocol):
    def apply_reconciliation(
        self, *, fence: AccountFence, request: ReconciliationRequestV1
    ) -> AppliedRoundV1: ...

def reconcile_round(
    round_id: str, *, fence: AccountFence,
    sources: ReconciliationSourcePort,
    account: ReconciliationAccountPort,
) -> AppliedRoundV1: ...
```

`ProviderQualificationV1`, `UnresolvedObligationV1`, `ReconciliationPolicyV1`, `ReconciliationComparisonV1` and the source-loader interface are root/B shared supporting types, not competing account models. The source port loads and verifies immutable references; it performs no network calls. Qualification is a verified durable producer binding, never a user-controlled permission flag. Policy records the frozen coverage, comparison precision and timing limits, with explicit bounded page/fact/payload limits chosen at freeze.

The coordinator implements `apply_reconciliation`: lock/revalidate ownership and current revisions; authenticate all retained source/qualification/disposition references; apply supported facts through the existing accounting transition/reducers; persist canonical order/ledger history plus dedup/application links; compare the resulting current projection; append result/cursor; revalidate the fence at commit. Any stale revision aborts for fresh preparation. The A SQL helper accepts the existing bound connection and never commits independently. Expensive decode stays outside shared read transactions; immutable source equality is rechecked in the final coherent capture.

Unsupported or incomplete observations retain blockers while independently authenticated supported executions continue to be booked. Missing pages do not erase known fills. Conflicting fact identity is quarantined; it is not a duplicate. A crash rolls back an uncommitted application; retry after commit returns its durable receipt without another posting. Atomicity is local database application, not an exactly-once broker-effect promise.

## Mandatory shared decisions before implementation

1. **Continuous engine/account bridge:** root's additive incremental entry must reuse the sole engine frontier/decision path. Historical `_Engine._admit`/product `RunSpec` require a complete tape and empty initial account; repeated historical reruns cannot be the forward loop. Reconciliation supplies facts/cursor/result to that entry, applies facts before callbacks, and never owns a second scheduler or financial state.
2. **Hold ownership:** B retains durable UNKNOWN/pending-cancel capacity independently of W2 modeled terminal commitments. An order terminal observation is not proof all fills/corrections arrived. Freeze an explicit snapshot representation for unreleased obligations and a separate later release transaction; A cannot call release or resolve-UNKNOWN directly.
3. **External mapping and sequencing:** freeze evidenced external order/activity adoption without invented local risk approval or submission attempts. Existing `BrokerOrderEvent` requires positive `broker_sequence`; absent E*TRADE sequence stays absent until a versioned mapping explicitly distinguishes local admission order. Confirmed real fills beyond estimates must be booked and halt risk, not rejected as inconvenient modeled fills. Unsupported financial shapes retain evidence and block, without fabricated balancing entries.
4. **Settlement/correction provenance:** freeze provider-confirmed settlement versus modeled due events and explicit correction predecessor mappings. A must not create actual settlement confirmations from the simulation calendar. Root owns any accounting/order/ledger DTO extension and retained old decoders.
5. **Durable schema and recovery:** root allocates additive schema/migration/codec changes for private source references, account-scoped fact/revision uniqueness, application-to-journal links, rounds/results/cursor and owner dispositions. B owns account/fence/control locking; root owns the attempt resolver and API/composition. No historical row/table is rewritten.

## Exact proposed lane A allowlist

All are **new** files, pending root assignment after merge and interface freeze:

1. `packages/domain/applied_reconciliation.py` — pure coverage/comparison/discrepancy rules.
2. `packages/application/account_reconciliation.py` — one bounded round workflow through injected ports.
3. `packages/persistence/applied_reconciliation.py` — immutable application/result/cursor persistence in the coordinator transaction.
4. `packages/adapters/broker/etrade_reconciliation.py` — pure retained-page normalization, with honest deferred candidates.
5. `tests/unit/test_applied_reconciliation.py`.
6. `tests/unit/test_account_reconciliation.py`.
7. `tests/unit/test_etrade_reconciliation.py`.
8. `tests/integration/test_applied_reconciliation.py`.

No edits to legacy reconciliation/inbox modules, canonical/order/ledger/accounting schemas, attempt/reservation/coordinator repositories, W1 transport/session/secret modules, engine, shared fixtures, SQL schema/migrations, API, packaging or canonical documents. Shared changes require separate root assignment.

## Acceptance and provider gates

Offline acceptance should cover: duplicate delivery versus duplicate execution; conflicting same identity; out-of-order correction/predecessor gaps; missing/cyclic pages; exact coverage-window boundaries; two complete rounds with intervening facts applied; late fills after cancel; complete obligation inventory including foreign orders; stale account revision/fence and crash/retry atomicity; restore gap and expired bounded lag; explicit external adoption; and negative UNKNOWN tests. Example independent arithmetic: a supported buy of 3 at USD100 with USD0.03 fee from USD1000 yields trade-date cash USD699.97 and 3 shares; a correction to USD101 yields USD696.97 through reversal/replacement, not a projection reset. Settlement moves buckets once. A duplicate changes neither history nor balances. Matching current views with a missing page or unresolved attempt remain blocked.

Apply the account amendment: CASH or explicitly selected MARGIN privileges do not alter `cash-funded-long-only/1`. Preserve discovery/balance mode disagreement, USD uncertainty, separate settled/unsettled cash, restrictions, margin liability/sign/calls and reserve overlap. Missing is never zero; margin buying power is never cash. Quantities compare exactly; cash tolerance up to USD0.01 requires per-field documented display rounding and cannot hide missing activity or become spendable capacity. Marks are diagnostic unless time/basis agree.

Hard E*TRADE gates remain: usable individual execution/activity identities and correction semantics; authoritative order/attempt mapping; opening/restore-gap history and statement coverage; complete documented pagination/204 absence semantics; USD and cash/liability/restriction semantics; current account/session and read qualification; actual endpoint quotas and quote entitlement/freshness. W1's complete production traversal and local read ceiling prove none of these. Sandbox stored examples still do not establish account economics. Two equal rounds, cumulative average fills, similar symbol/quantity/time matches or empty lookup cannot clear UNKNOWN. E*TRADE ambiguous Place remains durable/manual; no automatic resend, hold release, or re-arm. A simulator may qualify stronger identity/lookup semantics only for its own environment. Any fresh provider demonstration requires separately authorized current reads and cannot be substituted by synthetic evidence.

Preparation performed only source/document reads and this temporary proposal write. No tests, repository edits, credentials, provider calls, workers or W4 implementation were run.
