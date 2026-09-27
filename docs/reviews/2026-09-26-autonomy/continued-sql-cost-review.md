# Continued A2 SQL construction/execution cost review

2026-09-27; clean HEAD `071dd5c5624b35bef114275d4431823c9c82edeb`. Read-only source, installed dependency source and existing evidence inspection. No repository edits, project imports, tests, databases, benchmarks, heavy fixtures, provider access or nested workers. Standard-library-only commands selected profile rows and computed hashes.

**Result: no new small behavior-preserving SQL/account/journal repair is established by this review.** The latest evidence confirms substantial fresh SQLAlchemy expression construction and cache-key traversal, rather than identifying expensive database execution. Avoid interpreting this as proof that all optimizations are exhausted. A separate, concrete missing receipt index is identified below, but its effect on this failing workload is not established and the current evidence does not justify a migration or another retained fixture.

## Actual cost evidence

The latest `linux-55951fb-diagnostic-profile.json` is valid with no diagnostic faults, but factory execute did **not** return. It is a partial failed, cProfile-instrumented observation. Its static rows aggregate all callers; they contain neither per-statement cache hit/miss counts nor query plans. Inclusive rows overlap and are not available savings.

| Observed function | Calls | Self seconds | Inclusive seconds |
| --- | ---: | ---: | ---: |
| journal `_columns` | 11,665 | 0.296782 | 6.900901 |
| journal `_capture_receipt` | 2,979 | 0.119857 | 9.780549 |
| journal `_entry_row` | 4,606 | 0.069090 | 4.960733 |
| SQLAlchemy `_compile_w_cache` | 14,856 | 0.039132 | 6.578978 |
| SQLAlchemy `_generate_cache_key` entry | 14,856 | 0.034015 | 5.141910 |
| SQLAlchemy recursive `_gen_cache_key` | 1,125,627 | 3.013871 | 5.044113 |
| SQLAlchemy coercions `expect` | 1,472,241 | 2.422728 | 7.197745 |
| SQLite cursor `execute` | 15,298 | 0.526013 | 0.526013 |
| SQLite cursor `fetchone` | 28,830 | 0.063414 | 0.063414 |
| journal `_copy` | 11,665 | 0.064852 | 0.097526 |

The concrete source mechanism is fresh construction of bounded `substr`/SQLite storage-type `CASE` projections at every original query site, followed by fresh `Select`, comparison/bind and ordering/limit nodes. SQLAlchemy traverses each newly constructed statement to identify its compiled shape and collect its current bind parameters before looking up compiled SQL. Its installed `sql/elements.py:_compile_w_cache` explicitly calls `_generate_cache_key()` before `compiled_cache.get`; a cache-key cost therefore does **not** demonstrate a cache miss or that increasing the engine cache would help. The recursive visitor also encodes SQL/type-handler structure (`sql/cache_key.py:221`), not just a dispensable statement label.

Database `execute` and selected `fetchone` costs are far smaller in this trace. This does not supply a complete database cost bound—the report selects top rows and omits others—but it supplies no evidence of a dominant SQL scan, network wait or lock contention. It does not attribute the lease failure to this subsystem alone or predict unprofiled/Linux savings.

## Preserved responsibilities and prior exclusions

`durable_journal.py:111` reads current table/column/type/name/length and conditional dialect information, then creates fresh labeled bounded expressions. The extra rejection byte and SQLite storage-type branch prevent oversized corrupt retained text/blob transfer from escaping declared bounds. `_entry_row:175`, `_stream_row:189`, `_capture_receipt:199`, `capture_in_transaction:686` and `recheck_in_transaction:889` preserve query order, read/copy multiplicity, optional row-lock shape, conditional predecessor read and each detached validation. Exact row-count/chain/owner tests depend on those observations.

The account coordinator additionally makes its original locking/head/history/current-lease observations and trusted clock/fence receipt checks (`account_coordinator.py:655–829, 1256`). Removing a history or head read because the immediately preceding value looked equal would change the safety contract and is outside this task. Batching receipt, anchor or account reads would change the original observation/error ordering; it is not an allocation optimization.

The previous projection source is byte-identical. Its guarded reuse and guarded-clone alternatives were already rejected after ten finite normal and 41 adverse cases, including schema/type/dialect/limit changes, exposed-expression mutation, row changes and malformed bind inputs. Recorded candidate/original medians were 1.561–1.598 and 2.319–2.452. The proof was itself incomplete against arbitrary mutable compiler state. A second attempt at the same templates, now called a compiled-query optimization, is not a new source-backed candidate.

`daily_runtime_risk._recheck_table:805` has an existing operation-local projection reuse contract. That does not authorize extending its lifetime into distinct original journal constructions or replacing current schema/compiler reads. Factoring repeated SQL predicates out of rows, coalescing fresh reads, raw-driver SQL or literal-text shortcuts would remove/change existing SQL checks, type/bind behavior, events or ordering. None is proposed.

## New alternatives considered

**Disable compiled caching:** this would avoid cache-key traversal, but the actual installed implementation then calls the compiler for every execution instead of looking up its compiled result. It changes compilation frequency, type-processing/cache behavior, observable cache-hit metadata and compiler/error-hook timing. The profile does not measure the resulting compile cost, and there is no established finite compatibility seam for this change. It is not a demonstrated same-behavior repair, so no benchmark/prototype is released.

**Increase cache size or prewarm it:** key generation still precedes every lookup. There is no cache-miss/eviction evidence. Moving cold work outside the original lease/operation timing would also be an unapproved pre-lease change; no such relocation is suggested.

**Result-wrapper/copy simplification:** `_copy` has only 0.097526 s inclusive across this partial trace. Replacing `.mappings().one_or_none()` with a different result protocol would require proving the same processing, duplicate-row error and callback behavior; the selected profile does not establish wrapper allocation as a meaningful target. Removing a runtime `typing.cast` alone cannot address the multi-million-node construction/key traversal. No new implementation candidate is justified by these small aggregate figures.

**A missing journal receipt lookup index is a distinct source fact.** The entries query in `_capture_receipt:214–227` filters `(key_sha256, command_id)`, orders by `sequence`, and limits to `MAX_APPEND_RECORDS + 1`. Current `durable_journal_schema.py:52–80` and migration `0040_personal_continuous.py:77–100` declare primary key `(key_sha256, sequence)` and unique keys `(key_sha256, record_id)` / `(key_sha256, sequence, entry_sha256)`, but no `(key_sha256, command_id, sequence)` index. A secondary index of that shape could narrow the engine's receipt-row lookup while preserving the original query, order, result limit, copies and validations. It needs no reusable validation proof.

However, source alone does not show the actual query plan, selectivity, stream size or its share of the subsecond driver time. An index does not reduce Python projection construction or cache-key traversal, the dominant demonstrated SQL costs. It would add persistent schema/migration/write overhead and require normal exact-schema and SQLite/PostgreSQL acceptance. Therefore **do not present it as the restore repair or modify migrations on this profile alone**.

If the parent chooses to investigate that precise index question, the smallest later experiment would be finite fresh synthetic journal tables with the current schema and a candidate index in an isolated temporary database: inspect query plans and compare unchanged SQL/binds/result ordering and bounded transfer on realistic stream/receipt sizes, including early/late/missing commands and corrupt/oversized rows. Measure lookup cost separately from unchanged Python construction and account for insert/index/storage costs. An actual source-owned statement timing attribution would only be useful if the finite scan/selectivity evidence first suggests material opportunity. Neither experiment is run or requested as a mandatory next step here; no heavy retained rerun is justified now.

## Disposition

Preserve all original fresh reads, compiler/bind paths, transfer bounds, owner/object/fence checks, error order, lease and process/resource limits. No production edit or renewed reuse/pre-lease proof is proposed. The reviewed SQL branch has a concrete explanation for its current overhead and a separate unmeasured indexing hypothesis, but no established material behavior-preserving repair. This is a bounded negative assessment, not universal impossibility or permission to relax acceptance.

## Source/evidence hashes

```
ce6f67167d95ede5696bb11781d46c3bc5a83e871f51b18de8e421ff28324f71  packages/persistence/durable_journal.py
9cae2ec289ac364c6b73b0d6605f33b47ee843bc3b8e798d57fc78b1228af4cf  packages/persistence/durable_journal_schema.py
5f3cc0b043e3ea58344eb9d8757daf76a95f11fc6088e4b744cfe3b483fa8a86  packages/persistence/account_coordinator.py
846fd7019ce65ca13dabf00132fb94d7dec003e3f0ae8be778dd342d4ddd26a0  packages/persistence/database.py
cfae83fee7d05ff79dbc3a8e47036870c88d9785247171ba0bcbb4e30f6fee24  packages/persistence/daily_runtime_risk.py
0713cc6c55b35a7cd93eb89cb92cc4639ad9ba249c4d0f4389390ebeff78023d  packages/persistence/continuous_integrity.py
772a02be48d8c9542481c7f76333481867bdf7b7be7b707a02eb79d4f211f74d  migrations/versions/0040_personal_continuous.py
9584eb25ebea09189b4ed92fa89827a445b6a1c76d65262b14b7b5be70cdb941  uv.lock
22d6e05571620a7170938a59f0881b848e176317cf128cb5766bf44f5b1fb52f  docs/reviews/2026-09-26-autonomy/linux-55951fb-diagnostic-profile.json
cc5a27f0a6aa3e4759c5a6ccf659b214771612a2e62ce0d50ad445242cb7e417  docs/reviews/2026-09-26-autonomy/journal-projection-rejection.json
0dd6428c1058fe2dcbdab0fb0d921ece1ea7714c02dd5570f58de629785b0675  docs/reviews/2026-09-26-autonomy/journal-columns-cost-assessment.md
```

## Separate consequential decision, if ordinary repairs remain unavailable

This section is a read-only decision assessment requested after the cost review. It is **not** an authorized implementation, experiment, new acceptance rule or a recommendation to insert a renewal call.

The smallest concrete policy question exposed by the actual source is: **must this offline HALTED restore finish under one unreplenished 60-second lease revision, or may the same original owner renew its liveness lease while the unchanged hard operation/parent deadlines still bound the work?** The first is today's tested behavior. The second is an explicit change to restore ownership/acceptance, even if each lease TTL remains 60 seconds; it can extend cumulative ownership. The existing user instruction and prior studies do not authorize it by implication.

There is an actual renewal primitive, not a need to invent another lease protocol: `SqlAccountCoordinator.renew:1039` locks the durable head, checks complete current lease history and the exact fence, samples trusted time, rejects expiry, and (unless heartbeat time is unchanged) appends revision N+1 with the prior digest, original account/owner/lease ID/generation/policy/acquisition time and a later heartbeat/expiry, then exactly reads back the updated head. `AccountFence` deliberately omits revision and expiry (`domain/account_coordinator.py:103, 237`), so its identity remains stable across a valid renewal. This establishes only the coordinator primitive.

It does **not** establish a factory renewal seam:

- `CommittedAccountObservations` records exact owner/thread/fence/original head; tracked `revalidate` permits only successful `updated_at` changes (`account_coordinator.py:1188–1320`). Renewal changes the head digest and lease inventory. `renew` does not register such a transition in that observation state. A following fresh check would reject it.
- Integrity starts from exact coherent snapshot equality and later permits only that tracked head observation replacement (`continuous_integrity.py:1954, 1912`). Its original lease rows remain exact. A renewal is not covered by the timestamp exception, and cannot be hidden by excluding lease tables, rebasing the snapshot or relabeling old receipts as current.
- The supervised worker verifies acquisition revision 1 and then demands the exact original lease row, digest and expiry (`continuous_process_lifecycle.py:402–412, 498–500`). Both parent and child bind terminal release to that original lease digest (`:452, 480, 668`). Thus a factory-only change would break the independent parent observer and terminal protocol even though AccountFence is stable.

A concrete constrained alternative for the owner to consider would be **a separately versioned offline HALTED restore contract permitting at most one authenticated same-owner renewal at an existing out-of-transaction progress boundary before expiry**, with the initial and renewed revision both explicitly observed and retained, no background renewal thread, no retry/reacquisition/rearm, and fresh receipts issued only by the actual current owner. This is narrower than an indefinite heartbeat policy. The 60-second *per-revision* TTL would remain; cumulative ownership would change and must be acknowledged. The retained 120-second hard operation and applicable 150-second parent deadlines, cleanup reserve, separate worker's actual configured wall/CPU/memory bounds and all data/binding caps remain independent hard limits. There is no established schedule or guarantee that one renewal would make this workload succeed.

That policy choice has a concrete implementation boundary if separately approved: original coordinator transition ownership, factory committed-observation/integrity comparison for exactly the owned next lease row/head, and parent/child revision-and-release observation. It must preserve every existing fresh SQL/object/source/fence and terminal check. It needs evidence for foreign/concurrent renewal, rollback and uncertain commit, original versus renewed digest, skipped/duplicate/out-of-order revision, caught failure, expiry equality, Stop/deadline, crash between commit and parent observation, and release of the actual latest revision. Added retained revisions/context/temporary state must fit existing aggregate caps. The exact safe progress boundary and phase/cleanup protocol are unresolved; this report is not an implementation-ready design.

If the owner retains the unreplenished-revision rule, preserve the failing gate and continue only a new source-backed ordinary repair. If the owner chooses a renewable restore contract, record that explicit change first and assess the small bounded transition/observer design before coding; do not describe it as mere performance optimization or claim it passes the old contract. Raising the initial TTL, extending operation/parent limits or weakening the worker's exact-original checks is not a fallback authorized here. An extra renewal API existing in the repository does not resolve this decision.

Additional source binding for the decision section:

```
5b35dd589f1e56d33a4313ff43b80457bf9643cd9a37d161314739111294b62e  apps/trader/continuous_process_lifecycle.py
8c5da5b73d0efc3aea31a253ab346041fcdfc05955c8652d7f95cded2c1ec6e6  packages/domain/account_coordinator.py
```
