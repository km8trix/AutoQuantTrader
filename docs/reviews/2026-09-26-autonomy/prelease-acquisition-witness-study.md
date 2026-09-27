# A2.6: original acquisition witness study

2026-09-27. Read-only study under the owner's approval for bounded offline design/feasibility. No production edits, fixture runs, model code, database acquisition or new authority. Current proposal approval is supplied by the owner/task; the proposal's earlier “decision requested” heading does not grant production implementation.

**Finding:** the acquisition transition has a finite, source-backed shape that could be modeled independently. Existing code does not issue the necessary original witness, and a scalar model would not establish a usable production handoff. Do not start a new prototype on this study alone: the useful prepared-work subset, transitive behavior qualification, total simultaneous resources and net benefit remain unestablished. This is not a universal impossibility result.

## Established primitives and missing fact

`SqlAccountCoordinator.acquire_if_inactive_generation` (`account_coordinator.py:957`) supplies the closest precedent: an exact expected generation, `_state.lock`, no fenced effect in progress, trusted time, `_write_transaction`, a locked existing head, inactivity/generation/clock checks, one revision-1 lease insertion with exact SQL readback, and exact head update/readback. It returns only after `_write_transaction` has committed. SQLite uses `BEGIN IMMEDIATE`; PostgreSQL uses an actual transaction and the head's `FOR UPDATE` path (`:572`, `:655`). No bootstrap or expired-owner takeover is accepted by this conditional method.

The normal factory instead calls `acquire` (`continuous_simulation_factory.py:303`; coordinator `:899`). That method permits bootstrap and same-owner return, and calls `_observe` before insertion. Neither acquisition method returns the actual full locked predecessor together with the committed result. Reconstructing a tuple from the requested generation and a later matching head cannot supply that missing origin.

`_LeaseHead` contains five fields (`:250`); `immutable_account_lease_values` returns twelve SQL columns (`:80`). `_insert_lease` and `_set_head` already perform exact readbacks (`:831`, `:844`). `CommittedAccountObservations` and its private state demonstrate same-coordinator/thread/view identity, bounded state, failure latching and cleanup (`:449`, `:1188`). They are expressly same-lease observation ownership, not an acquisition witness or transferable execution permit. In particular, `revalidate` advances its expected row only after successful COMMIT (`:1256`).

## Finite hypothetical private contract

This is a design specification, not a proposed patch to ordinary acquisition APIs.

1. One exact coordinator/authority/engine/policy/clock/shared-state/thread and one original offline preparation/operation own a private acquisition scope. Pre-acquisition preparation remains unqualified. Missing/active/expired heads, bootstrap, renewal, takeover, concurrent/nested scope and foreign/copy claims are outside the restricted profile.
2. Under the existing serialization transaction, capture the **actual locked predecessor row** before any `_observe` or head mutation. Require exact equality to the preparation's original inactive head, including `updated_at`, not just generation. Original row/schema types and timezone handling must be explicit; a caller-created equal mapping cannot itself prove original capture ownership.
3. Perform only the existing ordinary inactive acquisition transition: one lease of generation `G+1`, revision 1, no previous revision; an exact returned/read-back lease row; and the target head pointing to that lease at the acquisition's actual trusted timestamp. Retain the original predecessor and result from this transaction, not from a later reconstruction. Existing public methods remain unchanged.
4. A preallocated private witness stays inert until COMMIT is confirmed. Afterward its sole role is to justify this acquisition delta during a fresh comparison; it is neither AccountFenceReceipt nor daily snapshot/source authority. It binds the exact actual lease and original owner/scope. Consumption is once, within that same thread/operation; failure or copied/foreign/retired use poisons the scope. A new original post-acquisition owner must independently issue any qualified data.
5. Retirement releases every added preparation/row/owner reference on success or failure. The witness may be retired after the initial handoff only if no later consumer relies on it; prepared data lifetime/resource/behavior proofs remain a separate unsolved obligation.

The transition is finite, but full predecessor capture/ownership and scoped witness issuance are new private behavior. No current API may be described as already implementing it.

## Commit and ABA gates

The first hard gate is the interval between a successful database COMMIT and witness activation/return. A new metadata allocation, callback, exception or interruption must not strand an acquired lease before the factory has original cleanup ownership. An inert preallocated scope is a plausible mechanism, but **the concrete protocol is not established**. It must preserve the original lease for cleanup on confirmed commit, expose no usable witness after body/commit rollback, and fail closed on uncertain COMMIT outcome. It must not retry acquisition or guess commit success from matching final scalar rows. `_rollback_failed_write` (`:526`) is an existing rollback/connection-invalidation precedent, not evidence that all post-commit delivery cases are solved.

Legal acquire/release ABA increments generation and appends immutable lease/release history. An exact locked predecessor and fresh complete dependency inventory reject it even if the account is inactive again. Wrong-owner acquisition, same-generation unexpected head timestamp changes, renewal, another account's changes and duplicate/new lease rows must also reject. A hostile external writer that restores every historical byte cannot be detected from equal endpoint snapshots alone; do not claim stronger ABA detection than the repository's locked transitions and retained-history assumptions support.

## Fresh snapshot equivalence remains strict

The provisional snapshot is never fed to `validate_snapshot` as if it were post-acquisition. `database.py:179` includes all lease/head/release and control tables; `continuous_integrity.py:1954` freshly captures under the actual fence and requires exact equality to its own supplied current snapshot. These public checks stay intact.

A separate hypothetical handoff comparison could allow only one original-witness lease-row addition and one exact target-head replacement. Every old lease/release row, other account row, control row, financial/source/journal row, schema/inventory and referenced object byte remains equal. Later owned `updated_at` movement continues solely through the existing same-lease committed-observation mechanism. Never exempt an entire table or rebase an old receipt, timestamp or fence. `daily_runtime_risk.py:1495` still issues its raw snapshot only from its own fresh fenced capture; `_resolved`/public identity guards remain unchanged.

Preserving these fresh checks does not yet show that any useful decoded value can be reused safely. The original constructors, schema discovery, mutable classes/defaults/globals/native behavior and transitive source callbacks used by that value still need a finite qualified profile. Acquisition provenance alone proves none of them. A new broad behavior-attestation framework is outside scope.

## Explicit small model accounting and its limit

An isolated **scalar counterexample model** can be specified without source imports, SQL, live owners or authority. Its identifiers are inert labels; it can test row-delta equations, legal phases and rejection logic, not actual locking, COMMIT origin or cleanup. No such model was implemented here.

One explicit illustrative layout, using the existing logical `1 container; 2 object/type bindings + child bindings` convention, is:

| Model record | Count | Child bindings |
| --- | ---: | ---: |
| Before head, after head, canonical acquired-lease row | 3 | 5 + 5 + 12 = 22 |
| Actual lease field snapshot, including contract-version field | 1 | 11 |
| Scope state | 1 | 18 |
| Original immutable scope-identity snapshot | 1 | 15 |
| Opaque witness token | 1 | 0 |
| Fixed record inventory | 1 | 7 |

Scope's 15 fixed bindings are coordinator, authority, engine, policy, clock, shared state, thread, preparation, operation, token, actual lease, before row, after row, lease row and cleanup holder. Its other three slots are phase, failed and consumed. The model uses preallocated mutable phase state; there is no uncharged sequence of old/new frozen scope replacements.

This is **8 logical containers and 89 internal bindings**, plus one owning scope-slot edge: **90 bindings**. Allowing three simultaneous temporary row dictionaries of sizes 5/5/12 adds three containers and `2×22 + 2×3 = 50` bindings: the stated model peak is **11 containers/140 bindings**. Those temporary rows must be discarded before later fresh comparison; otherwise their overlap must be added. The 22 row values are references/scalars, not a claim that strings/payloads occupy zero bytes. Any new retained or copied bytes remain subject to the original byte/memory limits.

This inventory is deliberately **not** a complete real-witness fit calculation. Native access/schema/behavior records, actual registry/weakref/closure mechanics, transaction-driver storage, fresh comparison buffers and—most significantly—the prepared/fresh historical graphs are not modeled and are not presumed free. Nor does small witness metadata imply that a third prepared graph fits beside existing captures/proofs. There is no extra resource allowance or automatic reuse/deduplication credit. Thus this small model is arithmetically finite but does not clear the proposal's full resource or cost gate for a new prototype.

## Adverse gates and disposition

Before any implementation-oriented experiment, require a specific useful pure-work subset and complete phase/lifetime accounting. Witness-focused gates include: exact predecessor mismatch; legal acquire/release ABA; absent/active/expired/foreign heads; wrong policy/lease/generation/result row; same-value copied owner/witness; thread/reentry/reuse; clock or method replacement; insertion/head readback failure; body rollback; deferred COMMIT failure; post-COMMIT/pre-return interruption; failed cleanup with the original failure preserved; no surviving graph after retirement; and unchanged fresh SQL/object/fence/final observations. Existing conditional-acquisition tests validate their existing API, not this new scope.

Keep the retained 60-second lease/120-second operation timer, applicable 150-second parent bound, and each worker's actual wall/CPU/memory limits. No renewal, timer relocation, cap growth, raw-head exception or authority broadening follows from this study. A complete cost model must charge added pre-capture, preparation, acquisition witness, fresh comparison, failure and retirement, not merely reduced lease-held time.

**Recommendation:** preserve this finite contract analysis, but do not code the witness/model yet. The source supports a narrow question, not a usable production handoff or demonstrated benefit. Proceed only if the overall prepared-work/behavior/resource model survives; otherwise reject this candidate without claiming all pre-lease designs impossible.

## Source identity

SHA256 values at review:

```text
packages/persistence/account_coordinator.py 5f3cc0b043e3ea58344eb9d8757daf76a95f11fc6088e4b744cfe3b483fa8a86
packages/domain/account_coordinator.py 8c5da5b73d0efc3aea31a253ab346041fcdfc05955c8652d7f95cded2c1ec6e6
packages/persistence/schema.py 500f00534db3af78351e7ae8b9156d2f4b587f72cd3621c9b0df48501c7732f5
packages/persistence/database.py 846fd7019ce65ca13dabf00132fb94d7dec003e3f0ae8be778dd342d4ddd26a0
packages/persistence/continuous_integrity.py 0713cc6c55b35a7cd93eb89cb92cc4639ad9ba249c4d0f4389390ebeff78023d
packages/persistence/daily_runtime_risk.py cfae83fee7d05ff79dbc3a8e47036870c88d9785247171ba0bcbb4e30f6fee24
packages/persistence/continuous_composition.py 52b89e1a6717783bdfb31d84b77e033c517b9a1fd9b12623da4e407f19dad106
apps/trader/continuous_simulation_factory.py d60324477620f85866eba36a001751101f0c027e44f50ec2aa6206f1e3f56a26
packages/application/continuous_process.py 0f4f9b925c14d14f4535086d9a05ad8d0d3e9a7b088bde5c712d53f1a57c6517
tests/integration/test_continuous_simulation_factory_outcome.py cd7546f114cffaef3de76f77fbcb9635a09c35a48229b7a9beede4372f0bb75e
docs/reviews/2026-09-26-autonomy/prelease-restoration-decision-proposal.md d6a0abbd1b74895b1369f096ac09cd0bbd3768d7e9fa7db1d8c3b640c9b5bfa1
```
