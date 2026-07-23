# ADR 0034: versioned feature artifacts and differential parity

- Status: Accepted
- Date: 2026-07-21

## Context

Phase 2 can replay an immutable manifest through availability-time-ordered,
watermark-complete market batches and retain causal strategy evidence. Phase 3
needs feature computation to preserve those guarantees before broader research,
captured-tape, and shadow workflows can rely on it. A feature value without an
exact input manifest, temporal policy, and implementation contract is not
reproducible evidence. Likewise, merely having batch and incremental code paths
does not prove that research and event-driven execution observe the same state.

The first slice should be deliberately small enough to prove these contracts
without also introducing a general feature graph, fitted models, persistence,
or a new execution path.

## Decision

1. Define one bounded Phase 3A reference feature, `rolling_close_mean`. It
   consumes raw point-in-time close observations from one exact replay manifest
   and has a fixed observation lookback of two. It is research evidence only;
   its values cannot become order or fill prices or grant risk, broker, paper,
   or live authority.
2. Represent the feature definition as an immutable, versioned artifact. The
   artifact binds the content-addressed dataset manifest, authenticated source
   tape, sealed replay-run manifest and plan, exact replay transcript, feature
   name and version, input field and semantics, `lookback=2`, publication lag,
   gap policy, and implementation/contract digest. Reusing an artifact identity
   with different facts is invalid. This first artifact has no fitted training
   state; future fitted artifacts must bind that state and training window
   explicitly rather than silently extending this contract.
3. Publish only causal feature snapshots. A snapshot binds the feature artifact,
   replay manifest, complete market batch, ordered source observations, value,
   observation time, and availability time. Its value uses only observations
   admitted by the manifest-bound replay prefix. Publication lag is part of the
   artifact and advances the snapshot's explicit `available_at`. This slice does
   not yet connect snapshots to a decision consumer; that later boundary must
   reject a snapshot until its recorded availability has elapsed.
4. Use the explicit gap policy `SKIP_AND_RESET`. An incomplete or skipped market
   batch emits no feature snapshot and clears the rolling history for every
   expected instrument in that batch. The next snapshot requires two new
   complete observations.
   The implementation does not impute a value, carry a pre-gap value forward,
   or form a window across the gap.
5. Implement both a batch reducer and an incremental reducer over the same exact
   manifest-bound tape. The batch path indexes adjacent batches from the full
   immutable sequence and selects windows through per-batch event maps. The
   incremental path authenticates each exact next lineage digest and retains
   its own per-instrument observation state. They share the proof-constructed
   snapshot value contract, but not window traversal or selection. Both emit
   snapshots in the same canonical order and under the same availability, lag,
   and gap rules.
6. Proof-construct an exact parity receipt only when the two canonical snapshot
   sequences are equal. The receipt binds the feature artifact and replay
   manifest, both result digests, the ordered snapshot identities, and the
   snapshot count. A value, timestamp, lineage, ordering, reset, or identity
   mismatch fails closed and produces no successful receipt. Numerical
   tolerance is not part of this decimal reference feature's parity rule. The
   exact mean remains a canonical Decimal even when it requires more than the
   normalized input storage scale; no SQL transport constraint is applied to an
   in-memory feature value.
7. Keep Phase 3A pure and in memory. It consumes the existing causal replay and
   complete-batch contracts and introduces no SQL schema or repository, API or
   CLI route, browser surface, job/worker lifecycle, provider capture, live
   adapter, shadow deployment, arbitrary feature execution, or promotion path.
   Those capabilities remain separate later Phase 3 slices with their own
   evidence and gates.

## Consequences

The repository has a narrow reference contract for proving that full-sequence
batch traversal and incremental event replay derive the same causal feature
evidence. Manifest lineage, two-observation warm-up, publication lag, and gap
resets are part of identity rather than caller convention, and an exact receipt
can be retained as differential-test evidence.

This decision does not complete Phase 3. It does not persist feature artifacts
or snapshots, expose them to a user, ingest a live or licensed tape, run shadow
signals, govern experiments or holdouts, support fitted features, or establish
batch/incremental parity for targets. Those requirements and the Phase 3 exit
gate remain open.
