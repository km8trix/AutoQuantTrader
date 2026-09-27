# Owner decision: bounded pre-lease restoration study

**Decision requested: permit a limited offline design and feasibility study, not production implementation.** No implementation-ready handoff is established. The existing retained restore and Linux gates remain failing; this proposal neither accepts the current attempt proof nor revives the rejected daily per-node layout.

## Why this is a separate decision

The factory already decodes its three retained configuration objects before acquiring a lease (`continuous_simulation_factory.py:229–303`). It then constructs owners using the actual fence and performs full retained validation. Existing capture/resolve/recheck phases shorten database transactions, but do not carry qualified results across acquisition.

In particular, the schema snapshot includes lease/head/release rows. `continuous_integrity.py:1954` freshly recaptures and requires exact equality before creating committed-observation ownership. Acquisition changes lease/head rows. Treating pre-acquisition work as usable later therefore needs a new, explicit handoff contract; rescheduling the existing callback alone is invalid.

## Narrow boundary to investigate

One fixed offline HALTED account, with existing signed history and an existing durably inactive lease head. Prepare only bounded, provisional interpretations of fixed historical bytes/rows before acquisition. They carry **no fence receipt, daily snapshot ownership, successful validation or execution authority**. Keep every existing post-acquisition SQL/object/source/fence/control/entry/terminal/cleanup observation; perform a fresh coherent comparison before any prepared interpretation can be consumed. Only newly established original owners under the actual lease may issue qualified results. Never attach an old receipt or timestamp to a new fence, adopt newer financial state, or expose provisional values as a completed restore.

The study must select a finite concrete set of pure decoding/canonical work; it may not become a general cache or graph-attestation framework. Existing public/prepared/transactional APIs and all live/provider paths remain outside scope. Moving identity checks would need an independently specified predicate proof; it is not included automatically.

## Exact proposed acquisition delta

For this restricted inactive-head case, `SqlAccountCoordinator.acquire` (`account_coordinator.py:904`) inserts one revision-1 lease and updates the target account head. The proposed handoff could permit **only**:

- One new target-account lease row, exactly the immutable SQL representation of the actual lease returned by this operation's coordinator: generation `G + 1`, revision `1`, previous lease digest `None`, original actual owner/lease ID/policy/times/payload/digest. All previously captured lease rows remain identical; no other lease row is added.
- One existing target head changing from inactive generation `G` to that same acquired lease: `last_fencing_generation=G+1`, `current_fencing_generation=G+1`, current digest equal to that lease, and the acquisition's trusted timestamp as `updated_at`. Account identity remains unchanged. No new head/bootstrap is admitted.

No lease release, renewal, takeover, other account's head, control transition/completion/head, financial row, source row, journal row, object byte, schema or inventory change is permitted by this delta. Later ordinary same-lease observation timestamps must continue through the existing `inspect_committed_observations` mechanism; they are not a general timestamp exemption.

**Unresolved acquisition ownership:** equality to an expected final row is insufficient to prove that this operation caused the transition or that the exact prepared inactive head was the transaction's predecessor. The existing `acquire_if_inactive_generation` (`:959`) atomically restricts generation/inactivity but does not return an original-before/after owner witness for the full prior row. The study must establish a minimal original-coordinator-owned transition binding, including race/ABA handling, or reject. It may not silently ignore intermediate head changes or replace exact snapshot equality with broad lease-table exclusions.

## Contract and failure-order changes to assess

Malformed history, Stop or preparation-bound failures could occur before acquiring a lease where they previously occurred afterwards. Concurrent history/control/object changes would discard the provisional preparation and fail closed; no automatic retry, reseal, renewal or adoption of later state is proposed. Post-acquisition failure still requires the original cleanup. Preparation must not begin outside existing operation/parent budgets to conceal cost. Behavior/schema mutation between preparation and consumption must reject or use a specifically reviewed unsupported-profile path without executing changed hooks as trusted validation.

Other unresolved questions are the minimum useful pure-work subset, byte/row provenance and native behavior qualification, exact shared memory accounting for overlapping prepared/fresh states, and whether all preserved fresh checks leave useful net savings. These are feasibility questions, not accepted design details.

## Deliverable, adverse gates and stop rules

Return a source-bound design, finite resource/cost model and separately reviewed temporary offline prototype only if the earlier model survives. Test copied/foreign/reused/thread/reentrant preparation; mutation of rows, object bytes, schema/class/code/callbacks; control changes; another acquisition/release cycle; absent/active/expired heads; wrong lease/policy/generation; clock regression, expiry and Stop before/during/after acquisition; and primary-failure-preserving cleanup. Prove that every original fresh SQL/object/fence/final check remains and no qualified value escapes before handoff.

Preserve the retained fixture's **60-second lease and 120-second operation wall timer**, the **150-second parent bound where applicable**, and all original aggregate resource limits. Preserve the separate worker's configured wall/CPU/memory limits (the genesis worker defaults are 30 seconds/30 seconds/512 MiB). No timer relocation, lease renewal/extension, cap increase or resource exclusion is allowed. Measure total preparation-through-cleanup as well as lease-held work; a faster `execute` alone is not a benefit or Linux prediction.

Stop if exact acquisition ownership cannot be established narrowly, resources exceed unchanged caps, required fresh checks erase meaningful complete-cost savings, or the design requires broad authority changes. Rejection is a valid study outcome. No genuine heavy fixture or production patch should precede a reviewed concrete plan; production adoption requires a further owner decision and all original acceptance gates.

**Recommendation:** this limited study has a coherent source-backed question and is defensible if the owner wants further investigation. Do not approve implementation now, infer a speedup, weaken existing validation, or treat further exploration as mandatory.
