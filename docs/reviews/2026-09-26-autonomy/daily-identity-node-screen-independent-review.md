# Independent feasibility review: stated daily per-node layout

2026-09-26. Owner approval covers feasibility only. Reviewed temporary layout, scalar screen, frozen report and mechanics; no production proof, factory wiring, graph acquisition or genuine fixture run.

**Reject this stated layout and stop it at the first resource gate.** The calculation follows the existing accounting convention and the actual validated source-owned measurement. It is not a rejection of every possible representation.

## Source-grounded lower bound

The original daily helper adds each exact non-scalar tuple and each other non-scalar identity to `seen` once, then takes dataclass-before-Mapping expansion or treats it as opaque. Exact scalar leaves skip `seen`. Its returned vector concatenates every expanded node's immediate children, in original traversal order. Aliases and cycles avoid a second expansion while repeated parent child edges remain in the vector.

The candidate explicitly chooses one logical NodeBinding for every such seen identity, including opaque leaves and exact tuples. Each node retains original object and original type. Expanded nodes additionally retain every original ordered child; accessors and further metadata add costs later. This is different from reusing the attempt fingerprint selector, which would omit daily fields and apply different precedence/leaf semantics.

The existing attempt helper's `retain` (`packages/persistence/_factory_attempt_fingerprint.py:287`) charges one container and `2 + len(accessors) + len(values)` bindings. Applied to this stated layout, the actual 9,356 seen identities and 54,690 returned child edges require at least:

- 9,356 containers.
- `2 × 9,356 + 54,690 = 73,402` bindings.

Combined with the simultaneous existing attempt proof's 7,387 containers/66,259 bindings, this is **16,743 containers/139,661 bindings**. The unchanged shared caps are 16,384/131,072: the lower bound exceeds them by **359 containers and 8,589 bindings**.

This already fails before raw-slot accessors, class/schema/Field inventories, native dispatch dependencies, owner/context/use/retirement state, records arrays, construction pending/seen buffers or temporaries. Omitting their numeric charges from this rejection is conservative; they cannot reduce the lower bound. Existing values do not become uncharged merely because their references predate the prototype.

Opaque per-node records implement the candidate's chosen stricter type/classification pin. They are not a universally necessary representation of the original predicate, which may accept some opaque-to-opaque type changes. No alternative packing, omitted records, cross-proof sharing or cap adjustment has been reviewed or implied.

## Evidence and mechanics

The screen's executable path binds the exact frozen measurement SHA, expected source/observer inventory and current file hashes, and requires validated complete original execution, zero test status, successful original public return, active simultaneous proof usage and consistent component/cap arithmetic. Main was not rerun into the existing exclusive report.

Independently ran the finite scalar selfchecks: **37 passed in 0.04s**. They cover authentic arithmetic, cap equality, one-over either dimension, malformed/negative/bool counts, provisional/failed/inactive/inconsistent observations, missing components and evidence immutability. No project modules or genuine ownership fixtures were imported.

Verified frozen hashes:

- Screen: `d4b32b71df304ffef99b3ac69e22373174e9b6dff212de8762dca455bc2e53c3`.
- Tests: `3a2d1fa1b2fc6dda38828f2b25f2a4f8e5b15d62097b9df6469cc8a9913ca3ee`.
- Layout: `53753c0f99ece7703690e0a685a199e929f27c51ad7340f5b5a7eeb694ad5cf0`.
- Actual original measurement: `99789c8f6417efaf0650d11c1d4233556f9674300002bc1d67442e3d931d6ee9`.

The frozen resource report agrees with all sums and explicitly records no admission, acceptance, new fixture, graph/authority construction or universal-impossibility claim. Its bounded scalar output contains no graph data.

## Appropriate stopping point

Full native-slot eligibility, schema/classification mutation handling, copied-owner lifecycle, fallback callback/error compatibility and timing were not implemented or proved. They cannot rescue this resource lower bound and should not be built merely to complete an infeasible candidate. Likewise no additional source-owned snapshot is needed to make this rejection.

Record the approved feasibility experiment's early rejection honestly. Preserve public/prepared/live/transactional behavior, all original fresh observations and the existing limits. A2 and failed Linux acceptance remain open. Any separately proposed representation or pre-lease design requires its own scope/accounting review; this result is not authority to pivot automatically.
