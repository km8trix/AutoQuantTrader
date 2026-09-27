# Daily identity feasibility: established per-node layout and first resource gate

2026-09-26. The owner approved the separate **feasibility experiment only**. No production substitution, new authority, runtime access or acceptance follows.

## Concrete candidate layout

Use the existing attempt data helper's logical accounting convention, but the daily predicate's complete traversal: each retained record is one container; each retained original owner/object, type, accessor and expected child is one binding. The attempt helper's `retain` charges `1` container and `2 + len(accessors) + len(values)` bindings per record. Shared preexisting values are still charged as retained edges. There is no reuse of its selected fingerprint projection or cross-proof deduplication.

The candidate has one `NodeBinding = (tag, original_object, original_type, raw_accessors, before_values)` for every distinct non-scalar identity visited by the literal daily builder. This follows the original exact tuple branch, then exact scalar skip, then identity-based `seen`, then dataclass-before-Mapping precedence. All dataclass fields—including private seals, owners and original-value fields—participate. Every edge remains ordered as the original LIFO traversal emits it; aliases/cycles receive one node record but do not remove repeated edges in a parent's children. Opaque leaves receive a record with empty child values to pin the chosen restricted profile's object/type/classification. Exact scalar leaves receive no node record but remain charged in parent edges.

Per-node rows:

| Original branch | Retained data record | Lower-bound charge |
| --- | --- | --- |
| Exact tuple | Original tuple/type and complete ordered item identities; even an existing immutable tuple's retained children remain charged | 1 container; 2 + item count bindings |
| Dataclass instance | Original object/type; original native slot accessors; complete `fields()`-ordered values | 1 container; 2 + field count values + field count accessors |
| Mapping | Original object/type and complete iteration-ordered key/value identities, with qualified dict/proxy access | 1 container; 2 + twice entry count bindings, before extra backing/accessor charge |
| Opaque non-dataclass/non-mapping | Original object/type, no semantic child traversal | 1 container; 2 bindings, before classification metadata |

The complete design would also need separately charged class/schema/Field-name/field-kind/native-descriptor inventories, qualified dataclass/Mapping classification and dependencies, original store/seal/saved-vector/episode/operation/thread ownership, contexts, use/retirement records, and all overlapping construction records/pending/seen/work buffers. A proxy's backing link and any additional raw structural record add charges; they cannot replace its original daily edges. Those costs are not yet implemented or counted as zero. They are nonnegative additions after the lower bound below.

This is the **established per-node layout**, not the cheapest conceivable representation. In particular, an inline-per-parent, packed or opaque-specialized alternative is a different untested representation. Some opaque type changes can remain opaque under the original predicate; this candidate's stricter qualified type pin is explicit, not a universally required original invariant. No alternative is automatically impossible or an authorized accounting escape.

## Genuine source acquisition and reuse of existing evidence

The already reviewed original-only measurement obtained its scalar input from the first actual return of the unchanged builder inside the source-owned, registered HALTED factory episode. It read the existing local `seen` size and returned identity vector, and held the summary provisional until that exact public daily validator returned. All 24 borrows and 144 selected daily calls completed, and the original retained-outcome test passed. The selected current snapshot/store/reader/thread/call-site attribution was independently reviewed.

For this candidate only, the literal helper gives an exact mapping from its `seen` inventory to node records: each exact non-scalar tuple and every other non-scalar dataclass/mapping/opaque identity is added once, before its expansion/opaque branch. Scalars are skipped before `seen`; aliases and cycles cannot add another record. Thus `seen_size` becomes a justified node-container lower bound **after choosing this representation**, rather than being automatically equated to proof usage.

The returned vector length equals the sum of the original expanded nodes' child-edge counts. Because this design retains each complete ordered child block, that length is also a binding lower bound, in addition to two object/type bindings for each node. It contains no accessor/schema/context or temporary-state charges and does not include extra proxy backing edges.

No new genuine snapshot acquisition or fixture is needed to reject this layout. The scalar screen verifies the frozen original measurement, original successful public-return qualification, expected existing proof component sums and caps, and unchanged source/observer hashes. It does not reconstruct owners, fabricate graph inputs, grant admission, install a proof or invoke validation. A surviving scalar screen would mean only “not rejected by this lower bound”; further admission/cost work would still need review before any actual snapshot use.

## First strict screen

Authentic measurement SHA256: `99789c8f6417efaf0650d11c1d4233556f9674300002bc1d67442e3d931d6ee9`.

- Original shared cap: 16,384 containers / 131,072 bindings.
- Existing simultaneous attempt proof: 7,387 containers / 66,259 bindings.
- Remaining: 8,997 containers / 64,813 bindings.
- Measured visited non-scalar identities: 9,356.
- Measured complete ordered child edges: 54,690.
- Candidate node-only lower bound: **9,356 containers / (2 × 9,356 + 54,690) = 73,402 bindings**.
- Joint lower bound: **16,743 containers / 139,661 bindings**, already **359 containers and 8,589 bindings over cap**.

Every omitted data-accessor, class/schema/behavior/context/construction charge can only increase those totals. This rejects the stated layout before graph-admission, transitive behavior, timing or another retained fixture. Unknown histogram categories need no reinterpretation for this lower-bound rejection; no unobserved type distribution is inferred.

## Deliverable and stop

`daily_identity_node_screen.py` is a temporary scalar-only feasibility prototype, with fixed input hashes and bounded JSON reads/output. `test_daily_identity_node_screen.py` supplies finite mechanics for cap equality/overflow, malformed/negative/bool counts, nonvalidated/partial observations and inconsistent budget sums. It imports no project code and uses no graph/owner fixture. The report records exact source/probe hashes and cannot label a fitting lower bound as admission or acceptance.

If this strict screen confirms the arithmetic, record **rejected for this per-node layout** and stop this candidate. Do not silently omit tuple/opaque records, invent packing/deduplication, increase caps, run full behavior or timing work, or repeat the genuine fixture to seek a smaller graph. The failed Linux acceptance and separate worker issue remain open. Any different layout needs its own concrete rationale/accounting review; this rejection does not prove a universal impossibility.
