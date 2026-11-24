# Factory attempt fingerprint pilot: prototype assessment

This is an unconnected, optimistic data-cost prototype. The user approved bounded
offline investigation; approval does not establish safety, usefulness or acceptance.
`continuous_runtime_attempt_sources.py` and `continuous_integrity.py` remain
unchanged. No source/factory proof is issued, no fingerprint is skipped, and no
SQL, external observation, fence or owner check is removed.

## Current prototype

`packages/persistence/_factory_attempt_fingerprint.py` attempts to admit a narrow
exact-data graph, retains raw identity bindings, and rechecks them. Its intended
roots and selectors match the resolved branch of the original `_fingerprint`:
`value.sources`; the nine explicitly projected fields of each captured `_Source`;
each provenance snapshot's original Table/name, account ID and rows; and resolved
dispatches. It does not traverse unrelated source-owner or SQL table internals.

The implemented profile includes exact scalars/tuples, exact finite Decimal,
exact date and UTC datetime, known original slotted domain/persistence records,
exact dictionaries with string/quoted-name keys, original enum members, and exact
mapping proxies with one exact-dict CPython referent. Mapping-proxy introspection
is a new CPython 3.12 assumption, not row provenance. Lists, unsupported classes,
custom metaclasses, unslotted records, effectful proxy backing and cycles fall
back before a seal is returned. SQL Table/name is restricted to explicit original
table instances through a dedicated selector; no full SQL metadata proof is made.

Bindings include original object types; record schema inventory, Field.name and
Field._field_type; class module/qualified-name/MRO and defining module export;
original member descriptors; enum state and property getter/code bindings;
container contents/order; and reflected runtime dependencies. Member reads use
original C slot descriptors, so a newly substituted property is not executed.
Class descriptor inventories are charged once; object edges still each count.
Dictionary length is checked before materializing its current contents. Admission
and rechecks pin the ABC token and integer conversion limit for that seal.

The helper remains incomplete. It is not safe to connect it as an authority or
claim equivalence to the complete fingerprint.

## Validation and economics status

The architecture check and scoped Ruff check passed on the current helper.
The focused pure suite contains 39 cases. Its first execution reported 39 passed
plus one test-fixture teardown error caused by restoring class `__qualname__` via
pytest's delete operation. The test owner corrected restoration with explicit
`try/finally`; the final rerun passed all 39 in 0.69 s. Evidence is
`/private/tmp/aqt-autonomy-audit/factory-proof-pure-corrected.txt`; command was
sanitized `python -B -m pytest -q --tb=short
tests/unit/test_continuous_attempt_fingerprint_proof.py`. Pure tests confer no
source/factory authority and do not prove complete dependency coverage.

The original retained fixture passed its instrumented run with a roughly 47.15 s
restore. The diagnostic itself is invalid for whole-operation attribution because
it reached its 30-call cap. Its first 30 calls were resolved fingerprints and
reported about 1.139 s inclusive total. This is neither a full fingerprint cost
measurement nor an uninstrumented performance acceptance result.

The authentic pending-source pure-data measurement completed with unchanged source
hashes: 2,030 charged containers and 20,500 bindings fit the existing fixed caps.
Median original fingerprint was 6.609 ms, raw recheck 2.195 ms, issue/drop 11.109 ms,
and issue/check/drop 13.737 ms. Three alternating rounds of three invocations each
produced model ratios for issue/drop plus N checks versus N original fingerprints:
N=3: 0.8923; N=6: 0.6122; N=12: 0.4721; N=30: 0.3881. This is a promising lower
bound, not sufficient adoption evidence. Its full report is
`/private/tmp/aqt-autonomy-audit/pending-proof-economics-first/economics.json`.

The measurement excludes full behavior-dependency authentication, original source
checks, root context/one-use permit machinery and additional full issuance
verification. Its fixture is genuinely source-owned synthetic pending data, not
qualified signed factory history. No retained-startup improvement may be inferred.
A separately scoped actual retained-graph budget/economics diagnostic is next;
the helper remains frozen during that measurement.

## Outstanding proof gaps

1. Initial Mapping classification is not established. A known slotted dataclass
   virtually registered as Mapping before admission can follow a different
   original converter branch while keeping the later ABC token unchanged.
   The prototype must reject this profile without invoking unsupported hooks.
   The original `__class__` descriptor path also needs to be pinned/rejected.
2. The prototype does not authenticate the full finite dependency graph of
   `detached_journal_value`, the canonical encoder/JSON path, dataclass reflection,
   Mapping classification, integer/string conversion configuration, and source
   `_fingerprint`. Function identity alone is insufficient: in-place code,
   defaults, keyword-defaults, closures and consumed global rebinding matter.
3. Root and source original method/dependency baselines, exact owner registry,
   copied/foreign owner rejection and code-in-place changes are not connected.
   A proposed one-time root-module completion registration avoids treating an
   arbitrary first-use snapshot as original code; it has not been implemented or
   reviewed as working authentication.
4. No original-factory context, entering/HALTED restriction, original thread,
   episode or borrow identity, one-use permit, reentrancy denial or failed-use
   poisoning is implemented. Public/ordinary `require_resolved` stays unchanged.
5. Retirement, cancellation, cleanup and restart/replay denial are unimplemented.
   The proposed proof must retire before `_FactoryResult`/`_factory_structure`
   construction so it does not overlap the existing original handoff inventory.
6. The helper charges each retained data/schema record and accessor/value/owner
   edge within 16,384 containers / 131,072 bindings in the authentic benchmark.
   Whole-operation charging is still incomplete: original behavior inventories,
   source proof/context/permit references and other simultaneous lifetime costs
   must be added without any new allowance. The current usage is a lower bound.
7. Authentic nonempty source data is insufficient to qualify the factory path.
   Cheap pending-source fixtures cover actual source ownership and data shape;
   the existing signed retained-outcome original factory gate must prove actual
   path reachability and unchanged external/SQL/fence observations if adopted.

## Required boundary if investigation continues

Only the final resolved attempt fingerprint comparison may use a private proof
inside the three authenticated checks of `_borrow_original_daily`. Every original
preceding source/reference/descriptor/outcome guard must remain in order, as must
all original full entry/final factory verification, actual SQL/artifact/clock/fence
observations and current immutable receipts. Unsupported initial profiles use the
original path. Mutation after issuance fails/poisons rather than resealing or
falling back to rescue the operation. Existing time/resource bounds remain fixed.

Do not develop the missing dependency/lifecycle framework until data-only economics
justify it. If this optimistic lower bound is already unfavorable, archive the
prototype and pure tests as rejected evidence and leave production source unchanged.

Independent finite review of helper SHA-256
`558c12db81c59b11788f642676fab3d836644531caa2a158190b776546508382`
confirmed rejection without custom-metaclass callbacks, unslotted and inherited-dict
schema shadows, compatible slotted `__class__` replacement, and Enum.value.fget
replacement. The reviewer also verified root bounds precede pending allocation and
dictionary lengths precede materialization. The listed open gaps remain open.
