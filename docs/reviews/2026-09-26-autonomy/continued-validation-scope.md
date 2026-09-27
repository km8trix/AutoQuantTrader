# Continued A2 validation scope

2026-09-27. Read-only review based on clean commit `071dd5c5624b35bef114275d4431823c9c82edeb` in `/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development`. No repository edits, tests, prototypes, benchmarks, fixtures or services were run by this reviewer. The single requested CI inspection is separately preserved in `ci-071dd5c-initial.json`; no monitor was started.

## Current acceptance and intended scope

PR56 remains open at exactly071dd5c. Run36297439151 is incomplete: foundations/browser succeeded; financial0–3 were active and4–15 queued at the bounded job read. Its completed foundations checkout proves generated merge9c9948ab0d0a5e4f448c8a882e4f20e369f77d2d; parents are b1156ba and071dd5c, and both candidate/merge trees are25304ef8e284092cf7e685ff5ce46e3769188be6. The compact record has SHA2569c98497e535f24c33af7005dc203ed3fd35fefcb53cf8f670c624a812e4fd4ba. This current incomplete run does not replace the preserved4965pass/2fail/0skip completed55951fb matrix or its expired-lease cleanup failures.

A narrowly local construction/dispatch change is ordinary reversible engineering if it preserves supported behavior, all fresh observations and all safety limits. It does not inherit permission for a new proof/cache/pre-lease authority, altered acquisition semantics, fewer validations, a larger resource pool or a longer lease. Reject an immaterial micro-optimization before another expensive fixture. A material finite helper benchmark is a screen, not retained or Linux acceptance.

## Environment and command sequence

Use the verified runtime directly; do not run `uv run`/`make check` merely to launch focused tests because dependency synchronization may occur. Never source `.env`, inspect credentials/private captures, activate native services, launch apps/providers or use an ambient database. Python support remains3.12–3.13; the existing optimized proof profile's narrower CPython3.12.13 qualification does not permit silently narrowing general pure-helper support.

From the active checkout, run architecture before project imports, then the smallest applicable test family. These commands are proposed, not executed in this review:

```sh
AQT_PYTHON=/Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python
AQT_PYBIN=/Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin
env -i PATH="$AQT_PYBIN:/usr/bin:/bin" "$AQT_PYTHON" -I -B scripts/check_personal_architecture.py

aqt_test() {
  env -i PATH="$AQT_PYBIN:/usr/bin:/bin" PYTHONPATH="$PWD" \
    PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC \
    "$AQT_PYTHON" -B -m pytest -q -p no:cacheprovider \
    --basetemp "$(mktemp -d /private/tmp/aqt-focused.XXXXXX)" "$@"
}
```

Each call owns a fresh fixture directory. Preserve failure output/source hashes separately; do not erase a failed record with a later pass. Do not invent a test count from source enumeration or old runs.

After a meaningful implementation, format/lint the changed paths and run the full type boundary plus architecture. Before the original retained gate, freeze candidate/source/test hashes and coordinate all expensive work through root:

```sh
env -i PATH="$AQT_PYBIN:/usr/bin:/bin" "$AQT_PYTHON" -m ruff format --check <changed-paths>
env -i PATH="$AQT_PYBIN:/usr/bin:/bin" "$AQT_PYTHON" -m ruff check <changed-paths>
env -i PATH="$AQT_PYBIN:/usr/bin:/bin" "$AQT_PYTHON" -m mypy apps packages
git diff --check
```

Angle-bracket path placeholders must be replaced with explicit owned files. At final integration use the maintained full static/API gates from TESTING and all16 required CI shards. A PostgreSQL skip is missing concurrency evidence, not acceptance. An explicitly disposable PostgreSQL endpoint is required for `--aqt-test-postgres-url "$AQT_DISPOSABLE_TEST_DB"`; never infer one from current environment. No PostgreSQL service was checked/created here.

## Focused families by changed seam

### Pure canonical/semantic/codec construction

Existing independent literal oracles and fixed byte/hash goldens must remain independent of candidate helpers. The actual source paths exist:

```sh
aqt_test tests/unit/test_canonical.py \
  tests/unit/test_personal_contract_semantics.py \
  tests/unit/test_personal_semantic_dispatch.py \
  tests/unit/test_personal_semantic_stopiteration.py \
  tests/unit/test_personal_canonical_tuple_dispatch.py \
  tests/unit/test_personal_canonical_deferred_dispatch.py \
  tests/unit/test_personal_canonical_fragment_join.py \
  tests/unit/test_personal_codec.py \
  tests/unit/test_personal_codec_primitive_dispatch.py
```

Required observations include exact leaf/output identities and fresh nested tuple allocations, aliases visited as before, mutation between calls, first failing field and two field-name reads, prefix/reflection order, Enum/subclass/metaclass behavior, dynamic encoder lookup, deferred serialization, Decimal context, malformed constructor/type/schema/canonicality rejection, and failure chains/lifetimes while traceback references remain alive. No claim of exact resource-exhaustion threshold equivalence beyond established contracts is needed; ordinary finite supported failures must remain equivalent.

These suites are collateral evidence for a daily identity-builder change: they do **not** directly compare `SqlDailyRuntimeRisk._assignment_identity_fields` to its literal previous implementation. Add a small dedicated literal oracle only if that exact candidate survives source/economics screening; do not claim existing canonical tests already cover it.

### Durable journal SQL-expression construction

Start with the actual journal unit family, then affected coherent capture/integrity integrations:

```sh
aqt_test tests/unit/test_durable_journal.py
# Next only if relevant to the selected SQL seam:
aqt_test tests/integration/test_continuous_integrity_capture.py \
  tests/integration/test_continuous_integrity.py
# Disposable PostgreSQL only; no endpoint is authorized or assumed here:
aqt_test --aqt-test-postgres-url "$AQT_DISPOSABLE_TEST_DB" \
  tests/integration/test_durable_journal_postgres.py
```

Existing substantive cases cover exact retry after later append; stale writers/exactly-one winner; late-conflict and outer rollback; unknown rowcount without repeated insert; typed/canonical validation before the transaction; no codec during writes; detached stalled decode while a writer commits; changed current rows and corrupt chain/head/cursor;256-record page and aggregate byte limits; SQLite storage-class corruption and transfer-bounded text/blob/integer metadata; exact original prepared-readback identity and weak cleanup. Coherent integrity tests bind declared tables/dependencies and shared aggregate limits, late control changes, referenced object limits and original fence expiry.

A new expression-construction candidate also needs a literal original SQL/execution oracle for its exact seam: PostgreSQL and SQLite compiled shape/current bind values/limit/order predicates; actual SQLite transferred values and pre-transfer bounds; empty/missing/changed rows; malformed table/column/type/length/nullable/quoted-name metadata; custom SQLAlchemy types/comparators/compilers; and statement mutation via connection events. No constructed statement or metadata field may be reused across a boundary that currently rereads it unless its behavior remains established. Compiling PostgreSQL SQL is not actual PostgreSQL execution/concurrency evidence.

### Daily identity-builder and runtime-row expression seams

Use exact identity-vector comparisons and hook traces first, not canonical bytes alone. For a local loop dispatch change retain the original LIFO pending stack, seen semantics, child order, generator expressions and alias/reference multiplicity. Relevant existing integration nodes include:

```sh
aqt_test \
  tests/integration/test_sql_daily_runtime_risk.py::test_altered_prepared_object_is_never_admitted \
  tests/integration/test_sql_daily_runtime_risk.py::test_replaced_raw_and_resolved_snapshots_cannot_reuse_preparation_ownership \
  tests/integration/test_sql_daily_runtime_risk.py::test_prepared_source_bytes_cannot_change_even_if_digest_metadata_is_unchanged
```

For a `_capture_runtime_rows`/`_expressions` change, the same file also has `test_invalid_or_oversized_source_storage_is_rejected_before_payload_transfer`, `test_aggregate_metadata_bound_precedes_transfer_even_for_valid_declared_columns`, `test_shared_budget_enforces_total_rows_across_individually_bounded_tables`, and `test_public_historical_capture_and_rechecks_never_decode_under_transaction`. Apply only the corresponding nodes initially.

If actual factory consumption is affected, `test_continuous_integrity_daily_episode.py` covers original descendant mutation, copies/foreign consumers/thread/reentry, primary failure plus cleanup, fresh object/row/fence changes on later borrow, original shared object pool, final coherent SQL/clock ordering and failure latching. It is a broader integration family, not the first microbenchmark. The seven genuine proof cases and original retained/fixed-worker fixtures remain coordinated expensive gates; do not run them merely to judge a few scalar lookups.

## Specific proposed type/id screen: source-only disposition

The original identity builder at `daily_runtime_risk.py:992` calls `type(item)` for the exact-tuple branch, then again before the scalar identity chain; for each newly seen non-scalar it also calls `id(item)` before membership and again for `seen.add`.

**Reject reusing the id result under ordinary behavior preservation.** `id()` raises a documented native `builtins.id` audit event on each call. Removing the second call removes a supported event at which an installed audit hook can observe, mutate or raise; module monkeypatching is unnecessary. Root subsequently reproduced this in an isolatedCPython3.12.13 process: the original emits two root-id events and propagates `AuditDenial` from the second; the temporary cached-id candidate emits one event and returns. I read the exact script/result but did not rerun them. Evidence: `identity-id-audit-rejection.py` and `.json` in the temporary audit directory. This is a demonstrated supported-hook/error mismatch, not a performance hypothesis. Official reference: [Python3.12 id](https://docs.python.org/3.12/library/functions.html#id). Keep both original calls and their positions.

**Type-only reuse can be screened narrowly, with a lifetime caveat.** Simply moving `item_type = type(item)` above the tuple branch overwrites the previous loop's `item_type` on every exact-tuple visit, whereas the original retains it through tuple processing and its native id audit events. Most ordinary instances retain their own class, but a getter can change a previously visited heap instance's `__class__`; then the old type reference can matter to class collection/finalization observed by a later audit hook's explicit collection. This is a reasoned adverse case to investigate, not an experimentally reproduced failure.

A more conservative temporary candidate uses a separate current-type local, deletes it before the original tuple path, and assigns/deletes it at the original `item_type` point on the non-tuple path. This preserves the prior `item_type` through tuple visits, keeps both original id calls and leaves all scalar aliases/identity comparisons in their original chain. Added stores/deletes may erase the benefit; a finite synthetic comparison can reject it without any fixture. Do not hoist/cache a tuple/set of scalar classes: imported Decimal/datetime/date or scalar aliases may be rebound by an earlier getter, and equality-based membership can add metaclass hooks absent from the original `is` chain.

For a candidate surviving that screen, the dedicated oracle should cover exact scalar and tuple leaves, nested dataclasses/mappings, arbitrary alias/cycle graphs, equal distinct objects, dynamic scalar-alias changes at existing callbacks, field/mapping iterator failures and StopIteration subclass cause/context, preserved fields()/getattr order, original audit-event multiplicity and rejection points, and temporary record/class/field-metadata lifetimes. An isolated child process is the appropriate future mechanism for audit-hook tests because installed audit hooks are not generally removable; this review did not start one. Arbitrary frame-introspection/global-code sabotage is not silently promoted into a broader generic proof requirement.

## Prior rejected-test pitfalls to preserve

- Semantic scalar loops looked correct on normal bytes but changed PEP479 StopIteration wrapping and retained partial outputs/temporary records via traceback locals. The current literal generator restoration and49 adverse cases are durable evidence. A manual catch is not an equivalent repair. A prior `item`/`item_type` lifetime bug also delayed a getter-created record's finalizer until after the next getter.
- Daily generator-to-list attempts reproduced changed StopIteration behavior and finalizer timing. Keeping the generator while changing the outer allocation was then measured about1% slower on bounded shapes. Those failures cannot be removed as inconvenient tests.
- Canonical fragment batching can retain the first dynamic encoder result across the next call or failure and alter rebound-encoder lookup/error order. Preserve completed conversion before fallback serialization. Captured canonical bytes do not reconstruct original aliases/classes/hooks; partial shape coverage cannot establish whole-workload benefit.
- Inline tuple scalar reuse passed finite compatibility checks but actual golden-contract ratio was1.014 candidate/current, despite favorable synthetic scalar-tuple numbers. Do not benchmark only the shape the optimization benefits.
- Guarded journal projection reuse/clone passed finite normal/adverse probes but cost1.56–1.60x/2.32–2.45x original construction on the tested real capture shapes. Metadata/compiler/quoted-name/event mutation guards were also incomplete. Operation-local reuse is not automatically safe or cheap; the `_recheck_table` local-column precedent does not transfer its exact scope to all callers.
- Authentic ownership fixtures are required for ownership claims. A fabricated registry/token may test rejection plumbing only. An adverse mutation rejected by an earlier unchanged guard does not exercise a newly substituted deep check; inject at the intended guarded boundary and assert the actual rejection/latching path.
- The approved attempt proof remains unaccepted on Linux. Its local passes and narrower qualified interpreter cannot be used to relax original fresh SQL/object/fence checks, cleanup or caps. Daily per-node and CLOCK pre-lease studies are closed/rejected for their measured resource/economic reasons; they do not grant broader implementation authority.

## Acceptance ladder

1. Establish a concrete source-local change and literal behavior oracle; reproduce a compatibility defect before fixing it where applicable. No broad rewrite or speculative framework.
2. Run finite representative comparisons, preserving normal/adverse hook/error/lifetime behavior. Measure candidate/current ratio with stated fixed iterations, alternating order, source hashes and input limitations; include unaffected controls. Stop for negligible or negative economics.
3. Implement only the surviving narrow change, add targeted independent regressions, then focused families and static checks. Investigate real failures; never weaken tests or treat skipped gates as passed.
4. Freeze source/test hashes; root coordinates a single original unprofiled retained gate and applicable genuine ownership/process integration checks. No competing heavy suites or instrumentation masquerading as acceptance.
5. Require exact-revision full Linux/PostgreSQL CI and unchanged ledger/venue/artifacts/controls/cleanup before A2 acceptance. Preserve60-second lease,120-second operation,150-second parent where applicable, worker/probe bounds and all shared resource limits. A passing repeat alone does not explain the existing recurring failures.

## Completed type-only screen review

Root then executed the conservative type-only variant as a temporary separately compiled function using `original.__globals__`. Its JSON and script are `identity-type-lookup-screen.json` and `.py`; my independent arithmetic/source review is `identity-type-lookup-independent-review.json`. No production replacement occurred. I only read and recomputed the recorded arithmetic, not the benchmark.

Nine alternating samples of ten calls per implementation give **candidate sample median / original sample median** ratios0.9655623194 (scalar-wide),0.9953873705 (records),1.0034830332 (mapping aliases). This is3.4438%/0.4613% faster and0.3483% slower respectively; it is not the median of paired ratios. Current daily source SHA matches the screen. The separate `current_type` preserves old `item_type` through tuples, and both original native id calls remain. Three normal-case identity-vector comparisons do not establish full hook/error/lifetime compatibility.

**Independent recommendation: reject the type-only candidate before further adverse qualification or any retained fixture.** The actual-record shape is essentially flat and mappings regress; no material actual restore benefit is established. Even applying the best synthetic ratio to all of the earlier2.1675-second observed helper cost would suggest only about0.075seconds—an intentionally optimistic illustration, not an upper bound or measured saving. Do not add guards, widen scope or run a heavy fixture merely to rehabilitate this tiny candidate. A separate newly proposed `_check_type` primitive seam remains a distinct review question.
