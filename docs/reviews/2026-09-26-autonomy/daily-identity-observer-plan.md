# Original-only daily identity observation

Temporary diagnostic, 2026-09-26. This observes unchanged validation. It neither implements nor approves a daily identity proof. No genuine fixture has been run by this agent.

Files:
- `aqt_daily_identity_cost.py`: opt-in pytest plugin.
- `test_aqt_daily_identity_cost.py`: finite synthetic mechanics checks; no project imports.
- `daily-identity-mechanics-final.txt`: current selfcheck output.

Run from `/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development`, after the architecture check. Root schedules at most one genuine run; no concurrent heavy work. The output must be a fresh direct child JSON under the audit directory:

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -I -B scripts/check_personal_architecture.py
```

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/private/tmp/aqt-autonomy-audit:/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC AQT_DAILY_IDENTITY_PROFILE_PATH=/private/tmp/aqt-autonomy-audit/daily-identity-original-first.json /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -B -m pytest -q -p no:cacheprovider -p aqt_daily_identity_cost tests/integration/test_continuous_simulation_factory_outcome.py::test_actual_signed_retained_outcome_restores_with_original_utc_and_lease
```

Cheap selfchecks (already performed):

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/private/tmp/aqt-autonomy-audit PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -B -m pytest -q -p no:cacheprovider /private/tmp/aqt-autonomy-audit/test_aqt_daily_identity_cost.py
```

## Selection and original behavior

The sole test node and sole exact `restore-original-retained-outcome` execute are literal. Project modules are read from `sys.modules` only after ordinary test collection and fixture setup; the plugin imports no project module. The constructor pins four original code objects and the original graph/episode/wrapper code, then disassembles the two explicit `require_resolved_snapshot(current)` CALL/cache ranges. It does not invoke any source method.

An observed borrow must belong to that execute's exact reader, registered original factory read, original daily episode/current, thread, HALTED control and store. Later borrows must match the first candidate. Only the direct chain `builder -> public daily method -> graph at one of the two sites -> [optional proof wrapper] -> daily episode check -> selected original borrow` is selected. Both active attempt-proof and ordinary fallback routes are counted. The suspended contextmanager generator is not incorrectly required on the live stack.

There are no substituted bindings, snapshots, extra validations, permits, proofs, replays, SQL, files from fixture runtime, credentials, provider calls, retries or changes to original deadlines/assertions/cleanup. A source hash change invalidates the observation. No frame, original graph, returned tuple/child or exception is retained by the observer; span bookkeeping uses scalar IDs/timestamps, and owner references are weak and cleared at stop.

## Bounds and fields

At most 20,000 selected events with room reserved for outstanding terminals; 4,096 started spans; depth 64; one returned vector histogram of at most 131,072 bindings; serialized output at most 32,768 bytes. Excluded builder-call count saturates independently at 20,000 and sets an explicit saturation flag. No raw input/output/exception text or runtime path appears in the report. Output is written once, after the test, using exclusive creation and mode 0600.

`aqt-original-daily-identity-observation/1` contains source/plugin/probe hashes, original test exitstatus, validity/extent, bounds, count/timing aggregates, the two CALL/cache offsets, proof/fallback route counts, and one first-vector summary. Returned and unwound counts/times are separate for execute, borrow, and first/second public/builder positions. Timing is inclusive and nested.

The first successful builder return contributes exact returned-tuple length, original local `seen` set size, and the existing public caller's original `before` tuple length. A finite type-identity inventory yields scalar counters for exact builtins, Decimal/date/datetime, mapping proxy, 22 declared daily record identities, and unknown. There is no dataclass discovery, arbitrary class-name lookup, custom type hashing/equality, Mapping classification, backing-map probe or graph re-traversal. The summary stays provisional until that exact public frame returns; public unwind is explicitly recorded as rejected. Shape overflow omits the histogram and invalidates that diagnostic summary.

Existing simultaneous attempt-proof charges are read from its original owner/source state at that first summary. Active counts include data, source/root behavior and existing reserves, with caps and arithmetic remainder. Inactive/unavailable are explicit and have no invented zero charge. These measurements are not a new daily proof's actual resources, compatibility or authority.

## Failure and timing interpretation

CPython 3.12.13 `sys.monitoring` slot 5 must be unused; an existing profiler is rejected untouched. All local masks, global event mask, callbacks and the owned slot are cleared in `finally`. PY_START/PY_RETURN are local. PY_UNWIND is globally enabled but immediately filtered to fixed codes: global event-filter overhead is real and not bounded by the selected-event counter.

Original exceptions, including timeout/interruption, continue unchanged. If the observer itself fails during an already-active original unwind, the original exception takes precedence and metadata is invalidated. Observer call/return faults propagate and invalidate; nothing suppresses an original test failure. Bounds or missing terminal events invalidate the measurement rather than extending limits. A fully recorded failed original execute may have `capture_status=valid` with `observation_extent=partial_original_unwind` and nonzero test exitstatus; this is valid partial observation, never acceptance. An invalid capture cannot turn a successful test into acceptance and causes a failed diagnostic exit.

Builder stop time is taken before the one bounded scalar summary; that summary's own nanoseconds are recorded separately. Public/borrow/execute costs include observation overhead. Nested times must not be added as independent savings. Outside-execute lease release/cleanup is not separately timed or classified; original test exitstatus remains authoritative and may include cleanup failures. This is a single instrumented original-path measurement, not unprofiled performance, Linux acceptance, a replacement implementation, or owner approval for a new proof.
