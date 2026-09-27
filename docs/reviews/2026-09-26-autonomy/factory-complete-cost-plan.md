# Bounded genuine proof cost observation

This diagnostic observes the first genuine lifecycle `[original]` case while the
existing seven-case module shares its original signed-history fixture. All other
cases run normally with no diagnostic monitoring. The three explicitly listed
pure proof/behavior/method-profile modules and the existing cheap source-owner
control module may run in the same process, unobserved; all four files are also
source-hashed. Other modules are refused. Fixture setup is outside every
timer. No project function is replaced, called extra, or bypassed; no registry is
fabricated and no permit is consumed by observation. The original uninstrumented
retained test and exact-source required CI remain separate acceptance gates.

## Mechanism and bounds

Plugin imports follow the genuine lifecycle module: app factory first, then the
root/source modules. This preserves normal import-time baseline construction.

The verified CPython 3.12.13 `sys.monitoring` facility records local PY_START and
PY_RETURN on 15 fixed original code objects. PY_UNWIND is necessarily global and
immediately filters unrelated code; its exception-event overhead is part of this
instrumented diagnostic. Monitoring slot 5 must be unused; the lifecycle test
uses another first-free slot and disables its one-shot observer normally. Existing
profilers cause refusal. All masks/callbacks are removed and the slot released in
the runtest-call finally, including test failures.

Selection requires the original execute operation, thread, reader, episode and
resolved value identities. Source calls additionally bind the original source
identity. The actual returned proof is independently observed in both original
registries, including the nonempty resolved-source condition; source and root
retirement must both have occurred. Exactly two root retirement returns are
expected: explicit pre-handoff retirement followed by the episode finally's
idempotent call. Exactly one source revocation is required; both root call
durations remain charged to lifecycle cost. IDs and weakrefs are retained, never source
graph references. Frame references and return values exist only during callbacks.
Original exceptions propagate unchanged; diagnostic errors propagate and cannot
turn failures into success.

Limits: 20,000 selected events including outstanding returns; 4,096 started spans;
64 live selected spans/ancestor frames; 32 KiB JSON. Metadata includes counters,
aggregated inclusive/direct-child times, source hashes and integer resource
counts only. Bound, admission, cleanup, hash or count failures invalidate the
result. A successful test with invalid capture returns a failing diagnostic exit.
No input graph, credentials, artifacts or provider runtime files are emitted.

## Interpretation

The report gives actual issue/retirement cost and actual private-source guard cost,
including both behavior inventories, raw-data checks and source/root ownership
handshake. It also times explicit new root begin/end and wrapper dispatch. The
same selected original graph's ordinary full owner checks provide an approximate
original guard-prefix and removed-fingerprint estimate. Candidate/original ratio
means modeled incremental replacement cost divided by estimated removed full
fingerprint cost; lower is faster.

This is an approximate economic model, not an exact paired measurement. Prefix
subtraction assumes comparable ordinary owner-check costs. Episode residual
includes some unchanged dispatch. Added borrow branch/finally instructions outside
explicit methods are not isolated. The separately reported new-span envelope
includes unchanged private-method prefixes and is not a rigorous upper bound.
Monitoring and the existing test observer also add overhead. Neither this model
nor a valid capture alone establishes startup or Linux acceptance.

## Finite validation

- `test_aqt_factory_complete_cost.py`: 17 passed in 0.03 seconds. Actual observed
  frames, nested accounting, ValueError/TimeoutError/KeyboardInterrupt/SystemExit
  identity, unwind reporting, no retained input, return-reserved event bounds,
  slot refusal, diagnostic-error propagation, unconditional cleanup, exact two-root/one-source retirement counts, both root costs charged, and explicit module allowlisting.
- Exact five allowlisted modules collected with the plugin: 100 collected in
  1.48 seconds; no fixture executed. The deliberately unmeasured collection JSON
  is invalid and cannot serve as economics evidence.

## Authorized launch command (root schedules; no launch by this author)

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/private/tmp/aqt-autonomy-audit:/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -B -m pytest -q -p no:cacheprovider -p aqt_factory_complete_cost --aqt-complete-cost-dir=/private/tmp/aqt-autonomy-audit/factory-complete-cost-first tests/unit/test_continuous_attempt_fingerprint_proof.py tests/unit/test_continuous_attempt_fingerprint_behavior.py tests/unit/test_continuous_attempt_fingerprint_method_profile.py tests/integration/test_continuous_attempt_factory_proof.py tests/integration/test_continuous_attempt_factory_proof_lifecycle.py
```

Run from `/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development`.
The output must be a fresh direct subdirectory. Preserve source/plugin/test hashes
for the entire fixture. No simultaneous heavy runs.

Optional same-process validation paths (each explicitly allowlisted and hashed):

- `tests/unit/test_continuous_attempt_fingerprint_proof.py`
- `tests/unit/test_continuous_attempt_fingerprint_behavior.py`
- `tests/unit/test_continuous_attempt_fingerprint_method_profile.py`
- `tests/integration/test_continuous_attempt_factory_proof.py`
