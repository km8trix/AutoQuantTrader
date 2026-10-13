# Targeted lifecycle observation replacement

The original seven genuine cases passed against frozen source/tests in 374.05s.
The successful restores took 52.482s and 52.946s with process-wide `sys.setprofile`
active until first proof use. The five expected denials took approximately
16.8–17.3s each. These instrumented times are not production performance evidence.

Root subsequently ran the unchanged, unprofiled original retained test: PASS,
222.75s total, 179.754s fixture setup, 40.246s restore. Production hashes stayed
unchanged. This review repeats root's measured result; it did not launch that run.

## Test-only replacement

`_first_local_event` in the lifecycle test file claims one free CPython monitoring
tool ID and enables only one local event on one original code object:

- `PY_START` on `_require_resolved_for_factory` for ordinary observation/actions.
- `PY_RETURN` on `_begin_factory_fingerprint_use` for the reentrant case, after
  the original permit has entered checking state.

The callback verifies `sys._getframe(1).f_code` is the exact target code, disables
the local mask, unregisters its callback and frees its own tool ID **before** the
existing case action. Its frame reference is deleted in `finally`. No global
event mask or existing process profiler is modified. A surrounding `finally`
also cleans up if the target never runs or raises. Other monitoring tool owners
remain untouched. No production function, validation, authority or limit changes.

The copied-proof case now reads the genuine registered owner immediately after
copied-token rejection and requires both `factory.failed` and `daily.failed`
before installing the separate cleanup-binding fault. This removes the earlier
coverage ambiguity: the binding fault cannot stand in for copy-denial poisoning.

## Microchecks and review

`test_proof_local_monitoring.py` imports the actual new test helper and exercises
12 cases: both local event types with normal/no-call/callback-error/target-error/
nested actions, an occupied monitoring tool, and an existing global profiler.
It checks exact frame values, at most one observation, propagation of original
errors and full mask/callback/tool cleanup. Result: **12 passed in 2.67s**;
`proof-local-monitoring-selfchecks.txt`. Earlier standalone six-case interpreter
probe is preserved in `proof-local-monitoring-probe.py` and `.json`.

Both architecture and spec reviewers independently inspected the replacement.
The spec reviewer also confirmed frame behavior in a separate ten-case probe and
verified compatibility with its cost plugin reserving monitoring slot 5. These
checks establish observer mechanics, not a new genuine-case outcome.

All five new repository test files pass scoped Ruff formatting and lint checks.
Only these test files changed after the first genuine run; production code stayed
frozen. The updated genuine cases have not yet run; root is coordinating them
after its original regression suite.

## Runtime qualification

The optional proof is qualified only for CPython 3.12.13. The seven positive-proof
lifecycle cases explicitly declare that restriction. Positive raw data admission
tests and finite implementation-inventory tests are similarly scoped. Unsupported
raw-profile tests, pure method-profile checks and all four actual source/genesis
controls remain active outside that qualification. The deep-row original hash
oracle still runs; only its optional positive native admission assertion is
conditional. Unauthorized proof issuance must still reject or return no proof.

The existing ordinary retained restore tests remain unchanged and unskipped. No
actual Python 3.13 runtime was available or executed here. Synthetic unsupported
sentinels exercise fallback plumbing only and are not Python 3.13 acceptance.

## Next root-owned combined command

From `/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development`,
run architecture first, then the complete 100-case scope in one process to expose
any mutation-test contamination of later genuine factory proof admission:

```sh
env -i PATH=/Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin:/usr/bin:/bin PYTHONPATH=/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 TZ=UTC /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -I -B scripts/check_personal_architecture.py
env -i PATH=/Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin:/usr/bin:/bin PYTHONPATH=/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 TZ=UTC /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -B -m pytest -q tests/unit/test_continuous_attempt_fingerprint_proof.py tests/unit/test_continuous_attempt_fingerprint_behavior.py tests/unit/test_continuous_attempt_fingerprint_method_profile.py tests/integration/test_continuous_attempt_factory_proof.py tests/integration/test_continuous_attempt_factory_proof_lifecycle.py --durations=10
```

The expected current-runtime inventory is 58 data + 23 behavior + 8 method-profile
+ 4 owned-source/genesis + 7 genuine lifecycle = 100 cases with no profile skips.
Capture source/test hashes before and after that run. Exact-source Linux CI and
complete proof-cost measurement remain separate from this test-only adjustment.
