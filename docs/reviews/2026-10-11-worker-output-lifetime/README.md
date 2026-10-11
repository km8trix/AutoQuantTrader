# Worker-output lifetime repair

The failure-line emitter suppressed auxiliary exceptions whose tracebacks could
retain a caller's private locals. A callback rethrowing the pending assertion
also extended that assertion's entry traceback. A new64-case witness retained
all55 original cases and exposed nine failures: six caller-local lifetime and
three same-primary traceback controls. The original55 still passed. Failed
Source/native/results remain preserved separately from the passing repair.

The test-only repair adopts the already qualified Stop helper policy: discard
complete suppressed auxiliary traceback history, including preexisting history,
using the native BaseException descriptor. Restore the exact pending primary's
entry traceback; do not traverse or mutate cause/context/args or invoke custom
exception attribute hooks. Failed primary admission leaves output and cleanup
unknown. Keep the fixed fallback, one dynamic write, no retry and4096-byte limit.
All11 other helper definitions and the original worker are unchanged.

All64 case identities/decorators remain; the prior retained auxiliary-write
traceback expectation now reflects explicit discard. Eight further controls
cover preexisting private frames, hostile exception hooks and failed primary
admission. The existing constructor-error expectation is unchanged. Constructor/
snapshot issuance faults outside the emitter remain a separate coverage gap;
this repair does not establish a universal private-object lifetime guarantee.

Source/configured statics/architecture/independent prelaunch review pass. A fresh
bounded selection passes110 unique cases:72 output and38 unchanged inert worker
wiring, zero failures/errors/skips/unavailable, ten equal Source pins before/
after/current, both EOF/no capture flags/redactions0. Child elapsed0.852374416s,
275 captured bytes. Native output is persisted before report admission; actual
source/count/result/archive review passes. The inert wiring admits the original
module as text and executes only its extracted function with fake ports. It
preserves all eight original assertions and does not run worker/SQL/account setup.

Repaired helper SHA256
`6df62727171429863c7c5ca66d0b270e2c95449ce6c1cfa911590d0c94236729`/9734B;
unit `46bcd0f72860e73cc5048e598a2f7a3190dd88103f63286267ba9a69b3877441`/32183B.
Report `2b08150bf30e4ad989e52369001394cb399f957df5b6bfc9d89391966561634c`/7342B;
JUnit `a3c5041954be646dabbc668d6b6aab53b58791c4b26f4e8b01674d2bd9d82ca5`/20995B.

After preparing the verified Python/dependencies described in [TESTING](../../TESTING.md),
run architecture before project imports. Use a fresh owned output directory:

```sh
/usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 TZ=UTC \
  "$AQT_PYTHON" -I -B scripts/check_personal_architecture.py
/usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 TZ=UTC \
  "$AQT_PYTHON" -I -B -m ruff format --check --no-cache --config pyproject.toml \
  tests/fixtures/lifecycle_failure_output.py \
  tests/unit/test_personal_lifecycle_failure_output.py \
  tests/unit/test_personal_worker_parent_diagnostic_wiring.py
/usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 TZ=UTC \
  "$AQT_PYTHON" -I -B -m ruff check --no-cache --config pyproject.toml \
  tests/fixtures/lifecycle_failure_output.py \
  tests/unit/test_personal_lifecycle_failure_output.py \
  tests/unit/test_personal_worker_parent_diagnostic_wiring.py
/usr/bin/env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 TZ=UTC \
  PYTHONPATH="$PWD" PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TMPDIR="$AQT_UNIT_OUTPUT" \
  "$AQT_PYTHON" -B -m pytest -q -p no:cacheprovider -c pyproject.toml --tb=short \
  tests/unit/test_personal_lifecycle_failure_output.py \
  tests/unit/test_personal_worker_parent_diagnostic_wiring.py \
  --basetemp="$AQT_UNIT_OUTPUT/pytest-temp" --junitxml="$AQT_UNIT_OUTPUT/junit.xml"
```

The reviewed bounded caller supplies child60s/raw65536B/separate reap5s/
native524288B/JUnit131072B/report16384B; the shell recipe alone does not enforce
those caps. Preserve exact source/command/native evidence and investigate any
failure before a fresh retest. No original integration module import, initializer,
financial replay, provider or capital effect is selected by this unit recipe.

Published341929e remains the separately bound automatic CI candidate. This
offline repair is no timing remedy, financial pass, deployment or execution
authority. Live-disabled/HALTED control and all existing safety limits remain.
