# Worker observation diagnostic — 2026-09-26

## Purpose and authorized scope

CI at `2a9fc2c` reports `child_observation_failed` but loses the caught exception
category. This small test-only diagnostic observes the existing parent-side
`process_module._observe_child` boundary in the original worker restart test.
Root subsequently authorized implementation in exactly three test files:

- `tests/fixtures/continuous_process_observation.py`
- `tests/unit/test_continuous_process_observation_diagnostic.py`
- `tests/integration/test_continuous_simulation_worker.py`

No production code, timeout, resource cap, process cleanup, child invocation,
lease/fence, assertion condition, receipt check, restart count or history check
is changed. No heavy test was run by this author.

## Mechanism

Each of the two original worker iterations creates a fresh diagnostic and a
scoped monkeypatch. The wrapper forwards the exact positional and keyword inputs
once to the original function; omitted keywords remain omitted. It returns the
same object or uses a bare re-raise for the same exception. Timing surrounds only
the original call. The scoped binding is restored after `supervisor.run` and its
finally cleanup finish, before the original assertion executes.

The original `assert outcome.status == "completed", outcome.reason` remains.
Only its AssertionError handler emits a bounded JSON summary, then re-raises.
Successful iterations emit no diagnostic output. Later receipt/restart/history
assertions retain their original behavior. No extra ps command, process lookup,
wait, retry, delay, deadline extension or cleanup call is introduced.

Counters have six fixed buckets: returned, TimeoutExpired, ValueError, OSError,
SubprocessError and other. Each count and
the total saturate at 4,096, setting `overflow`; the original call still occurs
beyond that cap. The first failure keeps only saturated call ordinal, a static
category, exact finite requested timeout within the existing 0–120-second request
range, and elapsed nanoseconds capped at 10^15. Invalid/outside-range timeout
metadata becomes null and sets overflow; its original value is still forwarded.
Cleanup failures never overwrite the first failure. Each new iteration resets
all state. The known first/second iteration number is attached only at emission.

No exception object, type name supplied by an exception, message, representation,
traceback, PID, command, arguments, paths, subprocess output or observation result
is stored in diagnostic state. Original callable retention is intentional; only
its ordinary original call frame receives arguments. The wrapper adds a traceback
frame while an error propagates, as any Python wrapper does, but stores no such
traceback. Output contains only fixed keys/categories and bounded scalars.

## Interpretation

- TimeoutExpired identifies the subprocess timeout branch; requested timeout and
  elapsed time show its budget and observed duration, not scheduler attribution.
- ValueError identifies the observation parser/result rejection. That still
  covers nonzero ps status, oversized/malformed output and rejected fields; it
  cannot identify the exact field or prove an OS cause without more evidence.
- OSError identifies the OS error family; no errno/path/message is exposed.
- SubprocessError identifies another subprocess failure family.
- Other preserves and categorizes all other BaseExceptions, including interrupts,
  without claiming a cause.

The first failure is the relevant main observation when the supervisor's reason
is `child_observation_failed`; later cleanup errors remain separately counted.
The diagnostic adds a small timing/metadata overhead under the unchanged real
deadline. Its passing run cannot erase the prior failure or establish a fix;
publication is for evidence and required exact-source validation only.

## Validation and reviewed checkpoint

Before project imports, the architecture check passed. Scoped checks then passed:

- 19 unit cases in 0.05 s: exact forwarding and one call, omitted/default timeout,
  return identity, error identity/cause/context and static categorization,
  redaction, first-failure survival through cleanup, per-iteration reset, bounded
  copy-out summaries, saturating counters/time and continued calls, no input or
  exception retention, and nonfinite/outside-range metadata.
- Scoped Ruff check passed; formatting check passed for all three files.
- `git diff --check` passed. No integration fixture or heavy test ran.

SHA-256:

- helper: `76222043208a82b773cc59384fe24964ea05012cfe7d018c47c0991016e028eb`
- unit tests: `ba38e24850a56b2068ca2e6ced0966dfa61ae5057d024693fddec04cb97d4ff6`
- original worker test with observation: `a7fd409943b8e42178cc77264b7930ad53ea8b1f27dcb8dedfd9f62c7ebee753`
- unchanged production process module: `0f4f9b925c14d14f4535086d9a05ad8d0d3e9a7b088bde5c712d53f1a57c6517`

Root schedules original worker integration, source review and publication after
current CI completes. This note is diagnostic evidence, not acceptance.
