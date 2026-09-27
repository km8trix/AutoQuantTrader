# Independent review — worker observation diagnostic

Reviewed read-only on 2026-09-26 in `autonomous-development` after the root-reported 102-case validation. Scope is exactly:

- `tests/fixtures/continuous_process_observation.py`
- `tests/unit/test_continuous_process_observation_diagnostic.py`
- the diff to `tests/integration/test_continuous_simulation_worker.py`

No tests, production edits, provider actions or reruns were performed by this reviewer. The existing native performance clock is treated as an ordinary trusted clock, consistent with this test instrumentation's stated scope.

## Result

No blocker found. The diagnostic is suitable for collecting the missing exception category on a subsequent justified validation revision. It is evidence collection, not a repair or acceptance of the previous worker failure, and it remains separate from the genuine retained-restore timeout investigation.

## Verified properties

- Each iteration captures the original parent `_observe_child` function before the scoped patch. The wrapper invokes it exactly once with unchanged positional/keyword arguments, including omission of the timeout keyword, returns the original object, and uses bare re-raise for original errors. It performs no extra process read, retry, wait, sleep, signal or cleanup call.
- The original two-iteration restart test, supervisor arguments, limits, exact completed-status assertion, receipt/hash/length checks, matching restart results, financial hashes and row counts remain. Only a first/second iteration label replaces the unused loop variable.
- `supervisor.run` and its existing `finally` cleanup finish while the observer is in scope. The monkeypatch context restores the original binding before the unchanged status assertion. If the run unexpectedly raises, the context still restores the binding; the diagnostic does not catch that exception as a successful outcome.
- Each iteration has a fresh diagnostic. Its first failure is immutable once recorded; later cleanup failures and successful cleanup observations only update aggregate counters. Thus the primary observation failure cannot be overwritten by cleanup.
- Six static category counters and the total saturate at 4,096 and mark overflow without suppressing further original calls. The first record contains only the saturated ordinal, static category, exact finite numeric timeout within 0–120 seconds, and bounded elapsed nanoseconds. Unknown or invalid timeout metadata becomes null without conversion or retention. Iteration is supplied as the known constant 1 or 2 by this test.
- No PID, command, raw stdout/stderr, exception arguments/message/type-derived name, private path, input object, observation result or traceback enters retained diagnostic state or its summary. Summary copies prevent caller mutation of internal counters/first failure. The original callable remains retained intentionally. A wrapper traceback frame can exist while an exception propagates, but the diagnostic does not save it.
- The summary is printed only after the original status assertion fails, after supervision/cleanup and binding restoration; successful outcomes emit nothing. The handler re-raises the assertion. Ordinary native timing and scalar bookkeeping add overhead under the same deadlines and do not grant a passing result.

## Test coverage reviewed

The 19 unit cases substantiate exact one-call forwarding, omitted/explicit timeout handling, return identity, exception identity/cause/context including interruption exceptions, first-failure preservation across cleanup, iteration reset, copied summaries, saturated metadata while continuing calls, non-retention of input/exception objects, and nonfinite/out-of-range redaction. The original process tests and worker integration remain the behavioral gate; the root reports 82 original process cases + 19 new unit cases + the original worker integration passing (102 total).

## Interpretation limits

`TimeoutExpired` identifies the timeout family but does not prove scheduler contention. `ValueError` still combines rejected ps exit status, output shape and field validation; it does not establish which parser predicate failed. `OSError` deliberately omits errno and private messages. A later passing run supplies no missing historical subtype and cannot erase the original CI failure. No change to a process/probe/lease/resource bound or production behavior is recommended from this diagnostic alone.

## Separate follow-up: proof-positive failure marker

Reviewed only the subsequent diff to `tests/integration/test_continuous_attempt_factory_proof_lifecycle.py`; no tests or source edits performed. No blocker found.

The added flag becomes true only after the existing execution and observer `ExitStack` return. Unexpected failure in the `original` or `retired` case emits one fixed JSON object after the preexisting test cleanup, while the original exception continues propagating. The other adverse cases and all successful runs emit nothing. Existing execution calls, observers, limits, assertions and cleanup operations are unchanged. Output contains only the known parametrized case and `bool(captured)`, without retained data, exception content, paths or credentials.

Interpretation is narrow: true means the test successfully captured a private-method entry; it does not mean the proof check completed or the operation passed. False means no entry was successfully captured and is not by itself proof of fallback (for example an exception before that callback completes would also leave capture empty). The marker supplies missing context for the 60.265-second positive-case failure without clearing it or identifying its root cause. The root reports two cheap pre-fixture plumbing checks preserving exception identity, monitoring slots and redacted false output; this reviewer did not rerun them.
