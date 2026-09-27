# Final-probe test cleanup masking: independent design review

2026-09-27. Read-only inspection of the original test, current supervisor and preserved old-head shard-15 log. No source edits, tests, fixtures or CI actions.

**The proposed test-only correction is justified.** The original failed node's stack reaches `_supervise`'s `finally`, then `_terminate_owned_child`, then the test's patched `_observe_child`. On first Z that patch waits for a false-exit SQL sample. But the supervisor has already set `stopping` and attempted to join that producer. This test-only wait can no longer expect a new sample. Its AssertionError replaces the earlier outcome/exception and interrupts the rest of cleanup. The log proves this masking path; it does not reveal the original failure reason or establish that the producer had already fully stopped.

Current production order remains appropriate: normal exit observation sets the latch before termination; failure cleanup stops the producer before termination; termination keeps the leader unreaped through group signals, then waits once and separately checks group absence. Do not change this order or increase bounds to accommodate the instrumentation.

Minimal correction:

1. Capture the original `_terminate_owned_child`. A local wrapper sets a cleanup flag only around that original call and restores the previous flag in `finally`; forward the same child/keywords and return or rethrow unchanged.
2. Inside the existing child-observer wrapper, always retain the main-thread assertion, original-child/unreaped assertion and exactly one original observation. Gate only the synthetic `zombie_seen`/false-sample handshake on not being inside cleanup. Do not fabricate an observation, set either positive event, skip native observation, or suppress real observation errors.
3. Assert `result.status == "completed", result.reason` before the original positive sample assertions. Preserve `require_result`'s delayed/post-exit sample, complete cleanup, zero child return code and exactly-one-wait checks, plus final probe and temporary-artifact checks.

For meaningful adverse verification, retain the existing positive test node and delegate it to a private shared exercise helper. Add one separate negative node using the same helper/instrumentation. On the first original Z observation outside cleanup, inject a single static `TimeoutExpired` before setting `zombie_seen`; use the original received timeout and keep every other original observation. This deliberately forces the formerly masked failure-cleanup route.

The negative must establish that injection occurred exactly once; no positive-handshake state was fabricated; the outcome is failed/child_observation_failed with no receipt; result acceptance was never called; the actual wait occurred exactly once; cleanup reports reaped and group absent; the probe stopped; and private operation artifacts were removed. The production timeout classifier can still report deadline if a real bound is exhausted—such a test failure must remain visible, not be relaxed or retried. The positive node retains every existing assertion and delay.

This one additional fault case tests the actual instrumentation and supervisor together rather than merely copying their intended behavior into a fake model. It is not a claim that old CI's hidden reason was TimeoutExpired; that remains unknown. New production changes are unnecessary.

Observed source paths: `tests/integration/test_continuous_process_lifecycle.py:320–399`; current `packages/application/continuous_process.py:706–716,807–845,875–902`; old-head raw stack is `linux-071dd5c-shard15-raw.log:531–562`.

Reviewed SHA-256 values:

```
a7b98cf8e11036068a002f7ca56516c973bf84e7315ae9fbf4e031b42cdd6655  packages/application/continuous_process.py
4908ac88f240ef37474834aec31d21fb1747010e0de91a2ec704c59feb5991ef  tests/integration/test_continuous_process_lifecycle.py (committed baseline, verified with git show HEAD)
28932f28ef2c2233cfa262b1001fa54b6cea86ae4a118b71bd0e3be17610ed7e  linux-071dd5c-shard15-raw.log
```

## Implemented test correction review

Reviewed final test SHA-256 `278f884b89f496b328be346e938724960c038d96255ee6b252159ea87305d0bb` against the committed baseline above. **No blocker.** The production source remains `a7b98cf8e11036068a002f7ca56516c973bf84e7315ae9fbf4e031b42cdd6655`.

The original positive node remains unchanged in identity and invokes one shared private exercise. Its delay, original SQL probe/result callback, forbidden-poll assertion, original observer call, one-wait requirement and final sample/cleanup checks remain. The cleanup wrapper forwards its arguments exactly and clears its main-thread, non-reentrant phase flag in `finally`. Only the artificial success handshake is bypassed during cleanup; original observations and unreaped-owner assertions still execute.

The added negative node injects once after an original Z observation, before either positive event is set. It requires the original failed/child_observation_failed outcome, no receipt, an actual cleanup observation, no positive flags or result acceptance, complete cleanup, return code zero, one wait, stopped probe and no operation directory. Status/reason now precedes positive-only assertions, so an earlier normal failure remains visible.

No timer, threshold, retry, production condition or original positive assertion is relaxed. Root is running the combined original worker/lifecycle gate; this read-only source review makes no test-pass claim. Old CI's initial masked failure remains unknown.
