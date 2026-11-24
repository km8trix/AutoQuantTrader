# First iteration2 parent-observe diagnostic

This checkpoint adds a separate test-only profile route. Wave4 integration and
original financial acceptance remain open. Public history descends fromaa311dd;
use Git and exact-revision CI for actual HEAD, dirty state and gate results.

## Problem and current evidence

[CI38330853330](https://github.com/km8trix/AutoQuantTrader/actions/runs/38330853330)
closes FAILED with6,289 financial passes/three failures across6,292 cases, zero
errors/skips. All20jobs close15success/fivefailure; foundations/browser pass.
Worker iteration2 reports `probe_stalled` with an observe callback recording
570.696498ms wall/570.541414ms threadCPU and zero child observations. Source supports
an initial500ms freshness-timeout inference; the exact rejecting branch is unproven. Retained and
retired proofs lose the60s lease; aggregate and separate signed-retained diagnostic
fail. These results establish no SQL, GC, scheduler or GIL cause.

The signed-retained profile separately admits309rows/4,919considered, execute
started/notreturned and testexit1, with instrumented wall60.346944174s/
processCPU60.324061511s/threadCPU60.324061501s. Inclusive costs overlap. The new
parent profile has its own schema and selected interval; those older factory rows
are not its data or a whole-restore savings estimate.

## Implementation and boundaries

- [Worker](../../../tests/integration/test_continuous_simulation_worker.py) reads
  only `AQT_PARENT_FIRST_OBSERVE_PROFILE_PATH`. Absent selection retains the original
  lifecycle expression and skips every new factory/wrapper/write/emit call.
  Existing stage timing and all eight original financial/restart assertions stay.
- [Helper](../../../tests/fixtures/parent_first_observe_profile.py) profiles only
  the first observe in iteration2, on the actual probe thread. Fresh SQL delegate
  lookup remains inside the existing timed forwarding and profiler interval.
  Exact-bool factories defaultFalse; no general callback/clock/cap configuration.
- The required worker stays unprofiled. A separate failure-triggered
  [Ubuntu job](../../../.github/workflows/ci.yml) runs the exact original node after
  successful foundations/failed backend tests; it is excluded from aggregation.
  Architecture precedes project imports. Clean environment, private0700 directory
  and exclusive0600 report preserve output ownership and exact pytest exit.
- Schema `parent-probe-iteration2-first-observe-static-cprofile/2` validates every
  native entry before selecting top32 inclusive/self overall/project sets, at most
  128 union rows and49,152 bytes. Static relative Source labels are permitted; no
  private/absolute path, SQL/parameters, addresses, code/frame or argument values.
  The failure line exposes only bounded scalar availability within4096 ASCII bytes.
- The probe stops profiling and converts to static data itself. After supervisor
  cleanup, main may write stopped data nonblocking. An active/invalid/oversized
  report is unavailable, with no added wait, cross-thread disable or active export.
  Upload only `parent-probe-first-observe.json` and `test-exit.json`; preserve test
  failure, and treat a missing stopped profile as an incomplete diagnostic.
- Native profiler storage/code retention is not bounded by emitted output. The
  legacy512-row/1,000,000-byte projection remains an intermediate. Ownership/error/
  lifetime controls are finite native-runtime qualifications, not arbitrary hook
  takeover or hostile-interpreter guarantees. Only an explicitly pending callback
  primary authorizes auxiliary-fault isolation. Unrelated ambient handled errors
  cannot authorize swallowing fresh errors or interruptions; protect their retained
  ownership without granting suppression authority.

The instrumented interval includes existing dispatch/timing/counter and profiler
bookkeeping overhead. Static conversion can delay queue publication after the
profile stops. Rows cannot attribute automatic GC, isolate exact CPU/wait or prove
cause, removable time, observer/lease fit or future profitability.

## Validation and next gates

Independent Source/model/collector reviews pass. Corrected temporary214 ordinary
cases pass with zero failures/errors/skips,0.88s pytest/1.237691708s healthy capture;
fresh architecture3.292199833s. Preserve the earlier hostile-parameter collection
failure and213-pass/one-failure invalid-syntax mutant. Deferred hostile construction
and valid `finally: pass` repair the tests while retaining strict hooks/assertions.

The earlier installed609 pass (2.20s pytest/2.535625917s healthy capture) and genuine
full-lint I001 remain historical. Moving only the new worker import block preserves
module AST apart from import order and all eight assertions. Fresh609 unique cases pass with identical
ordered IDs, zero failures/errors/skips,2.76s pytest/3.200404750s healthy capture/
885raw bytes/66stable inputs; architecture3.961583208s/64pins. Full format1,065 files
and full lint pass. Independent current-result and final public Source/docs/privacy
reviews pass. The combined
selection counts214 plus395 retained ordinary cases; shared49 wiring cases count
once. The earlier697 canonical/financial cases and444 stage-timing gate retain
their own historical scopes. Ordinary passes do not execute the actual worker or
qualify Ubuntu native profiler/report transport, financial checks or Wave4.

Next normally publish the reviewed checkpoint to the existing approved
[draft PR56](https://github.com/km8trix/AutoQuantTrader/pull/56). Then independently
admit exact-source required and diagnostic outcomes plus bounded artifact ZIP/JSON.
No blind retry, manual CI dispatch, force push, merge or deployment is selected.

Production, trading authorityfalse/HALTED and all checks remain. Preserve lease60s,
retained alarm120s, worker30s wall/CPU/512MiB, parent29.25s+.75s cleanup,
observer100ms and freshness500ms. No credentials/provider/live capital are involved.
Commands and constraints are in [TESTING](../../TESTING.md),
[STATUS](../../STATUS.md), [PLAN](../../PLAN.md),
[ARCHITECTURE](../../ARCHITECTURE.md) and [DECISIONS](../../DECISIONS.md).
