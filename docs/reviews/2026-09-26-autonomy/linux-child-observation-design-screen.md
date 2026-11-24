# Linux child observation: bounded design screen

2026-09-27. Read-only source, tests, preserved Linux failure and primary Linux/procps source review. No project imports, tests, process observations, prototype, repository edits or fixture ran.

**Disposition: ordinary, narrowly scoped platform-adapter implementation is justified.** On Linux replace the per-call `/bin/ps` process with a bounded read of the same kernel status/RSS information, preserving `_ChildObservation`, the supplied observation deadline, sole-waiter ownership and all supervisor/cleanup decisions. This requires substantial adverse tests but does not require a new product/architecture decision, renewable lease, altered risk limit or new authority. No speedup or passing-worker claim is made.

## Confirmed failure and original contract

`linux-071dd5c-shard3-raw.log:474` records iteration 2, first failure call 68, `TimeoutExpired`, requested timeout 0.1 seconds, elapsed 379,105,127 ns. Total 82 calls included 81 returns and one timeout; cleanup did not overwrite the first failure. The original completed assertion failed with `child_observation_failed`. This identifies the observation timeout category. It does not distinguish process startup, scheduling, observation or cleanup latency within the timed call.

`packages/application/continuous_process.py:230–255` runs `/bin/ps -o state=,rss= -p <pid>`, caps the accepted output at 64 bytes, validates known state and numeric RSS, and returns exit only for `Z`. `:644–665` recomputes remaining work time and supplies `min(0.1, remaining)`; timeout versus other observation errors preserve separate outcome rules. RSS is checked against the unchanged memory limit only while non-exited.

The supervisor starts a new-session child (`:595–610`) and remains its sole waiter. `_terminate_owned_child:270–333` sends TERM and final KILL while the leader remains unreaped, performs the only `wait`, then independently proves group absence. Missing state, stdout EOF, zero RSS or a missing PID are not exit proof. Preserve this sequence without adding `poll`, `waitpid`, `waitid`, `Popen.kill`, retries or background readers.

The module explicitly excludes indefinitely blocked kernel I/O and hostile code. A native read must not be presented as a hard real-time guarantee against scheduler pauses or a kernel call that never returns.

## Concrete data-source choice

Use a **single `/proc/<pid>/status` sample**, not stat/statm/smaps, child-reported data, `getrusage`, or peak memory.

Reviewed procps-ng 4.0.4 `ps` prints `state` from `PIDS_STATE` and `rss` from `PIDS_VM_RSS`. The latter selects status data. Its reader performs optional stat work before status, and successful `status2proc` overwrites state from the status `State` field and RSS from `VmRSS`. Thus its relevant returned pair does not establish a requirement for a separate earlier stat-state observation. [ps output source](https://gitlab.com/procps-ng/procps/-/raw/v4.0.4/src/ps/output.c), [item/source selection](https://gitlab.com/procps-ng/procps/-/raw/v4.0.4/library/pids.c), [reader and status parser](https://gitlab.com/procps-ng/procps/-/raw/v4.0.4/library/readproc.c).

The CI log identifies Ubuntu 24.04.5 but does not record its installed procps package version. The reviewed tag is primary implementation evidence, not proof of the precise runner binary. Supported Linux acceptance must exercise the actual new adapter; no exact concurrent RSS equality with a later ps invocation can be promised.

`apps/worker/personal_research.py:94–105,438–460` already reads procfs through a no-follow/nonblocking regular-file descriptor with a 16 KiB payload limit and strict field parsing. Reuse the pattern locally in the application module; do not import an app composition root. That existing function measures **VmHWM** for another purpose. This supervisor must continue measuring **VmRSS**, in kB multiplied by 1024, including valid zero. Linux documents these as distinct peak and current-memory fields and notes asynchronous RSS accounting; this is not an accuracy upgrade. [Kernel proc documentation](https://docs.kernel.org/filesystems/proc.html).

### State and missing-memory decision

Linux 6.8 emits `R,S,D,T,t,X,Z,P,I`. The existing observer accepts initial codes `D,I,R,S,T,U,W,Z`; do not silently broaden acceptance to `t`, `X` or `P`, or treat any new code as exited. Parse one exact state-code token from a properly bounded `State` row; only `Z` produces `exited=True`. Its descriptive text is not a second state signal. [Kernel state source](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/proc/array.c).

**Chosen compatibility rule:** a present `VmRSS` must be unique and exactly an unsigned decimal plus `kB`. A missing `VmRSS` is zero only for an otherwise valid status record whose memory section is wholly absent. Reject a present malformed/duplicate RSS or a partial memory section without RSS. Apply this no-memory rule to any accepted state, not just Z; absence alone never establishes exit.

Why: the kernel captures `mm` before writing status and omits its memory section when no `mm` exists. It need not already report Z. Procps clears its record to zero before each read, so an absent memory section leaves RSS zero. Requiring RSS on every zombie breaks normal exit; requiring it on every non-Z state can add an exit-transition failure the current ps path does not have. This explicit no-mm representation is not a fallback from an I/O error, short/oversized read, unknown state or malformed field. [Kernel status construction](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/proc/array.c), [procps record reset and parser](https://gitlab.com/procps-ng/procps/-/raw/v4.0.4/library/readproc.c).

A finite parser should also require unique exact decimal Pid/Tgid matching the requested positive child PID. This is a consistency check, not a new ownership token. Do not read cmdline, environ, maps, credentials or child files. Ignore unrelated status lines without logging or retaining their payload. The trusted procfs record and the existing sole-unreaped-child invariant supply the context; an arbitrary caller-supplied status file is not production evidence.

## Boundaries for the small implementation

- Keep `_observe_child(pid, timeout=...)` as the dispatcher. Preserve the existing ps code as a separately testable helper for non-Linux platforms, including Darwin `?E` handling. Linux read/parse/deadline failures fail closed; no per-failure fallback to ps or another fresh timeout.
- Use one bounded status acquisition through `os.open` with `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` and a regular-file `fstat` check. Read no more than 16 KiB plus the rejection byte, require a complete nonempty bounded record, and close the descriptor on every path. Procfs normally reports size zero: do not reuse `_private_read`'s positive st_size/size-equality requirement. Handle short reads as transport progress within the same bounded acquisition/deadline, never as a fresh observation or retry budget.
- Retain only the parsed scalar observation across calls. No procfs snapshot, open descriptor, PID registry or RSS cache survives a call. PID ownership still depends on not reaping before final signalling. An open procfs descriptor alone does not prevent numeric PID reuse; the kernel documents that it instead remains associated with the original process. [Kernel proc descriptor semantics](https://docs.kernel.org/filesystems/proc.html).
- Set one monotonic deadline from the original passed timeout. Reject exhausted/zero budget before opening; check before further I/O, after the bounded read, and after successful parsing and descriptor cleanup. At equality or later, raise `subprocess.TimeoutExpired` with a static observation identifier so the original supervisor deadline/failure branch remains applicable. Do not return a late success.
- On an existing read/parse/close failure, propagate that failure rather than masking it with a final elapsed-time error. Close before successful return. A close failure prevents success. No signals/timers/threads should be added to manufacture preemption; the existing excluded blocked-kernel-I/O limitation remains explicit.
- Leave the original 100 ms or shorter observation budget, work/parent/lease deadlines, memory threshold, cleanup reserve, pipe/receipt limits and final receipt/lifecycle checks unchanged. The 16 KiB bound is a new bounded internal status format following existing precedent, not an increase to child output or acceptance limits.

The parser should pin a finite definition of the optional memory section for the supported Linux profile; it need not accept every future kernel addition. Unknown or inconsistent shape must fail closed. This rule and malformed-input behavior need explicit tests before adoption. These are local implementation choices, not unresolved consequential product decisions.

## Validation needed; none run here

Preserve all existing ps parser tests by calling the retained ps helper explicitly; do not delete them merely because Linux dispatch changes. Add separate dispatcher tests proving no subprocess call on Linux and unchanged ps behavior elsewhere.

Add parser/bounded-I/O/deadline cases for normal RSS, zero and over-limit RSS, full no-mm records in Z and non-Z transitions, partial/missing/malformed/duplicate fields, mismatched PID/Tgid, lowercase tracing/dead/parked/unknown states, wrong units/signs/extra tokens, byte-bound equality and overflow, partial reads, empty/missing/denied/symlink/nonregular files, every acquisition/read/close failure, and exact/shorter deadline equality before and after cleanup. Assert descriptor closure, no retry/fallback and no accepted late result.

Retain `test_continuous_process.py`'s real zombie leader/live descendant, no-poll/single-reap ordering, unavailable-observation cleanup, stop/memory/deadline and terminal protocol tests. Its existing deadline model at `:796–952` should continue to preserve timeout versus other-error precedence. A finite Linux owned-child test must exercise live current RSS, stopped state and actual unreaped Z without confusing leader exit with group absence. The original fixed-worker integration and Linux matrix remain acceptance gates; a parser unit pass alone cannot close the failure.

No performance number is proposed. Removing the per-probe subprocess eliminates one observed failing mechanism, but scheduling, resource bounds, independent lease expiry and other worker failures remain independently relevant.

## Source binding

```
0f4f9b925c14d14f4535086d9a05ad8d0d3e9a7b088bde5c712d53f1a57c6517  packages/application/continuous_process.py
8f44671bcf03d962f78491ef09a07abdcd7f73e94602468c39b63f7f0bbdbea5  apps/worker/personal_research.py
4eaba660713d3161e3e4c94e713e1b4dbbb8dcd127407fe791db7457e181f668  tests/unit/test_continuous_process.py
76ba04b4517e90d3dbee42c83e715128af12c8fbcbd5ba8fe3498e15c4241ac7  tests/unit/test_retained_research_runner.py
a7fd409943b8e42178cc77264b7930ad53ea8b1f27dcb8dedfd9f62c7ebee753  tests/integration/test_continuous_simulation_worker.py
76222043208a82b773cc59384fe24964ea05012cfe7d018c47c0991016e028eb  tests/fixtures/continuous_process_observation.py
b1a77aeae13356faaa34c723f2e67ee03c54e07be752ec48986369dcf8d6b9d5  /private/tmp/aqt-autonomy-audit/linux-071dd5c-shard3-raw.log
```
