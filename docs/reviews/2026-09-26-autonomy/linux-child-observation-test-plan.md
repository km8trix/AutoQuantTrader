# Linux child observation: finite validation plan

Scope: replace only Linux's per-observation `/bin/ps` subprocess with the source-reviewed single `/proc/<pid>/status` read. Preserve `_ChildObservation(exited, resident_bytes)`, current RSS, original caller timeout (`min(0.1, remaining)`), unavailable-observation rejection, and sole-parent ownership/signals/reap/group-cleanup ordering. No source changes or tests were run for this plan. The current CI failure is a handled `ps` TimeoutExpired, not proof of an unhandled worker race.

The screen proposes a 16 KiB + 1 bounded read using `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`, regular-file fd qualification, no reliance on procfs `st_size`, and unconditional close. Native evidence is status `State`, exact requested positive `Pid`/`Tgid`, and current `VmRSS` in kB × 1024. Only Z means exited. The existing allowed first-code set D/I/R/S/T/U/W/Z remains; unaccepted kernel t/X/P codes do not become exit evidence. Non-Linux retains the literal existing ps helper. The reviewed no-mm qualifier requires absence of every key beginning Vm or Rss and exact HugetlbPages/CoreDumping/THP_enabled/untag_mask; these belong to the kernel mm branch.

## 1. Keep existing tests meaningful

Extract the original ps implementation into an explicit private helper without parser/error/command changes. Retarget only tests that deliberately mock `subprocess.run` or assert raw ps grammar to that helper: state/RSS success, malformed/unavailable output, Darwin `?E`/`?Es`, and Linux rejection of Darwin syntax. Keep Darwin dispatcher tests and original cleanup-transition model using the public observer dispatch. The saved `_REAL_CHILD_STATE_AND_RSS_PARSER` seam must still exercise the real dispatcher plus original Darwin helper, not a stale function accidentally bypassing dispatch.

Add dispatcher tests: exact Linux branch calls native helper once with identical pid/timeout; Darwin calls ps once; native read/parse/timeout errors propagate without fallback, retry, cache, or subprocess creation. Preserve unsupported-platform behavior if currently delegated to ps; do not broaden supported production platforms through a test.

## 2. Pure status parser table (synthetic bytes; host independent)

- One valid status for every existing accepted state code; only Z exits. Exact VmRSS 0, 1, 1024 and a value over the existing memory ceiling return kB × 1024 without clamp. Prove VmHWM/high-water, VmSize, RssAnon/RssFile/RssShmem values are not substituted or summed.
- Require exactly one positive Pid and Tgid equal to the requested PID; reject mismatch, missing, duplicates (equal or conflicting), signs, fractions, junk, unsupported/ambiguous state and duplicate State.
- Exact VmRSS grammar: unsigned ASCII decimal plus literal kB; reject duplicate fields, missing unit, wrong unit/case, signs, non-ASCII digits, invalid separators/extra tokens and bounded huge numeric input according to the reviewed grammar. Do not introduce formatting rejection merely because a synthetic sample differs from procfs spelling.
- Kernel no-mm status: missing VmRSS qualifies as zero only when the entire reviewed memory section is absent; test Z and a supported non-Z exit transition. Missing VmRSS with any memory-section field must reject. Reject malformed/duplicate memory evidence even if another field might suggest exit. Cover all reviewed prefixes/keys, including unfamiliar Vm/Rss-prefixed fields conservatively.
- Ignore unrelated bounded status fields without using them as authority; test Name containing spaces, parentheses and escaped newline/backslash text, plus unrelated lines before/after relevant fields. Unknown relevant field syntax must not be silently treated as no-mm absence.
- Missing file/empty/truncated/reordered relevant records fail or parse exactly as specified. Full input size boundary accepted only if syntactically valid; one byte over rejects. No raw process names or status contents in raised messages.

## 3. Native read and deadline model (mock only; host independent)

Use finite injected/mock os and monotonic operations, not a real process. Assert exact path selection, flags, one bounded acquisition with short-read progress, no statm/stat/cmdline/environment reads, and no spawn/poll/wait/waitid/signal. Do not use reported st_size to skip the read. Confirm regular-file check and fd closure exactly once on success, parser failure, oversize, read/fstat failure, and timeout.

Exercise absent/denied/symlink/nonregular input and OSError propagation without masking; malformed bytes raise the reviewed static ValueError. Short reads may progress on the same fd under the same total byte and time bounds; truncated contents cannot create guessed evidence or a second observation. No file descriptor leaks or success from reused earlier bytes.

Use a clock trace for: already-expired/zero remaining budget before open (no read), expiry during open/read, after read/close, during parsing, and exact equality at the deadline. Successful return requires time strictly before the original deadline. Raise `subprocess.TimeoutExpired` with a static identifier when deadline failure is primary, so the supervisor's existing classification remains valid. Preserve a preexisting I/O/parser/close exception when a later clock check also observes expiry; explicitly check cause/context and operation order. The OS can delay a syscall or scheduling beyond a requested duration: tests prove late results are rejected, not that Python can interrupt every kernel operation precisely at 100 ms.

## 4. Supervisor and cleanup integration models

Keep existing `test_observation_timeout_uses_fresh_work_deadline`, `test_other_observation_failures_at_deadline_preserve_failure`, cleanup model, and all `test_continuous_terminal_probe.py` cases unchanged. Add a bounded native-dispatch variant only where it verifies new behavior: native timeout maps to child_observation_failed before work deadline and deadline afterward; native malformed/missing evidence cannot install a receipt; native memory above the limit still selects memory_limit. Exit evidence must still precede signals and the sole reap; EOF/missing status alone is not exit. Failed cleanup still blocks reuse and cannot be hidden by an earlier observation failure.

## 5. Actual Linux-owned child checks (Linux-gated only)

New tests must use a freshly launched direct test-owned, provider-free child with a short finite lifetime, readiness handshake and unconditional finally termination/reap. No repository worker/factory/database/credentials fixture is needed. Gate only these genuine procfs tests on Linux; mocked parser/deadline/fallback tests run on every supported host.

- Live child: native observation returns nonexit and nonnegative exact integer RSS; prohibit the observer from launching ps or invoking any wait/poll/reap. Current RSS semantics are established by the kernel/procps source qualification and exact synthetic parser cases, not by assuming two asynchronous snapshots have identical RSS.
- Stopped child: owner-controlled SIGSTOP produces supported T/nonexit; always continue/terminate/reap in finally. This makes explicit that stopped is not exited.
- Exited but unreaped direct child: await a positive Z status within a fixed short test deadline without calling poll/wait/waitpid during observation; native observation is exited and zero-RSS no-mm. Assert original Popen returncode is still None, then perform the owner's single final wait and prove the child was available for that reap. Missing status after reap must reject, never synthesize exited.
- Existing real fixture tests continue to cover zombie leader plus live descendants, early pipe EOF, group termination, no destructive signal after reap, and cleanup refusal. No new orphan/foreign-PID destructive operation is authorized.

A macOS-only pass cannot qualify the actual Linux procfs backend. Record genuine Linux skips honestly; exact-revision Linux CI is required before acceptance.

## Ordered validation and acceptance

1. Run architecture before project imports; review parser/no-mm grammar and old ps helper equivalence before source implementation.
2. Focused synthetic new file (suggest `tests/unit/test_continuous_linux_observation.py`), scoped Ruff/format and mypy. Run existing process/terminal/diagnostic tests once after the new tests pass; own-process inspection may need the already established sandbox escalation.
3. After root coordination, run the original fixed-worker restart and lifecycle integration without changing limits or assertions. Do not overlap heavy fixtures.
4. Exact-revision Linux CI runs actual native child cases plus original financial gates; preserve failures, skips, diagnostics and hashes. Passing this unit scope does not close a failed worker or retained lease gate.

Clean commands from the worktree (reuse the verified runtime and sanitized environment documented in TESTING):

```sh
AQT_PYTHON=/Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python
"$AQT_PYTHON" -I -B scripts/check_personal_architecture.py
env -i PATH=/Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin:/usr/bin:/bin PYTHONPATH="$PWD" PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC "$AQT_PYTHON" -B -m pytest -q -p no:cacheprovider tests/unit/test_continuous_linux_observation.py
env -i PATH=/Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin:/usr/bin:/bin PYTHONPATH="$PWD" PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC "$AQT_PYTHON" -B -m pytest -q -p no:cacheprovider tests/unit/test_continuous_process.py tests/unit/test_continuous_terminal_probe.py tests/unit/test_continuous_process_observation_diagnostic.py
```

The proposed new filename matches the standard runner's existing `test_continuous_*.py` selection (`scripts/run_personal_tests.py:121`); no CI selection weakening or new acceptance shortcut is needed.
