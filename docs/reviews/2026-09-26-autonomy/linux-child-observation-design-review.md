# Independent Linux child-observation design review

2026-09-27. Read-only review of the design screen, original source/tests and primary kernel/procps source. No project imports, tests, process observations, source edits or fixture runs.

**No blocker to the proposed narrow implementation.** This approves the design for implementation and adverse validation, not acceptance of unimplemented code or a claim that the original Linux worker failure is repaired. The renewal contingency remains separate and unapproved.

The existing adapter returns only `exited` and current resident bytes. Linux `/proc/<pid>/status` can supply those values without a new observation subprocess. The current supervisor still decides timeout/failure at `continuous_process.py:644–665`, enforces the same memory threshold, and requires the original post-exit lifecycle result. The process remains unreaped through final group signals and is reaped only by `_terminate_owned_child:270–333`. No proposed change needs a new authority token, retry, limit extension, wait/poll, or group-cleanup exception.

I independently checked Linux 6.8 `proc_pid_status`: it obtains `mm` before writing task state, omits the memory section when `mm` is absent, and escapes the task name's newline. Thus a valid non-Z no-memory transition must remain non-exited with zero RSS; Z is the sole accepted exit code. [Kernel source](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/proc/array.c).

Procps 4.0.4 maps VM_RSS to status data; `status2proc` assigns both state and current RSS. This supports the chosen native sample, not an assertion of the CI binary's version or equality with a later sample. [Procps item selection](https://gitlab.com/procps-ng/procps/-/raw/v4.0.4/library/pids.c), [status parser](https://gitlab.com/procps-ng/procps/-/raw/v4.0.4/library/readproc.c).

Implementation acceptance conditions already required by the screen:

- Define the finite no-memory predicate explicitly. Missing RSS is zero only after a complete, bounded, valid status record with no recognized memory section. Missing/denied/empty/oversized/truncated reads, partial memory fields, duplicate or malformed RSS, PID/Tgid mismatch and unknown state remain failures. Absence or zero never proves exit.
- Preserve the original accepted state policy, including rejection of lowercase `t`, `X` and `P`. Preserve Darwin's existing ps grammar and `?E` non-exit handling. Move old ps parser cases to the explicit ps helper rather than weakening or deleting them; add independent dispatch tests.
- One fixed deadline includes open, bounded partial-read progress, parsing and descriptor cleanup. Exhaustion before open prevents acquisition; equality after close cannot return success. Preserve an existing I/O/parser error rather than replacing it with the final timeout. Every acquired descriptor must close, including rejected records and read/parse failures. No fallback or fresh timeout is permitted.
- The 16 KiB status bound follows the repository's procfs precedent and does not change child pipe, memory, work, cleanup, lease or parent bounds. Native calls cannot preempt an indefinitely blocked kernel call or a scheduler pause; the module already excludes the former, and late successful work must be rejected rather than called a hard real-time guarantee.
- Retain genuine Linux live/stopped/unreaped-zombie and original worker coverage, plus the existing descendant/group absence, sole reap, Stop, memory and deadline tests. Parser success alone does not establish worker acceptance.

The design does not claim the observed TimeoutExpired identifies only subprocess startup. Removing that subprocess is a concrete way to eliminate its creation/communication/reaping from each observation; remaining scheduler, process, SQL and lease failures still require their own evidence.

Reviewed SHA-256 values:

```
d5ec4e45b00ede0a63fb8bb2f9b69d5af4c18080f1bffbe3d96abe045b5f2613  linux-child-observation-design-screen.md
0f4f9b925c14d14f4535086d9a05ad8d0d3e9a7b088bde5c712d53f1a57c6517  packages/application/continuous_process.py
4eaba660713d3161e3e4c94e713e1b4dbbb8dcd127407fe791db7457e181f668  tests/unit/test_continuous_process.py
8f44671bcf03d962f78491ef09a07abdcd7f73e94602468c39b63f7f0bbdbea5  apps/worker/personal_research.py
```
