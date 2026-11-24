# Independent native Linux observation candidate review

2026-09-27. Reviewed temporary candidate SHA-256 `21a3684d24ad069fa91b98597328bb556ed24614d7231655392daaa355eb322a`, source baseline `0f4f9b925c14d14f4535086d9a05ad8d0d3e9a7b088bde5c712d53f1a57c6517`, and completeness addendum `390266b9ff1024cf59208d95b7ec7c77a5d6979ce0afda479fd535877b58a1aa`. No candidate import, tests, fixture or process observations performed by this reviewer.

**No source blocker to copying this candidate into the repository for the required validation.** This is not test acceptance or evidence of a repaired Linux worker.

The candidate dispatches only Linux to its native helper. The retained ps helper preserves the original body and Darwin state interpretation; the author's static evidence confirms the remaining original module AST is unchanged. No new wait, signal, thread, retry/fallback, persistent PID/descriptor/data cache or authority is introduced.

The native reader uses one fixed supplied deadline. It checks time before open, after open, before and after each bounded read, and after parsing plus descriptor closure. The loop's remaining byte allowance permits exactly one rejection byte, and each nonempty read consumes that allowance. EOF and final newline remain required. A body failure keeps its original exception while still attempting close; successful-body close errors prevent return; a late otherwise successful observation raises the original timeout category. The reader does not claim preemption against a blocked kernel call or scheduler pause.

The parser accepts only exact positive PID, bounded bytes, unique matching Pid/Tgid, original allowed state codes and unique unsigned decimal VmRSS in kB. It returns current RSS, not VmHWM, and zero does not imply exit. Only Z does. Missing RSS is accepted only when the entire recognized optional memory section is absent; partial memory or malformed RSS rejects.

The correction adds a unique bounded `nonvoluntary_ctxt_switches` marker after state/identity/memory fields. That rejects the concrete identity-only or earlier newline-ended prefix the first candidate accepted as no-memory. Later selected fields reject; unrelated architecture-tail rows may follow. This is consistent with the reviewed kernel construction and is explicitly not an arbitrary selective-deletion/forged-procfs attestation.

Required remaining gates are the screen's parser/I/O/deadline adverse cases, the addendum's marker/order cases, unchanged ps tests through the retained helper, Linux live/stopped/unreaped-zombie behavior and original supervisor/group cleanup/worker integration. Native syscall failures, missing files and unknown shapes must remain failures without a fallback. All original memory, pipe, work, cleanup, lease and parent limits remain unchanged.
