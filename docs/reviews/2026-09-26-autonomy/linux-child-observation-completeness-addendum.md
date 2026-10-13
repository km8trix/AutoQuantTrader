# Linux child observation completeness correction

2026-09-27. This addendum supersedes the original screen's assumption that bounded EOF plus State/Pid/Tgid alone establishes a sufficiently complete no-memory record. Preserve the original screen and first static-check artifact as historical evidence.

The first temporary candidate accepted a newline-terminated identity-only prefix as resident memory zero. Parent review identified this concrete gap before integration. No production change or test result depended on that candidate.

In Linux 6.8, `proc_pid_status` emits state/identity, the optional memory block, then generic sections ending in `task_context_switch_counts`; this emits `nonvoluntary_ctxt_switches` before optional architecture fields. See [primary kernel construction](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/proc/array.c), lines 377–382 and 416–440.

The revised finite grammar requires exactly one such marker with a single unsigned decimal token of at most 20 digits. State/Pid/Tgid and any memory rows must precede it; selected rows after it are rejected. Unrelated fields may remain in their existing relative ordering and unrelated architecture fields may follow. The marker's numeric value grants no authority and never changes state or RSS interpretation. Complete no-memory S remains nonexit; only Z is exit.

This rejects the concrete identity-only and pre-marker prefixes, including prefixes containing VmRSS. Bounded EOF, final newline, single descriptor and unchanged deadline remain necessary. It does not attest against selective line deletion or forged procfs, nor prove that optional architecture tails are complete. Those are outside the existing trusted-kernel observation context.

Required test additions: missing/truncated/duplicate/malformed marker, exact decimal length boundary, marker before selected fields, selected fields after marker, and permitted unrelated architecture tail. The test owner is preparing them separately. No imports, tests, subprocess observations or timing runs were performed by the candidate author.

Source SHA256: `0f4f9b925c14d14f4535086d9a05ad8d0d3e9a7b088bde5c712d53f1a57c6517`.
Revised candidate SHA256: `21a3684d24ad069fa91b98597328bb556ed24614d7231655392daaa355eb322a`.
Original screen SHA256: `d5ec4e45b00ede0a63fb8bb2f9b69d5af4c18080f1bffbe3d96abe045b5f2613`.
Static AST-preservation/compile evidence: `linux-child-native-static-check-v2.json`.
