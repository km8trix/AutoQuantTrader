# Bounded worker timeout location metadata — 2026-10-11

Public `1382752` [CI run 38121952457](https://github.com/km8trix/AutoQuantTrader/actions/runs/38121952457)
fails shard3's original worker restart assertion with `child_observation_failed`.
The existing diagnostic reports iteration2/call18,43 calls/42 returns/one
TimeoutExpired,213556818ns aggregate observation wall time for a0.1s request.
That does not establish which native check rejected or why the delay occurred.
The remaining matrix must finish before a further publication can replace it.

This change adds optional test-only binding to the unchanged Linux observer's
code. After the original ending clock sample, an exact TimeoutExpired may supply
one `deadline_check_line_offset` in the first failure. Admission requires the
adjacent original observer/check code identities, a complete scan of at most8
traceback frames and an offset0–4095. Binding inspects at most32 immediate code
constants and requires one check code. Static code identities and the scalar
offset survive; exceptions, tracebacks, frames, messages, commands, paths,
payloads, causes and contexts do not. Failed binding clears both identities.
Malformed or exhausted metadata sets overflow and omits attribution without
replacing the original error. Unknown/unbound/foreign cases keep the old shape.

At unchanged observer Source332, mocked native rejection sites have offsets15
(entry),21(after open),26(before read),28(after read),43(after parse and close).
An offset identifies a rejecting check, not the operation that consumed time.
Do not infer syscall, scheduler, parse or ownership causation from it.

The worker changes only its diagnostic constructor keyword. All original
financial, restart, receipt and cleanup assertions remain. Production observer,
supervisor, clocks,100ms deadline, descriptor/byte bounds, retries and authority
are unchanged. The [manifest](source-manifest.json) binds the three test paths;
CI/runner/configuration/lockfiles/migrations are unchanged.

Architecture before imports and configured three-file Ruff/compilation pass.
The diagnostic run passes52 cases (19 unchanged plus33 new); the separate
process/Linux observer run passes270 with3 actual-Linux skips on macOS,273 cases.
All five bounded checks have both EOF, unchanged selected pins and no timeout,
overflow or reap failure. See [selected facts](validation-summary.json) and
[portable commands](../../TESTING.md). These are distinct runs, not Linux or
original worker acceptance.

A preparation regression exposed exception/frame/payload retention; its failed
one-case baseline and passing unchanged retest remain preserved. The first local
process run retains21 failures consistent with denied Darwin ps inspection;
unchanged tests pass with process inspection permitted. Its wrapper also exceeded
the report cap before saving the native result. Exact JUnit is retained; missing
fields are unavailable. The corrected wrapper saves native output separately,
without increasing child/raw/report/reap limits or weakening tests.

Independent Source review passes; actual-result review passes. A local focused
checkpoint precedes any publication. A later exact-source CI run answers the new
rejection-location question only if the failure occurs; a pass cannot prove a
timing remedy. Preserve every original matrix result before selecting that run.
No retained-study replay, changed lease/risk limit, provider/initializer/live,
merge or deployment is authorized by this diagnostic.
