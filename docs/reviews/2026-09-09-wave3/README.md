# Wave 3 — durable research workspace

Status: local exit gates passed; GitHub PR/CI/merge verification remains open. Wave 4 starts after the verified merge.

The [accepted-content manifest](accepted-content.json) binds the reviewed source, tests, documentation and sanitized evidence. Its own hash and the exact tested/merged tree are verified separately during GitHub closeout.

Base: `6ea218addaa38d1c36c69b6a7ffbe564d701f834`, verified Wave 2 merge via [PR #53](https://github.com/km8trix/AutoQuantTrader/pull/53). [Merged verification](wave2-merged-verification.json) binds the tested/merged tree, 83 accepted artifacts and successful PR/post-merge CI. PR CI passed 1,640 Python tests including PostgreSQL, browser, migrations and installed-wheel process checks.

Current scope: immutable actual-engine research jobs, private content-addressed inputs/reports, fenced recovery/cancellation, descriptive evaluation and the research UI. Existing fixture records and financial schema history remain preserved. The fixed reference strategies have no learned parameters. Known-accessed/unknown history is never described as untouched. Actual provider calls, trading and deployment are not part of current implementation.

## Exit evidence

| Gate | Evidence and scope |
|---|---|
| Select dataset → run → report → comparison | [Actual browser acceptance](browser-acceptance.json): real Tiingo sample base/adverse reports, queued cancellation, final-build synthetic trial reports and compatible cost comparison; 319px and desktop layout checks |
| Independent economics | [Three retained reports](independent-reports.json), including 268 synthetic scored returns with Decimal80 annual checks; [all 12 final trials](final-browser-experiment-completed.json) independently checked with exact rational arithmetic and export-byte bindings |
| Evaluation protocol | [Browser declaration before execution](final-browser-experiment-queued.json), [actual worker](final-browser-experiment-worker.json), and [exact windows/costs](final-browser-experiment-windows-costs.json): three independent chronological windows × four declared cost models, no-fit reference, prior access, no winner and suitability `not_assessed` |
| Recovery and publication | [Actual parent termination/restart](worker-recovery.json): child retains ownership until exit, real lease expiry, two attempts and one publication; source regressions cover cancellation, fencing, controlled abandonment and phase-specific termination |
| Read/write coexistence | [Five simultaneous lanes over retained history](read-contention-wal-accepted.json) complete three rounds, with unchanged leases/timeouts and original database preserved; [38 WAL regressions](sqlite-wal-validation.json) include restart, backup and rejected initialization |
| Conventional installed package | [Byte-identical wheels](wheel-checks.json), [468 source bindings](wheel-source-bindings.json) and [actual installed workflow](installed-workflow.json): 43 unchanged locked dependencies, verified module origins/RECORD, economics and idempotent restart |
| Browser and static quality | [139 Vitest and 33 bundle cases](frontend-validation.json), [96 frontend source hashes](frontend-source-hashes.json), [Python lint/types/contracts/architecture](static-checks.json), and [independent review](independent-review.json) |
| Integrated regressions | [1,974 Python tests passed](local-checks.json), eight PostgreSQL tests skipped locally; [sanitized output](check-output/personal-suite.txt) and [unchanged source pins](source-freeze.json). PostgreSQL execution remains a GitHub CI gate. |

The five-session real sample remains exploratory current-vintage evidence, with four scored sessions and an explicit following execution horizon. Synthetic histories demonstrate engineering behavior. Neither source establishes an untouched holdout, empirical liquidity, investment suitability or permission to trade. Annualized metrics remain undefined when their required history is absent.

The final source-worker experiment completed all 12 trials in 48.944 seconds, with one attempt and publication each. All three earlier registries and 36 cancelled unexecuted trials remain retained, along with the three earlier completed reports. Their source pins are not rewritten. Source checkout and installed wheel retain distinct actual-source pins because the wheel preserves its explicit legacy native-helper exclusion; each acceptance record binds the bytes it actually ran. API and worker installations must use the same build.

The [research runbook](../../runbooks/personal-v1-research.md) covers explicit local setup, imports, process limits, cancellation/restart, exports, SQLite runtime/filesystem requirements and consistent database/object backups. New infrastructure, provider access, order execution and deployment are outside this wave. GitHub checks must run the PostgreSQL cases and released-wheel process checks before merge.

## Supporting checks

- [Independent report arithmetic](independent-reports.json) covers two real-sample reports and the 520-session synthetic recovery report. Rational and 80-digit calculations independently check reported economics. These reports retain their original earlier build pins.
- [Actual worker recovery](worker-recovery.json) records parent termination, child ownership, real lease expiry and one eventual publication across two attempts.
- [Frontend validation](frontend-validation.json) and [source hashes](frontend-source-hashes.json) bind 139 browser unit cases, 33 bundle-policy cases, type/lint/build checks and the measured production bundle.
- [Independent review](independent-review.json) and [static checks](static-checks.json) identify their checked source snapshots; newer source changes require a refreshed final record.
- [Workflow snapshot checks](workflow-snapshot-checks.json) bind ordered batch reads, event bounds and writer-commit regressions. [SQLite WAL validation](sqlite-wal-validation.json) covers 38 operating-mode, restart, backup, caller-scope and rejection cases. The [accepted five-lane workload](read-contention-wal-accepted.json) completes all three overlap rounds over the retained history without changing leases/timeouts or the original database.

## Integration failures and successive checks

The initial getter fix passed a smaller concurrent workload, but the stronger retained-history workload still exposed commit blocking. The records below preserve that distinction. None of the intermediate timing checks establishes the final exit gate.

- [Initial failure](pre-fix-read-contention.json), [first cancelled registries](pre-fix-trials-preserved.json), [smaller first-fix check](read-contention-first-fix.json), and [actual worker commit failure](read-contention-commit-failure.json).
- [Snapshot negative control](read-snapshot-negative-control.json), [readiness snapshot regressions](readiness-snapshot-checks.json), and [remaining transaction work before batching](read-contention-before-batching.json).
- [Batched readiness checks](readiness-batched-checks.json), [query counts](readiness-query-count.json), [dependency preloading checks](readiness-preload-checks.json), and [remaining DELETE-journal failure](read-contention-after-preloading.json).
- [Third stale-build registry preservation](stale-build-trials-preserved.json) records 12 further explicit owner cancellations with zero attempts/publications, preserving all earlier reports and registries before the final build's browser registration.

All private input bytes, provider credentials, local provider paths and full report artifacts stay outside this evidence directory. Disposable concurrency copies of the retained acceptance database preserve the original; cancelled trial records and earlier report identities are not rewritten.
