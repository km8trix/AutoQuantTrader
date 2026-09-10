# AutoQuantTrader continuation instructions

Planning baseline reviewed 2026-09-08 against code at `107fa79`.

## Canonical documents and location

- The active repository is `/Users/spencer.karrat/Documents/GitHub/AutoQuantTrader`.
- Read `docs/IMPLEMENTATION_PLAN.md` for current work and accepted evidence; read `docs/ARCHITECTURE.md` for the target design.
- Those are the only current plan and architecture. `docs/reviews/2026-09-08-design-review.md` explains the consolidation and static code findings. Historical ADRs/runbooks are scoped implementation records, not competing roadmaps.
- Do not resume the former Phase 2A/2B checkpoint or infer accepted work from an old phase/wave title. Inspect current revision, worktree status and the plan's status table before acting.

## Current handoff

Waves 0/1 closed through GitHub PR #52, merged as ec63ca793ed4fe8a68397dc752000e102741da59. PR CI passed 1,271 Python tests with PostgreSQL plus browser/migration/packaging checks. Root verified the merged tree matches the tested PR and all 140 bound artifacts. Post-merge CI also passed; exact results are recorded in docs/reviews/2026-09-09-wave2/wave1-merged-verification.json.

Wave 2 is complete through GitHub PR #53, merged as 6ea218addaa38d1c36c69b6a7ffbe564d701f834. PR CI passed 1,640 Python tests including PostgreSQL plus browser, migration and installed-wheel process checks. Post-merge CI also passed. Root verified the exact tested/merged tree and all 83 bound artifacts; read docs/reviews/2026-09-09-wave3/wave2-merged-verification.json.

Wave 3 local exit gates passed on codex/personal-v1-w3-integration from that merge. Read canonical plan section 18 and docs/reviews/2026-09-09-wave3/README.md. Actual browser dataset/run/report/comparison, 12 predeclared descriptive trials, independent arithmetic/exports and worker recovery passed. Local checks passed 1,974 Python tests (eight PostgreSQL skips), 139 Vitest and 33 bundle cases, lint/types/contracts/architecture, two identical wheels and actual installed workflow. GitHub PR/CI/review/merge and exact merged-content verification remain required before Wave 4 starts. Preserve W2 accepted evidence and old fixture contracts/history. Root owns shared integration; delegated new DTO/schema/projection ownership is recorded in the plan. At most three additional workers globally; no nested workers. No provider calls or deployment occurred in W3.

The account amendment permits explicitly selected dedicated CASH or MARGIN accounts, while strategy funding remains cash-funded, long-only and without borrowing. Production read traversal passed; sandbox balance identity remains blocked. Currency, liability/restriction/cash semantics, quote rights/freshness, actual quotas, recovery identities and reconciliation remain connected-execution gates. Trading authority is false. W3 implementation is offline research work and requires no provider calls or credentials. Never display keys, tokens, private session paths or provider payloads. Owner authorization for earlier reads does not authorize orders or deployment.

## Working constraints

- Preserve unrelated uncommitted changes and historical evidence. Do not merge or delete old worktrees automatically.
- Keep secrets and private data out of logs, artifacts and Git. Do not read `.env` or private runtime artifacts simply to infer readiness.
- Use repository-owned fixtures for offline tests. Provider requests, new subscriptions, infrastructure activation and live actions require appropriate owner authorization; planning is not authorization for those effects.
- Work on an isolated feature branch for changes. Run checks proportionate to the change, including financial/transactional tests when those boundaries change. Documentation-only planning needs document/link/diff checks, not service startup or the entire trading suite.
- The owner requests a standing end-of-wave workflow: after all wave exit gates pass, commit the reviewed in-scope changes, push the feature branch, open a GitHub PR, satisfy required CI/review checks, merge through GitHub, verify the merged revision, and start the next eligible wave through this orchestration task. No repeated approval is needed for this workflow. Preserve unrelated work and do not bypass branch protection, force-push, or treat an incomplete wave as closed. Trading/deployment remain separately scoped; CI, restart or code merge cannot enable them.

## Accepted evidence and limits

W1 integrated gate: 1,264 Python tests passed, 7 PostgreSQL tests skipped; Ruff format/lint, mypy 291 files, API contracts, standard architecture and Compose model passed. Two standard wheel builds were byte-identical; installed CLI start/duplicate/SIGTERM/restart behavior passed outside the checkout. The real 20-bar Tiingo sample remains exploratory current-vintage data with explicit 20:00 ET historical-availability assumptions, not PIT or full-study-period evidence. W0 frozen contracts/old worktree history remain unchanged; the dated amendment supplies the current account scope revision.

No financial schemas/migrations, deployed resources, native lifecycle or trading changed. Browser code is unchanged; W1 PR CI passed the browser regressions. The previous .venv launcher remains preserved/broken; use the runbook's separate environment or exact temporary verification environment in evidence. OAuth daily expiry is conservatively 2026-09-10T04:00:00Z with a two-hour idle admission window. Never rewrite activity times to prolong access. New supervised renewal publishes a private reference and preserves original issuance and expiry.
