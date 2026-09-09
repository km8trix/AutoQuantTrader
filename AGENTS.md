# AutoQuantTrader continuation instructions

Planning baseline reviewed 2026-09-08 against code at `107fa79`.

## Canonical documents and location

- The active repository is `/Users/spencer.karrat/Documents/GitHub/AutoQuantTrader`.
- Read `docs/IMPLEMENTATION_PLAN.md` for current work and accepted evidence; read `docs/ARCHITECTURE.md` for the target design.
- Those are the only current plan and architecture. `docs/reviews/2026-09-08-design-review.md` explains the consolidation and static code findings. Historical ADRs/runbooks are scoped implementation records, not competing roadmaps.
- Do not resume the former Phase 2A/2B checkpoint or infer accepted work from an old phase/wave title. Inspect current revision, worktree status and the plan's status table before acting.

## Current handoff

Wave 0's frozen contract/baseline gate and Wave 1's bounded A/B/C foundation/read-feasibility gates passed. Current task must finish the authorized GitHub closeout before starting Wave 2 from the verified merged revision. Read the canonical plan section 16 and docs/reviews/2026-09-08-wave1/wave1-acceptance.md for exact acceptance and limits.

The owner authorized revising cash-only account eligibility. Apply docs/contracts/personal-v1/account-eligibility-amendment.md alongside the unchanged W0 pack: an explicitly selected dedicated account may have CASH or MARGIN privileges, while the strategy remains cash-funded, long-only and without borrowing. Production completed fresh discovery, balances, portfolio, current orders, bounded order history and activity. Initial no-content responses remain unreconciled observations. Sandbox balance identity still fails. USD, financing/liability/restriction semantics, quote rights/freshness, quotas, retention and usable recovery identities block connected execution; all trading authority remains false.

The reviewed base is 107fa791bb52e9fa42cbce65992ea1ce9168834e on codex/personal-use-planning-20260908. W0/W1 changes await commit/PR/merge. This is the sole orchestrator; three W1 workers completed in isolated worktrees. Root owns shared schemas/migrations/composition/build/CI, with at most three additional workers globally. Preserve all historical worktrees.

The owner authorized bounded Tiingo reads via TIINGO_TOKEN and E*TRADE sandbox/production read-only qualification through explicitly named .env references. Helpers may load exact named values internally; never cat/source/log credentials or expose values to the model. Owner OAuth and supervised renewals succeeded; private session references remain outside Git. Do not infer session/account/trading authority from credential presence or repeat provider calls without a concrete need. Published evidence contains metadata only; private real data remains outside Git.

## Working constraints

- Preserve unrelated uncommitted changes and historical evidence. Do not merge or delete old worktrees automatically.
- Keep secrets and private data out of logs, artifacts and Git. Do not read `.env` or private runtime artifacts simply to infer readiness.
- Use repository-owned fixtures for offline tests. Provider requests, new subscriptions, infrastructure activation and live actions require appropriate owner authorization; planning is not authorization for those effects.
- Work on an isolated feature branch for changes. Run checks proportionate to the change, including financial/transactional tests when those boundaries change. Documentation-only planning needs document/link/diff checks, not service startup or the entire trading suite.
- The owner requests a standing end-of-wave workflow: after all wave exit gates pass, commit the reviewed in-scope changes, push the feature branch, open a GitHub PR, satisfy required CI/review checks, merge through GitHub, verify the merged revision, and start the next eligible wave through this orchestration task. No repeated approval is needed for this workflow. Preserve unrelated work and do not bypass branch protection, force-push, or treat an incomplete wave as closed. Trading/deployment remain separately scoped; CI, restart or code merge cannot enable them.

## Accepted evidence and limits

W1 integrated gate: 1,264 Python tests passed, 7 PostgreSQL tests skipped; Ruff format/lint, mypy 291 files, API contracts, standard architecture and Compose model passed. Two standard wheel builds were byte-identical; installed CLI start/duplicate/SIGTERM/restart behavior passed outside the checkout. The real 20-bar Tiingo sample remains exploratory current-vintage data with explicit 20:00 ET historical-availability assumptions, not PIT or full-study-period evidence. W0 frozen contracts/old worktree history remain unchanged; the dated amendment supplies the current account scope revision.

No financial schemas/migrations, deployed resources, native lifecycle or trading changed. Browser code is unchanged; W0 browser results are historical until remote CI runs. The previous .venv launcher remains preserved/broken; use the runbook's separate environment or exact temporary verification environment in evidence. OAuth daily expiry is conservatively 2026-09-10T04:00:00Z with a two-hour idle admission window. Never rewrite activity times to prolong access. New supervised renewal publishes a private reference and preserves original issuance and expiry.
