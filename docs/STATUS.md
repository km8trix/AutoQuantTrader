# Current status

Updated 2026-09-27. Read [SPEC](SPEC.md), [PLAN](PLAN.md), [TESTING](TESTING.md)
and the [evidence index](reviews/2026-09-26-autonomy/README.md).

- **Current milestone:** A2/A2.1 remain open; A2.3's attempt-proof pilot remains
  unaccepted. A2.7 and A2.8 have passed applicable local gates, with exact-source
  Linux acceptance pending. A0/A1 and A3's offline scope are complete. Wave 4
  remains incomplete.
- **Current task:** publish the reviewed changes and inspect the new revision's
  Linux results. The bounded procfs reader replaces only Linux's per-call ps
  subprocess; other platforms keep ps.
  Original observation deadlines, current RSS, Z-only exit, sole reap, group
  cleanup and receipt rules remain. Review corrected truncated-record and
  malformed-key gaps before the implementation was integrated.
- **Checkout/publication:** `codex/autonomous-development` in
  `Documents/AutoQuantTrader/autonomous-development`. Local commit `9f9cd72`
  contains A2.7 and test isolation; `7ac47bb` contains A2.8.
  [Draft PR #56](https://github.com/km8trix/AutoQuantTrader/pull/56) targets W4
  integration. Its last verified published head was `071dd5c`; inspect Git/PR
  synchronization before resuming publication. PR #55 targets `main`;
  neither may merge here. Preserve the separate integration checkout's existing
  architecture edit. New production changes are confined to primitive admission
  in `personal_contracts.py` and Linux observation in `continuous_process.py`;
  all other production remains at `2a9fc2c`, scripts/CI at `26631c6`.
- **Completed A2.8 locally:** 188 new cases pass; three real Linux procfs cases
  skip on this Mac and must execute in CI. All 114 existing process regressions
  and 19 original worker/lifecycle cases pass. Architecture, full Ruff/format
  (1,036 files), mypy (421 files) and API drift checks pass. Independent source
  reviews bind the final implementation. [Local evidence](reviews/2026-09-26-autonomy/linux-native-local-validation.json).
  Darwin worker passes do not qualify native Linux behavior.
- **Completed A2.7 locally:** 83 new oracle cases and 744 existing contract/
  financial cases pass. The unchanged retained test and cleanup pass in 221.51 s,
  with restore at 39.764 s; 19 original worker/lifecycle cases pass. This is not
  a paired speedup measurement. [Source-bound checkpoint](reviews/2026-09-26-autonomy/contract-primitive-local-validation.json).
  The first integration selection had 172 passes/two failures from earlier
  copy tests leaking stdlib class-cache metadata. Three test-only sites now
  restore that metadata; five unit and five ordered integration cases pass.
  The production guard remains strict; [failure and correction](reviews/2026-09-26-autonomy/contract-copy-isolation-correction.json)
  are both retained.
- **Known Linux failures:** old-head [run 36297439151](https://github.com/km8trix/AutoQuantTrader/actions/runs/36297439151)
  on `071dd5c` has completed all 16 financial shards: 4,962 passes/five
  failures/no skips. Its separate diagnostic was still running at this checkpoint.
  [Completed matrix](reviews/2026-09-26-autonomy/linux-071dd5c-financial-final.json)
  preserves the earlier partial observations.
  The worker's second iteration records a ps `TimeoutExpired` at a requested
  0.1 s; it is deliberate fail-closed handling, not the former terminal race.
  [Worker trace](reviews/2026-09-26-autonomy/linux-071dd5c-shard3-failure.json).
  Positive original proof and original retained restore expire at 61.224/60.035 s,
  each also failing lease cleanup. [Retained traces](reviews/2026-09-26-autonomy/linux-071dd5c-retained-failures.json).
  Shard 15 adds retired-proof lease expiry at 61.087 s and a test-only cleanup
  handshake that masks the original supervisor failure. The hook is now
  isolated from cleanup; all 20 worker/lifecycle cases pass locally, including
  the injected-failure regression. The old underlying
  failure remains unknown. [Shard 15 trace](reviews/2026-09-26-autonomy/linux-071dd5c-shard15-failure.json).
  Last complete [55951fb run](reviews/2026-09-26-autonomy/linux-55951fb-ci-failure.json)
  had 4,965 passes/two failures; its diagnostic also failed. All older failed
  evidence remains preserved. A passing repeat alone is not a repair.
- **Closed investigations:** A2.4 measured 2.1675 s of daily builder work. A2.5's
  per-node proof layout exceeds existing shared caps and is rejected. A2.6's
  CLOCK-only reuse candidate is rejected: 8.204 ms of repeated work in a 44.155 s
  original execute does not justify the new machinery. No production witness or
  reuse substitution was implemented. [Study disposition](reviews/2026-09-26-autonomy/prelease-study-disposition-review.md).
  Other representations remain untested; do not repeat or broaden rejected
  experiments without a concrete new source-backed question.
- **Next actions:** update/push PR #56 under existing authorization if not already
  synchronized, and validate its exact revision
  on Linux, including all three actual procfs cases and original financial gates.
  Preserve prior CI as completed or incomplete according to actual observations.
  Fix new failures before dependent work; continue the next concrete unblocked
  task. Do not infer permission for renewal, larger caps or longer timers.
- **Blockers:** A2's Linux acceptance still fails. A4 separately needs the
  supervised Mac's measured-time source and non-secret qualification record,
  then review of the [genuine producer contract](reviews/2026-09-26-autonomy/capture-bridge-contract.md).
  Preserve [existing rights/retention approvals](reviews/2026-09-10-wave4/recovery-2026-09-20.md).
  Current OAuth/window and initializer approval remain separate; never request
  or use production credentials for testing.
- **Authorization:** branch push/draft PR, bounded offline attempt-proof pilot,
  daily-identity feasibility and A2.6's offline study are approved. That study
  approval does not authorize production adoption or lease renewal. No merge,
  provider/live/initializer/deployment or recurring automation authority exists.
  Ordinary reviewed behavior-preserving engineering continues autonomously.

Verified Python: `Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python`.
Use TESTING's clean environment. Original applicable 60/120/150-second retained
bounds, worker bounds, resource caps and fresh validation remain unchanged. No
provider calls, real orders, account initialization or deployment occurred.
