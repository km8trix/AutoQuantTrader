# Current status

Updated 2026-10-11. Read [SPEC](SPEC.md), [PLAN](PLAN.md), [TESTING](TESTING.md)
and the [repair record](reviews/2026-10-11-restore-string-pairs/README.md).
Use Git and exact-revision CI for actual HEAD and gate state.

- **Current milestone:** Wave 4 integration acceptance remains open.
- **Current task:** publish the corrected canonical string-pair repair and qualify
  its automatic exact-source Linux/PostgreSQL gate.
- **Completed work:** corrected-source local validation passes 470 distinct cases
  (344 encoder/semantic/codec, 8 original retained/proof, 118 account/factory/admission),
  zero failures/errors/skips. Architecture, configured Ruff, Linux-platform mypy
  (421 files) and API contracts pass. The corrected shortcut preserves the original
  five per-item appends and passes three new formatting-result lifetime regressions.
  All previous 24 pair cases and the literal preceding oracle remain unchanged.
  Original retained/proof tests and their financial/venue/cleanup assertions are unchanged.
- **Work in progress:** reviewed public assembly and exact Linux acceptance. The
  original 60-second lease, 120-second restore alarm and risk controls remain intact.
  Successful local restores print45.360s retained,45.242s original proof and46.303s
  retired; five injected negative cases still reject. These are local observations.
- **Known failures:** the initial combined-fragment candidate a78d6b9 passed467
  local cases but fails three subsequent legitimate lifetime regressions. It retains
  the first custom formatting result through the second lookup, changing events,
  bytes or exception behavior; that source is rejected. Its CI positives concern
  that source only. Earlier1821d78 CI38161407124 failed two original lease tests
  (62.320s retained/60.536s retired), with5699 other financial passes. Both failures
  and passing historical observations remain preserved separately.
- **Blockers:** exact corrected-source Linux acceptance; original Wave4 financial,
  worker/capacity/genuine/parent gates; source/account/session/host qualification
  and separate initializer/adoption approval. CAPTURE_GENUINE_SOURCE_BRIDGE_REQUIRED
  remains. No owner location is missing.
- **Next actions:** review and normally publish only the focused public descendant;
  qualify its automatic completed logs, investigate failures and update this file.
  No manual CI retry, consumed-study replay, limit increase or dependent merge.
- **Checkout:** explicit ownership-checkpoint-publication on
  codex/ownership-checkpoint-publication, corrected descendant ofa78d6b9.
  Approved destination is remote codex/autonomous-development and existing
  [draft PR56](https://github.com/km8trix/AutoQuantTrader/pull/56), baseb1156ba.
  Private evidence uses a separate local branch; never merge or push its history.

The repaired synthetic benchmark preserves six workloads' literal bytes. Pair
medians improve28.23%/26.54%; nonpair tuples regress2.44%, scalar strings0.42%.
These observations establish no whole-restore, Linux or universal speedup.
Original tests, workflows, configuration, migrations and risk limits are unchanged.
Development stays offline/HALTED, trading authority false. No broker/provider
request, production credentials, retained operational initialization, real
orders/positions/funds, risk increase, merge, deployment or automation follows.
Preserve lease60s/alarm120s, worker30s wall/CPU/512MiB, parent29.25s+.75s cleanup,
native observer100ms and probe freshness500ms. Read [DECISIONS](DECISIONS.md)
and [ARCHITECTURE](ARCHITECTURE.md) before changing these boundaries.
