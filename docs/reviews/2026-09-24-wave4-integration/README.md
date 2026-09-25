# Wave 4 integration checkpoint — September 24, 2026

This checkpoint adopts the reviewed continuous-simulation implementation into the Wave 4 feature branch so the exact integrated revision can run through Linux CI. Wave 4 is still in progress and the PR remains a draft.

The source is the frozen R13g candidate, manifest SHA-256 `c44eb28c73213d449e401d1a451959ca12291c900549e4b960606467af26387c`. The adoption comprises 249 source, migration, test and CI files (222 new and 27 modified) over the verified Wave 3 merge `e1bcea18eaa18ad144bc3b03a4891d11ecdd9b06`. Existing canonical plan, architecture and historical evidence are preserved rather than overlaid with older candidate copies. `source-adoption.json` binds each selected file and its original target hash or absence. Root freshly rehashed all 1,605 candidate files and 1,183 accepted correction evidence files before adoption.

## Behavior

The implementation connects the existing economic engine to durable continuous account checkpoints, daily risk and attempt history, independent stateful venue observations, and applied reconciliation. Account publication retains original source, lease, deadline and Stop checks. Forward observations are retained through bounded source-aware capture and replay interfaces. The fixed supervised worker remains HALTED restore/integrity only; initialization and an active strategy launcher are separate acceptance work.

CI splits the existing personal regression profile into 16 deterministic shards, with at most four concurrent jobs. Foundations, real PostgreSQL migration checks, installed-wheel/process checks and browser checks remain required. The existing aggregate check rejects a failed or skipped dependency.

## Existing validation and its limits

The original full macOS profile accounted for all 4,292 cases: 4,281 passed, ten failed and one Linux-only case skipped. Five test-only corrections subsequently passed all 43 affected and guard cases (129 phases). The final formatting-only change preserves the complete test AST, and formatting/lint passed. The original failed full run remains failed; this is not a new all-green full R13g run. All 23 PostgreSQL cases passed in the original profile.

R13d packaged source and controlled build inputs are identical to R13g: all 558 wheel-projection files match, and two earlier wheels were byte-identical (`8b4ba3d299cb5c2d8fe2f13f69f93c118c22d3f44308b04e682ae816b7c34f6e`). Installed HALTED first run and restart passed on the same retained synthetic history under the original 60-second lease, 120-second worker and 150-second parent limits. These remain historical checks on identical packaged bytes, not fresh Linux or active-worker results.

The September 20 Tiingo technical sample returned four HTTP 200 responses for DIA/IWM/QQQ/SPY over September 14–18: twenty rows and all thirteen required fields. A separate credential-free offline reload reproduced the same capture and qualification hashes. This establishes current-vintage access and retention/reload only, not full captured-session decision parity or point-in-time history. Raw licensed responses and credentials remain outside Git.

## Remaining acceptance

- Actual CI on this integrated revision, including Linux-only behavior and PostgreSQL concurrency.
- Actual authorized captured-session replay with identical decisions and complete stateful-session acceptance.
- Fresh production OAuth and the separately bounded E*TRADE quote/account reconciliation checks; historical authorization and retention approval remain valid, while prior sessions and the September 21 window have expired.
- Specific owner approval, adaptation and qualification of the local simulation initializer; no initializer operation is part of this checkpoint.
- Final review, evidence binding and the authorized end-of-wave merge and exact merged-revision verification before Wave 5.

No orders, deployment, trading activation, account initialization or provider requests are performed by applying this source checkpoint. CI uses disposable fixtures and service databases.


### September 24 offline adapters and Linux CI finding

Draft PR [#55](https://github.com/km8trix/AutoQuantTrader/pull/55) is open at the integrated baseline `47fab9c32108151e1d98a5e636579a22cb86813c`. The optional Chrony-to-StandardClock conversion passed 53 offline cases, format/lint/types and the architecture boundary check. Local original-binding checks for both capture HTTP adapters passed 85 cases, including four unchanged no-effect publication/source guards. [Adapter evidence](offline-adapters.json) binds the exact source and independent review. These additions do not qualify a host clock or admit genuine captures.

The first Linux CI run exposed a retained-history startup failure: integrity verification exceeded the original 60-second lease at 60.190 seconds, followed by a separate lease-release cleanup failure. The failed result remains failed; source performance work is isolated and the lease limit is unchanged. Foundations, migrations, installed-wheel and browser jobs passed, while the full regression gate remains unresolved. The September 24 quote window expired without fresh OAuth or a provider request. Initializer approval, actual source ownership/captured-session replay and provider/account qualification remain open. Wave 4 is incomplete and no merge or Wave 5 start is authorized by these component passes.


### September 24 retained conversion correction

The baseline Linux run completed with 4,291 passed, one failed and zero skipped tests. The single retained-factory failure exceeded the unchanged 60-second lease; the failed run remains recorded. Two narrow conversion changes now dispatch exact built-in tuples and scalars before redundant dataclass reflection, preserving bytes hashing, mapping precedence, subclass behavior and all existing source, SQL and lease checks. The focused qualification passed 284 cases (76 new and 208 existing), plus formatting, lint and type checks.

A finite synthetic benchmark verified all 768 outputs and measured lower converter costs on that fixture only. One fresh copy of the existing synthetic C12 history then restored successfully in 43.601 seconds with the original 60-second lease, 120-second operation and 150-second parent limits. Financial records, source artifacts and independent venue data were preserved, and owned cleanup passed. This is a local restore result, not a startup performance comparison or Linux acceptance. Bounded static code locations were added to the existing CI failure reporter without changing its test, lease or timing logic.

The correction is ready for a new exact-head CI run on draft PR #55. The updated suite is expected to contain 4,416 cases. Actual captured-session replay, scoped provider/account qualification, the separate initializer approval and final CI/review/merge remain open. No provider request, initialization, order or deployment occurred.

[Correction evidence](pure-dispatch.json) binds the source and independently reviewed results.


### September 24 imported-calendar consistency prerequisite

A new opt-in helper compares a capture request with the exact imported research-calendar pin and session open/close values. It uses the existing Tiingo projection, including string session kinds and the personal America/New_York calendar constraint. The caller must explicitly choose that digest convention. Equal copied content can pass this check and does not confer source authority. The genuine-source admission guard and all existing capture behavior remain unchanged.

All 106 focused cases passed: 44 new calendar cases and 62 existing capture/import/publication guard cases. Formatting, lint, types and the architecture boundary also passed, with source/runtime and owned cleanup checks. Synthetic cases cover winter/summer offsets, half days, missing sessions and nested mutation. This completes a mechanical prerequisite; it does not qualify a real calendar, clock, provider or captured session. The implementation is held locally while the already-running correction CI finishes, so that run continues to test its original exact commit.

[Calendar qualification evidence](capture-calendar.json) records the exact scope and bindings.


### September 25 canonical fragment assembly correction

The latest Linux run completed with 4,415 passed and one retained-restore failure at the unchanged 60-second lease. The failed run and separate cleanup failure remain recorded. A bounded local diagnostic identified repeated typed-JSON assembly as a material cost; its instrumented restore also failed and is not performance acceptance.

The correction records fallback positions, preserves conversion and deferred serialization order, and joins completed string fragments directly. All 296 compatibility cases passed, including 12 new ordering, mutation and error-precedence cases, with format/lint/types. Two finite synthetic workloads verified 768 timed outputs and measured candidate/old median ratios of 0.732 for primitive tuples and 0.935 for mixed fallbacks. These are serializer measurements only.

One fresh copy of existing synthetic C12 history restored in 41.345 seconds under the original 60/120/150/8/1 limits, with financial/source/artifact/venue preservation and complete cleanup. The calendar helper and serializer correction are ready for exact-revision Linux CI, expected to contain 4,472 cases. This local pass does not close the prior Linux failure. Actual captured-session replay, scoped provider/account qualification, specific initializer approval and final review/merge remain open. Wave 4 is incomplete.

[Correction evidence](canonical-fragment-join.json) binds the exact source and independently reviewed results.


### September 25 tuple validation cost correction

Linux CI on `5e6595c` completed with 4,471 passed and one retained-restore failure at 60.186 seconds; the unchanged 60-second lease and separate expired-lease cleanup failure remain recorded. The new correction assembles scalar tuple children without recursive helper calls and dispatches exact tuples earlier in identity traversal. Canonical bytes, ordered identities, mutation/read/error order and all source, SQL and lease checks remain unchanged.

All 335 focused checks passed: 309 existing unit cases, 25 new identity cases and one original PENDING publication/restore fixture, plus format/lint/types. The first proposal's two mypy errors are preserved; its unit/PENDING phases never ran. The corrected exact-type predicate needs no runtime cast.

Finite benchmarks verified 1,536 serializer outputs and 512 identity outputs. Serializer candidate/prior median ratios were 0.921 for primitive tuples and 0.981 for mixed fallbacks, but scalar string and None controls were slower at 1.283 and 1.668 (about 84 ns and 127 ns extra per call). Identity ratios were 0.774 and 0.845. These measurements do not establish a uniform speedup or predict startup performance.

One unprofiled fresh copy of existing synthetic C12 history restored in 40.821 seconds under the original 60/120/150/8/1 limits, with financial/source/artifact/venue preservation and complete cleanup. This local pass does not close the Linux failure. Together with 26 separately qualified diagnostic-helper cases, the next required CI suite is expected to contain 4,523 cases across 16 shards. Actual captured-session replay, provider/account qualification, specific initializer approval and final CI/review/merge remain open. Wave 4 is incomplete and Wave 5 has not started.

[Correction evidence](validation-cost.json) binds the exact source and independently reviewed results.


The optional Linux diagnostic profiles only the original factory execution and runs after a required backend regression failure. Required tests remain unprofiled, original limits and failures remain authoritative, and diagnostic artifacts contain bounded static code metadata and timings only. All 26 finite reporter and fake-lifecycle checks passed, along with architecture/format/lint. The earlier assertion-message test failure is preserved and its test-only correction was rechecked. No actual retained history was rerun for instrumentation. [Diagnostic evidence](linux-retained-profile.json) records the exact scope.
