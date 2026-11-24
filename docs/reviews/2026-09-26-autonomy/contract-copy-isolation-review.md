# Factory proof test-order failure: class copy cache isolation

2026-09-27. Original nine-file integration evidence remains preserved in `contract-primitive-factory-integration.txt`: 172 passed, two failed in 808.46 seconds. This report does not claim those integrations have passed after the fix; root owns their rerun.

## Verified cause

The earliest relevant ordered test is `test_continuous_integrity_daily_episode.py::test_original_episode_rejects_copies_foreign_consumers_threads_and_reentry[reader]`. Its stdlib `copy(reader)` adds `__slotnames__ = []` to `SqlContinuousIntegrityReader`. The subsequent `[consumer]` case similarly changes `SqlContinuousCommitComposer`. `test_continuous_factory_integrity_result.py::test_copied_reader_does_not_gain_an_operation` repeats the reader mutation. These are both classes pinned by the original factory behavior baseline.

After a passing architecture check, a finite separate-process reproduction imported the existing factory, allocated each class with `object.__new__`, and used stdlib copy without constructing owners or running fixtures. For each class, the original root behavior guard passed before copying, exactly one new key appeared (`__slotnames__`, exact empty list), no prior binding changed, and the guard raised the observed `FACTORY_BEHAVIOR_CLASS_NAMESPACE_CHANGED`. Removing only the added cache key restored the original guard. Evidence: `contract-primitive-class-copy-reproduction.json`.

This explains both integration failures: the direct pending-profile test exposes the strict guard error; the opaque-claim test receives the existing initial-unsupported `None` fallback when that same guard rejects the class inventory. The primitive `_check_type` prefix does not create or mutate either class. No `__annotations__` mutation was needed to reproduce the exact failure.

## Focused fix

Added `tests/fixtures/copy_isolation.py` using the existing newer proof test's `copy_preserving_class_inventory` pattern. It performs the actual stdlib copy and restores only a changed lazy slot-cache binding in `finally`. Updated precisely the three above copy sites. Their original copied-owner denial assertions, invocation ordering and fixtures remain intact. The existing proof test's local helper is untouched.

No production proof guard, namespace policy, registry, baseline, authority method or constructor changed. A real metadata mutation continues to be rejected; the five new unit cases demonstrate both pinned class failures before restoration, distinct copied objects with shared member identities, exact original class restoration, preservation of an existing cache object's identity and cleanup plus original exception identity when copying fails.

Validation: architecture passed before the pure reproduction; clean-environment `pytest -q --tb=short tests/unit/test_continuous_copy_isolation.py` passed all five cases in 1.15 seconds (`contract-copy-isolation-unit-first.txt`). Scoped Ruff and format checks passed, and `git diff --check` passed. No heavy fixture ran in this agent.

Frozen SHA-256 values:

```
4316fe896665fec5dc2c4d26096965ccec9eb8af5b2f3b4c76928b5897a76054  tests/fixtures/copy_isolation.py
dc4335e6fd88159b3def2c8b0e07ad29ff761b29291ec4ecf562c9f59effae16  tests/unit/test_continuous_copy_isolation.py
451cdad3ee8b4febca347c3b3510fb69e52283a1ded7454686b050d9eb3725ac  tests/integration/test_continuous_integrity_daily_episode.py
821edce3c01d34d10a8889a64cfb0df32b0acdc82ae8c5b3878980469b3ddc20  tests/integration/test_continuous_factory_integrity_result.py
48b76a5c4d7e0eac6b08c4c3eb5f0d542a94eec0b4a681a6337727195e53108a  packages/persistence/_factory_attempt_behavior.py (unchanged)
```
