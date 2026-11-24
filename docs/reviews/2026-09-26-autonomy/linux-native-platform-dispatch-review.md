# Native observer platform dispatch typing correction

2026-09-27. Read-only review. No project imports or tests.

**No semantic blocker.** The only source delta is replacing the direct condition `if sys.platform == "linux"` with one local assignment `platform = sys.platform` and the same comparison. For the supported platform strings, the dispatcher still reads the attribute once, evaluates the same equality, and calls exactly one original helper with the same PID and timeout. Return values and exceptions propagate unchanged. There is no additional observation, fallback after failure, retry, deadline or cleanup change.

The saved local avoids the platform-specialized type-checker's direct-condition narrowing; root is validating both Linux and Darwin type-check configurations. This review does not claim either command passed.

Independent AST comparison against candidate `a7b98cf8e11036068a002f7ca56516c973bf84e7315ae9fbf4e031b42cdd6655` confirms the ps helper is unchanged and the entire remaining module is unchanged after removing only `_observe_child`. The ps helper's existing Darwin state interpretation remains intact. The statement that all original code except the dispatcher is unchanged remains accurate; prior byte hashes must not be represented as this corrected revision.

Reviewed current source SHA-256: `daacbce9a7e995fafa790562a1e5a05d1c1a0cec4b857f683834aa23b5002646` (`packages/application/continuous_process.py`). Existing dispatch/error tests remain relevant; exact new-revision Linux CI is still required. The earlier Linux mypy failure remains a failed result.
