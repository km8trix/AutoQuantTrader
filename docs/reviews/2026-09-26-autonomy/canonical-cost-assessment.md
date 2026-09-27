# Canonical encoding cost assessment

This final audit was read-only: no project imports, prototypes, benchmarks, tests, fixtures, or repository edits. It found no additional small, useful, exactly behavior-preserving encoding optimization established by the current source and existing evidence. This is a scoped finding, not proof that every possible optimization is impossible.

## Source binding and current behavior

Audited checkout: `/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development`.

`packages/domain/canonical.py` SHA-256:
`b0f5a2a2869242f9ae3e0fc5b27d255435155aba4d4daf6390949980b0ce630e`.
This exactly matches the canonical source recorded in `canonical-retained-shape-summary.json` (`source_sha256`), so the prior bounded captured-shape comparisons apply to this implementation.

- `packages/domain/canonical.py:152`, `_append_typed_text`: the previously measured minimal BUILD_STRING change is already present for the exact string, integer and bytes leaves. It preserves dynamic `json.encoder.encode_basestring_ascii` lookup and existing `str()` / `hex()` timing. Exact subclasses take the original conversion path.
- `packages/domain/canonical.py:194`, `_typed_fragment_text`: serializes deferred converted values, retaining the original fallback behavior and dynamic encoder calls.
- `packages/domain/canonical.py:217`, `canonical_json_text`: completes conversion before deferred serialization, then joins fragments once. Moving fallback serialization earlier can change mutation and failure order.
- `packages/domain/canonical.py:228`, `canonical_json_bytes`: calls `canonical_json_text(value).encode("utf-8")` once. No redundant text generation or byte encoding was found. Direct byte-fragment construction or a different encoding is not an established compatible fix.

The fallback's remaining string concatenation is not automatically interchangeable with formatting under a dynamically substituted encoder that returns a string subclass: operator hooks and temporary lifetimes can differ. No measured, compatible improvement to that path is established.

## Compatibility evidence

Source-relative test citations:

- `tests/unit/test_personal_canonical_fragment_join.py:84`: earlier fallback serialization can mutate a later converted value; deferred order matters.
- `tests/unit/test_personal_canonical_fragment_join.py:215`: subclasses must not acquire additional formatting, string or hex hooks.
- `tests/unit/test_personal_canonical_fragment_join.py:252`: dynamic integer digit-limit errors and deferred earlier-error precedence must remain unchanged.
- `tests/unit/test_personal_canonical_deferred_dispatch.py:213`: aliases repeat hooks; mutation between calls changes canonical bytes.
- `tests/unit/test_personal_canonical_deferred_dispatch.py:230`: later conversion can affect deferred output.
- `tests/unit/test_personal_canonical_tuple_dispatch.py`: independent literal legacy oracle covers tagged wire/hash identity, subclasses, Enum dispatch, mutation and context-free Decimal behavior.

The earlier callback/lifetime probes are summarized in [rejected shortcut evidence](rejected-shortcut-investigation.json), which embeds the extended hook probe alongside the captured candidate results. Naive pair batching retained the first encoder-returned temporary across the second encoder invocation or failure, whereas the current implementation releases it earlier. Encoder rebinding through callbacks/finalizers also makes lookup order observable. Byte equality on ordinary inputs alone cannot establish compatibility.

`canonical-leaf-evidence.json` records the already implemented three scalar BUILD_STRING changes, 289 historical focused passing tests, eight new cases and static validation. That historical record is evidence for the existing change, not a fresh validation run or a general startup-performance claim.

## Prior bounded measurements and dispositions

Exact source: [captured-shape summary](canonical-retained-shape-summary.json), especially `capture`, `replay`, `coverage`, `benchmark`, `assessment` and `limits`. Candidate ratios below mean **candidate median / current median**; less than one is faster.

| Candidate | Covered-mix ratio | Established disposition |
| --- | ---: | --- |
| Function-entry exact two-string tuple, complete each scalar fragment first | 0.9857866715 | About 1.42% estimated covered-sample gain, with shape regressions; no material retained-workload benefit established. |
| Function-entry exact empty tuple | 1.0090060247 | About 0.90% slower estimated covered mix; rejected. |
| Function-entry exact two-string tuple, extend original complete fragments | 0.9856681263 | About 1.43% estimated covered-sample gain; finite compatibility probes passed, but material startup benefit remains unproved. |
| Combined pair fragment guarded by original builtin encoder identity | 0.9490490533 | About 5.10% estimated covered-sample gain; the guard does not establish concurrent/signal rebinding compatibility or complete hook/lifetime/depth equivalence. Do not implement from this evidence. |
| Arbitrary exact-string escaping memoization | Not measured | Would retain arbitrary potentially credential-bearing text and change data lifetimes. Neither implemented nor justified. |

The prior capture observed 62,011 canonical calls and 10.860592460 seconds of inclusive canonical time. It retained 30 samples totaling 2,982,859 bytes; 22 supported tuple/scalar samples replayed with byte equality. Eight samples were skipped because their original Enum classes were unavailable; one also contained a mapping.

Fixed capture limits omitted 253 outputs above 1 MiB, costing 4.306194076 seconds (39.65% of measured canonical time). Supported replay samples represented an estimated 31.05% of canonical cost and 86.49% of calls using size-bucket weights, not exact semantic frequencies or statistical confidence. These comparisons do not predict omitted-graph cost or end-to-end improvement. Canonical output also loses original aliases, subclasses, hooks, error/read order and temporary lifetimes.

The earlier instrumented retained test passed locally. It was not the separate unprofiled original acceptance gate and does not establish Linux CI acceptance. This audit adds no timing or test result.

## Conclusion

No overlooked compatible scalar/encoding repair with established useful benefit was found. The small supported scalar change is already present; the useful adjacent candidates have either been measured without material benefit or lack required behavior equivalence. Preserve these limits and stop this canonical exploration without raising capture limits, repeating the heavy fixture, introducing caches, or changing authority or validation checks.
