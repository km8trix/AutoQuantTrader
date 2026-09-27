# Continued pure-computation cost review

2026-09-27. Checkout: `/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development`, inspected at clean `071dd5c`. Repository source and tests were not edited. Initial work was read-only; the coordinating agent subsequently authorized the single finite temporary primitive-dispatch probe documented below. No fixture, provider, SQL, artifact, process-observation, lease, or source-owner operation ran.

## Finding and recommendation

One new, concrete small optimization is worth normal implementation and compatibility validation: give `packages/domain/personal_contracts.py:_check_type` the same **matching exact primitive annotation/value** prefix already established in `packages/application/personal_codec.py:_unpack`. It removes generic typing dispatch only for `str`, `int`, `bool`, and `type(None)` when `type(value) is annotation`, preserving the original 65,536-character string bound and message. Keep the entire original body for all other inputs.

The finite prototype passed all 52 original/candidate/project comparisons and substantially reduced synthetic matching-primitive cost. This supports a narrow implementation proposal; it does **not** establish a retained-startup speedup, material Linux benefit, or acceptance. The profile provides no per-annotation frequencies, and the eligible portion of this helper is not measured separately. Do not translate synthetic ratios into seconds saved from the full restore.

No further canonical/semantic/daily graph, SQL projection, CLOCK reuse, or pre-lease proposal is recommended by this review.

## Latest profile and why this seam is distinct

Evidence: `docs/reviews/2026-09-26-autonomy/linux-55951fb-diagnostic-profile.json`, SHA-256 `22d6e05571620a7170938a59f0881b848e176317cf128cb5766bf44f5b1fb52f`.

This is a valid profile of a **failed, incomplete** original restore. `factory_execute_returned` is false. Its selected rows are not a complete call graph, inclusive times overlap, and no hotspot total is an available saving.

| Function | Total calls | Self seconds | Inclusive seconds |
| --- | ---: | ---: | ---: |
| `canonical.py:152 _append_typed_text` | 3,361,178 | 7.089534 | 11.959762 |
| `daily_runtime_risk.py:991 _assignment_identity_fields` | 63 | 2.771300 | 6.115496 |
| `personal_contracts.py:20 semantic_value` | 2,655,138 | 1.765564 | 4.355777 |
| `personal_codec.py:116 _unpack` | 260,362 | 0.648145 | 3.892574 |
| `personal_codec.py:35 _pack` | 447,115 | 0.596245 | 1.300858 |
| `continuous_runtime_history.py:322` generator | 2,433,356 | 0.569647 | 0.770851 |
| `personal_contracts.py:94 _check_type` | 309,629 | 0.485759 | 1.132715 |
| `detached_journal_capture.py:89 detached_journal_value` | 480,292 | 0.452830 | 1.272022 |
| `durable_journal.py:111 _columns` | 11,665 | 0.296782 | 6.900901 |

The largest own-time functions already have directly relevant rejection evidence:

- `canonical-cost-assessment.md` and `canonical-retained-shape-summary.json`: scalar BUILD_STRING is already implemented; pair/empty tuple alternatives had small or negative measured covered-shape value or unresolved encoder callback/lifetime compatibility. Direct byte encoding is already a single conversion. No new finding justifies reopening those variants.
- `semantic-generator-evidence.json`, `semantic-stopiteration-after-all.txt`, and `semantic-tuple-inline-assessment.json`: literal generator boundaries preserve PEP479, error chaining and transient result/metadata lifetimes. Earlier eager loops were withdrawn; the subsequent compatible inline generator regressed actual contract conversion. This proposal does not modify semantic conversion.
- `daily-native-membership-rejection.json`: eager/frozen scalar membership changed live-alias/short-circuit behavior, with weak synthetic economics. No daily graph dispatch or proof substitution is proposed.
- `journal-columns-cost-assessment.md` and `journal-projection-rejection.json`: inclusive SQLAlchemy construction cost does not establish reusable immutable expressions; guarded reuse and cloning were slower and dynamic schema/transfer/error behavior remains necessary.
- `continuous_runtime_history.py:317–326` performs fresh stored field identity checks with an observable `getattr` generator. No equally narrow measured replacement was established. This review does not convert it to eager iteration or skip checks.

The new seam is the separate constructor validator at `personal_contracts.py:94–134`. Every `ContractRecord.__post_init__` field calls it at `:143–146`, after the existing `_hints` lookup and current field/value read. It currently calls `get_origin` and `get_args` at `:98` even for matching ordinary primitives. The profile reports 37,530 contract post-init calls; the primitive subset is unknown. Global `get_origin`/`get_args` totals are shared with other callers and must not be added to this helper's inclusive cost.

## Proposed behavior boundary

Use exactly this prefix before the existing body:

```python
if (
    annotation is str or annotation is int or annotation is bool or annotation is type(None)
) and type(value) is annotation:
    if type(value) is str and len(value) > 65536:
        raise ValueError(f"{name} exceeds text bound")
    return
```

The `type(value) is str` check retains static type narrowing before `len`. Annotation checks use identity, not equality, hashing, field reflection or metaclass access. Exact builtin inputs cannot supply subclass hooks or finalizers on this branch; original builtin typing introspection returns only its ordinary `None`/empty-tuple results. The prefix introduces no cache or retained objects.

- `bool` and `int` remain distinct. Mismatches retain the existing rejection and message.
- `None` is accepted only with its exact annotation. Other values under that annotation retain the original `must be null` error.
- Exact strings keep the character bound, including Unicode/surrogates; no normalization, encoding, trimming or stronger bound is added.
- Scalar subclasses and custom annotation metaclasses retain the original body. A subclass value with its exact subclass annotation keeps the original acceptance, including the original fact that the exact-string bound is not applied to string subclasses.
- Alias reads, ordered union attempts and catches, Literal equality/generator behavior, fixed/variable tuples, Decimal finiteness and datetime UTC checks remain in the original body and order. Their recursive calls use the candidate again, just as codec `_unpack` already does.
- `ContractRecord.__post_init__`, current field iteration/getters, mutable hint lookup, subclass constructors, all surrounding validators, canonical bytes/hashes, SQL/fence observations and limits remain unchanged.

The repository precedent is `personal_codec.py:119–126` and `tests/unit/test_personal_codec_primitive_dispatch.py`: exact primitive matches already bypass generic typing introspection there, while mismatches, aliases, constructors, text bounds and subclasses remain enforced. No new imported-function attestation framework or fallback guard is warranted solely to preserve calls to a deliberately replaced `get_origin`, `get_args`, `isinstance`, or tracing function. This proposal makes no universal observation-equivalence claim for those substitutions; such a claim is also absent from the existing codec precedent. Supported custom data/annotations still take the original dispatch.

## Finite probe and retained evidence

Files:

- `/private/tmp/aqt-autonomy-audit/check-type-primitive-probe.py`, SHA-256 `f3240b03c41e90f09c4fab6782e2892d7c514e657d38a3ca2af4bb61cd632617`.
- `/private/tmp/aqt-autonomy-audit/check-type-primitive-probe-first.json`, SHA-256 `70d98c0d451bfae352f28d008379ab656164d2dd7749625f16976abf4792a064`.

The script contains a literal original implementation and asserts AST equality with current `_check_type` after only function-name normalization. It derives the candidate by adding the displayed prefix to that literal body. `_original` recurses through `_original`; `_candidate` recurses through `_candidate`. The project helper is independently compared as a third result. No project function/global is replaced.

**52 comparisons passed, zero mismatches.** Cases include all four primitives; bool/int separation; Unicode and text boundary/overflow; large integers; subclasses and enums; aliases, unions and Literal matches/rejections; fixed, variable, empty and nested tuples; Decimal finite/nonfinite values; aware/naive datetimes; dates; custom metaclass/annotation reads; and StopIteration error identity/cause/context through annotation and Literal hooks. JSON retains exact outcomes and traces rather than only a pass count. These are finite script checks, not 52 new repository pytest tests.

Seven alternating samples, 300 iterations per sample and 48 top-level calls per iteration gave:

| Finite workload | Original median ns | Candidate median ns | Candidate / original |
| --- | ---: | ---: | ---: |
| Matching primitives | 6,964,292 | 1,921,125 | 0.275854 |
| Existing VersionPin's declared string-field shapes | 7,445,792 | 1,910,375 | 0.256571 |
| Synthetic primitive/fallback mix | 8,740,625 | 5,596,791 | 0.640319 |
| Fallback shapes including primitive tuple descendants | 10,474,709 | 9,284,583 | 0.886381 |

Ratios below one are faster. The JSON labels the last workload `fallback_control`; it includes nested primitive tuple checks, so it is **not** an isolated measurement of added overhead on ineligible leaves. No actual workload weighting, constructor timing, end-to-end timing, repeated-fixture gain or CI conclusion follows. The VersionPin case uses literal field shapes and does not reconstruct records.

Exact executed command, after the coordinating agent's successful architecture check and explicit temporary-probe authorization:

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 \
  PYTHONPATH=/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development TZ=UTC \
  /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -B \
  /private/tmp/aqt-autonomy-audit/check-type-primitive-probe.py \
  /private/tmp/aqt-autonomy-audit/check-type-primitive-probe-first.json
```

Exit 0; command wall time approximately 0.431 seconds. The report was created with exclusive mode `0600`; a repeat must use a new report path and must not overwrite this first result. No repeat is needed to establish this finite disposition.

Before source acceptance, add permanent independent-oracle coverage for these boundaries plus adverse error-name formatting, constructor/field-read order and mutable hint updates between fields; run affected contract/codec/canonical and original retained gates as scheduled by the coordinating agent. A pure ineligible-leaf control can accompany normal implementation benchmarking if needed, without another heavy fixture solely for the microbenchmark. Preserve the original Linux acceptance requirement.

## Additional source hashes

- `packages/domain/personal_contracts.py`: `e33f82ecfe99a35ee50fb516f22f8f99449a18caee408cf4cd9a69d37ebaf5e6`.
- `packages/application/personal_codec.py`: `ef21916d22afe404a8ac3247d6f1202dc2e73a6182ba4b6f7cb96770674a9b9e`.
- `packages/domain/canonical.py`: `b0f5a2a2869242f9ae3e0fc5b27d255435155aba4d4daf6390949980b0ce630e`.
- `packages/persistence/daily_runtime_risk.py`: `cfae83fee7d05ff79dbc3a8e47036870c88d9785247171ba0bcbb4e30f6fee24`.
- `packages/persistence/detached_journal_capture.py`: `e3b105bbce75a87f85d33062679c7028de914439538bae95a9e89870cdd601d2`.
- `packages/persistence/continuous_runtime_history.py`: `1237cc3e76c2d797d2db60d9ec6aa6377943cfc5c688134898244ad04e37fa81`.
- `packages/persistence/durable_journal.py`: `ce6f67167d95ede5696bb11781d46c3bc5a83e871f51b18de8e421ff28324f71`.
- `tests/unit/test_personal_codec_primitive_dispatch.py`: `af6c47180bc417a5e0a119f017d600f0545802ff064392b92807e7c234b16647`.
