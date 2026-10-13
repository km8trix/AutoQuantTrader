# A2.7 exact-primitive contract dispatch — final source review

2026-09-27. Read-only review of the actual eight-line prefix in `packages/domain/personal_contracts.py` and frozen `tests/unit/test_personal_contract_type_dispatch.py`. No tests, experiments, source/test edits or heavy fixtures were run by this reviewer.

**No blocking finding.** The implementation matches the reviewed narrow proposal. Only an original exact `str`, `int`, `bool` or `NoneType` annotation paired with a value of that exact type returns through the new prefix. The identity comparisons invoke no custom annotation equality, hashing or metaclass attribute behavior. A matching exact string still checks the same 65,536-character bound and raises the same formatted ValueError; successful values do not evaluate `name`.

Everything else reaches the unchanged original body: bool/int mismatches, subclasses and enum values, bytes, Decimal/UTC validation, aliases, unions, Literal and tuple recursion, unsupported annotations and reflection failures. Primitive descendants of a compound annotation can take the prefix during the original recursive visit; the enclosing visit/order/catches are unchanged. The historical behavior accepting an oversized string subclass when annotated with its own class is preserved. No constructor, field getter, later hint lookup or domain semantic constraint is removed, and no result is cached.

The permanent oracle is independent: it contains the literal prior checker, recurses into itself and uses its own literal UTC guard. It does not delegate expected behavior to the candidate. The tests additionally assert concrete expected validity, errors and callback traces, rather than only comparing two results. Meaningful adverse coverage includes exact string/Unicode boundaries; mismatch and subclass paths; TypeAliasType/union/Literal/tuple behavior; metaclass/reflection callbacks and StopIteration identity; dynamic `name.__format__` count, exception identity/context and original union catches; Literal generator exception chaining; Decimal/timezone behavior; constructor field order, repeated construction and mutation of a later field's cached hint; and real VersionPin/ReductionPoint constraints.

The author reports **83 passing cases** and scoped Ruff success; those results are not independently rerun here. This review confirms the frozen test contents support the claimed narrow compatibility scope. It does not establish a retained-restore improvement, full acceptance or Linux timing margin.

Skipping dynamically replaced imported typing helpers for admitted exact primitives is an intentional consequence of bypassing unnecessary native reflection, matching the existing `personal_codec._unpack` precedent. Repository source/tests expose no supported extension contract requiring those helper calls for exact primitives. This is not a promise to preserve arbitrary tracing or monkeypatched helper behavior, and it does not require another runtime attestation framework.

The existing attempt fingerprint substitution uses detached/canonical projection, not this constructor type-check predicate. This edit creates no new source ownership, proof admission, schema/cache authority, global constant or proof inventory requirement. Existing focused and affected financial/integration gates remain necessary; rejected SQL, daily-proof and pre-lease studies are not reopened.

Frozen SHA-256 bindings:

```
968012e5de4add2d4c19d7c8042a37255d5c1682ab0e91f2bd8dd492847df98b  packages/domain/personal_contracts.py
5b22ec534c0df638856ed51c763f5aeb1131c8f7adc0835db85491c66235ff58  tests/unit/test_personal_contract_type_dispatch.py
```
