# A2.6 CLOCK-only behavior inventory checkpoint

2026-09-27. Companion to `prelease-pure-work-study.md` (SHA-256 `5bd17c295cbf7832cfdf28ccbbc62b26a6a8dc5bf3a4c93af1d5b9afe0f55406`). Static source inspection only. No project imports, predicate implementation, cache probing/mutation, benchmarks, tests or fixture. Standard-library modules were imported only to locate their installed source and identify CPython 3.12.13; their source files were then read. No native cache layout was inspected or assumed.

**Conclusion:** the three-record CLOCK profile is finite enough to continue the approved study. It is not inherently a general schema/graph-attestation problem. However, the transitive predicate is substantially larger than “same codec and unchanged three dataclasses.” Current code offers no complete qualifier. Neither native-cache residency qualification nor a complete cold/warm qualifier has been implemented, measured or admitted. Do not release a substitution prototype from this inventory. The already planned original-only CLOCK count/cost/size observation remains a legitimate bounded next investigation; no additional owner permission is required within A2.6.

## Fixed input grammar and root inventory

Only exact `runtime-clock-observation/1` payloads from the original bounded journal snapshot, decoded with the actual original `personal_codec` module and exact expected `RuntimeClockObservation`, are candidates. No other schema, custom codec, custom metaclass, arbitrary annotation, subclass or provider object is admitted by this prospective profile.

The three concrete dataclasses and their bases are:

- `RuntimeClockObservation` → `ContractRecord` → `object` (`runtime_operating_contracts.py:29`). Fields: exact scope and VersionPin; fixed Literal aliases for profile/status/evidence; exact tuple of reasons; optional str/int/datetime fields; exact int sequence; exact bool recovery/rearm flags.
- `ContinuousAccountScope` → `ContinuousPersistenceRecord` → `ContractRecord` → `object` (`continuous_persistence_contracts.py:26`). Four declared string/Literal fields.
- `VersionPin` → `ContractRecord` → `object` (`personal_contracts.py:154`). Three string fields.

This means five project class namespaces, including the two bases, plus the native `object`/`type` behavior. The record graph needs no Enum instances, Decimal values, ObjectRef traversal, account/daily owner, clock sampler, SQL operation or provider callback. Those facts narrow the prospective predicate; they do not permit weakening any enclosing original observation.

`RuntimeClockObservation.__post_init__` also compares to the original `CLOCK_POLICY` VersionPin and checks sequence/profile/magnitudes. Pinning only the policy object's identity is insufficient: its fields, original type, equality method and class descriptors matter. Generated record constructors and original `__post_init__`/VersionPin equality must remain original. Native slot descriptors, MRO, class names/modules, field dictionary order, Field `name`, `init`, `_field_type`, frozen parameters, annotations/defaults, and absence of unexpected attribute interception must be established without invoking unknown getters. Nominal frozen dataclasses are not a sufficient mutation proof.

## Concrete project functions and data

The complete direct project function groups reached for this schema are identifiable without discovering arbitrary application call graphs:

| Group | Required original behavior/data |
| --- | --- |
| `personal_codec.py` | `decode_record`, `_object`, `_reject_number`, `_mapping`, `_text`, `_unpack`, `_name`, `_hints` wrapper and its original wrapped body, `encode_record`, `_pack`; codec version, depth/byte limits, exact JSON/native bindings and imported typing/dataclass/type objects. |
| `personal_contracts.py` | `ContractRecord.__post_init__`, `_hints`, `_check_type`, `require_utc`, `require_text`, `require_digest`, `VersionPin.__post_init__`; `_TYPE_HINTS`, relevant exact returned dictionaries, UTC, regex and imported typing/dataclass/native bindings. `content_digest`/`semantic_value` are not called by the selected `_validate_record` codec predicate itself; enclosing record/entry hashes remain original and outside the substitution. |
| `continuous_persistence_contracts.py` | `ContinuousAccountScope.__post_init__`; class/base namespaces and bindings for `journal_identifier` and `require_digest`. |
| `durable_journal_contracts.py` | `journal_identifier`; leave original `JournalRecord.__post_init__` at its current post-acquisition site rather than including its result in the reused verdict. |
| `runtime_operating_contracts.py` | `RuntimeClockObservation.__post_init__`, original three Literal alias values, original `CLOCK_POLICY` fields, original class bindings. `OPERATING_PROFILE` is not read by this constructor. |

`decode_record` itself canonical-encodes before returning (`personal_codec.py:221`); journal `_validate_record` performs another original encode (`durable_journal.py:268`). The prospective reused predicate must account for both invocations, exact root type and original exception handling. No “redundant encode” deletion is established. The three dataclass generated `__init__` methods and generated VersionPin `__eq__` are explicit additional function entries, including their code/defaults/cells and resolved `object.__setattr__` binding.

## Warm type-hint path: two distinct caches

1. `personal_codec._hints` is a native `functools.lru_cache(maxsize=512)` wrapper (`personal_codec.py:30`). On a hit it returns a mutable hint dictionary. The wrapper's function namespace can also be modified; wrapper identity and `__wrapped__` alone do not bind all callable behavior. `cache_info()` reports aggregate counters/capacity, not which class key maps to which dictionary.
2. `personal_contracts._hints` (`:88`) performs an ordinary dictionary membership/read on `_TYPE_HINTS` and returns a mutable dictionary. Both outer keys and per-class field mappings matter. Cold entries are populated through the imported original `get_type_hints`.

A dictionary previously returned for a class may be mutated later. Clearing/repopulating either cache can replace its current dictionary. Therefore pinning a single preparation-time returned mapping does not prove the later original predicate reads it. An ordinary cache key lookup is not automatically callback-free if foreign keys with custom hashing/equality may be present; shape/key safety must precede lookups used as qualification.

The native LRU implementation is selected at the end of installed `functools.py` from `_functools._lru_cache_wrapper` (`:646`). The Python fallback documents cache lookup, recency, eviction and result lifetimes (`:570` onward), but it is **not proof of the native wrapper's exposed layout**. No native layout, resident key-to-value link or mutation-safe introspection API has been established here. Do not manufacture one from `cache_info()` or infer it from the fallback source.

## Cold reflection path and inherited annotations

Installed CPython 3.12.13 `typing.get_type_hints` at `typing.py:2219`:

- checks `__no_type_check__`, walks the original MRO including bases, obtains module dictionaries via `sys.modules.get(base.__module__)`, reads each original `__annotations__` and copies `vars(base)`;
- includes inherited annotations, including ClassVar declarations not returned by dataclass `fields()`;
- calls `_eval_type` for each annotation with `base.__type_params__`, then `_strip_annotations` because callers do not request extras.

`runtime_operating_contracts.py` and `continuous_persistence_contracts.py` do not use postponed annotations, so most annotations are already exact type/typing objects. Their ancestor `ContractRecord` and `VersionPin` live in `personal_contracts.py`, which **does** use `from __future__ import annotations`: inherited `ClassVar[str]` and VersionPin's `str` annotations still take the string/ForwardRef path. “CLOCK has no forward references” would be false.

The finite cold reflection functions/classes that must be accounted for include:

- `typing.get_type_hints`, `_eval_type` (`:407`), `_strip_annotations` (`:2319`), `get_origin` (`:2344`), `get_args` (`:2374`);
- `ForwardRef.__init__` and `_evaluate` (`:884`, `:916`), `_type_check` (`:175`) and `_type_convert` (`:166`); original native `compile`/`eval` and fixed namespace resolution for the known annotation strings, rather than arbitrary expression evaluation;
- `_BaseGenericAlias` attribute behavior, `_GenericAlias` metadata/equality, Literal alias metadata and native `types.GenericAlias`/`UnionType` origin/argument behavior; `_should_unflatten_callable_args` for the exact `tuple[str, ...]` branch; original empty type-parameter tuples and absence of new aliases/annotations;
- cold evaluation of `ClassVar[str]` reaches `_SpecialForm.__getitem__`, its `_tp_cache` wrapper, the original ClassVar `_getitem`, `_GenericAlias` and `_BaseGenericAlias` constructors and `_collect_parameters`. `typing._tp_cache` at `:376` resolves a wrapper from mutable `typing._caches` and falls back to the original callable after TypeError; its native cache is a second cache family, not the codec cache. Pin the relevant wrapper/function/key/value path, including the `_SpecialForm` `_getitem` slot and relevant alias metadata. A global dictionary identity alone is insufficient.

This inventory is intentionally specific to the known annotations. New arbitrary annotation expressions, extra schemas, arbitrary alias descendants or custom metaclasses must remain unsupported. Exact code/global/default/cell bindings and relevant native descriptors are needed; hashing a source file does not prove live Python function objects are unchanged.

Native `compile`/`eval` and cache/interpreter operations remain within the existing trusted-interpreter/test-instrumentation fault model; this study does not claim a sandbox against hostile native mutation or instrumentation. Any reliance on a narrower instrumentation profile must be stated explicitly, not silently added as a reason to disregard ordinary class/code/cache changes.

## Dataclass, JSON, datetime and regex boundary

- Installed `dataclasses.fields` at `:1278` obtains `__dataclass_fields__` through attribute lookup and returns dictionary values whose `_field_type is _FIELD`. `is_dataclass` at `:1301` consults the same marker. Pin marker absence/presence, exact original Field instances and metadata, class lookup/native descriptors and the original helpers. Merely holding class identity does not freeze the schema.
- `json.loads` has explicit object-pairs and number callbacks, so it constructs a `JSONDecoder`, rather than using `_default_decoder` (`json/__init__.py:333`). The exact payload is bytes, so `detect_encoding` and native decoding also matter. Include original `JSONDecoder.__init__`, `decode`, `raw_decode`; scanner factory/native `_json` scanner; original parse-string binding, numeric parser and the codec callbacks; `decode`'s captured whitespace-match default. Require the qualified native scanner path or reject unsupported fallback instead of broadening to arbitrary JSON implementations.
- The codec's `json.dumps` options (`allow_nan=False`, explicit separators and sorted keys) construct a fresh `JSONEncoder`, rather than using `_default_encoder` (`json/__init__.py:226`). Include original `JSONEncoder.__init__`, `encode`, `iterencode`, class descriptors/default behavior, native `c_make_encoder` and `encode_basestring_ascii`, and the original option values. With valid packed CLOCK data no float/custom-object default path is expected; exclude changed class/options/native bindings before trusting that fact. The existing attempt behavior inventory covers only its own selected canonical path and is not a ready JSONDecoder/typing/cache qualifier.
- Exact datetime values are created by native `datetime.fromisoformat`; `require_utc` compares their offsets with original UTC and `_pack` uses native `isoformat`. No user datetime subclass is in this input profile. Native type/descriptor and UTC bindings still belong to the explicit trusted profile.
- `require_digest` calls `re.fullmatch(r"[0-9a-f]{64}", value)`. Installed `re._compile` at `re/__init__.py:280` first consults mutable `_cache2`, then `_cache`, and can compile a missing pattern. Warm qualification must bind the relevant exact pattern key and original native Pattern result and preflight lookup safety, not merely `re.fullmatch` identity. Cold compilation reaches `_compiler.isstring`, `_compiler.compile/_code`, `_parser.parse` and its State/SubPattern/Tokenizer paths, then native `_sre.compile`. That additional cold subgraph has not been fully inventoried or qualified here. It cannot be called “covered” by the codec's native LRU guard. A reviewed warm-only regex profile could reject when the relevant entry is missing/changed, rather than supporting every regex parser path.

## Two finite directions; neither is a ready predicate

**A. Narrow resident-cache use profile.** After original provisional decoding, establish the current relevant codec/type/typing/regex cache entries, their exact key/value relationships and expected bounded contents. At each use, a native-cache-specific guard would establish that the original predicate would take those same supported warm paths; clearing/eviction/mutation rejects the provisional result. This avoids certifying cold behavior at use, but requires a reviewed bounded native LRU profile that does not currently exist. It must not walk unrelated schemas' object graphs or grant a second resource allowance. The preparation's own cold behavior and rejection ordering still require qualification; warmed fixture state cannot be assumed for a fresh worker.

**B. Qualify both warm and cold behavior.** Establish exact relevant cache outputs and all original fixed-annotation reflection/compiler paths, permitting only known CLOCK inputs. The native cache lookup itself must first be shown safe; calling `_hints` to inspect its answer is not a safe guard until that is established. A cold result may create fresh equivalent typing alias objects, so exact identity to a previous hint dictionary is not an adequate equivalence definition. This direction has more functions, mutable data, temporary objects and reflection work and still needs exact bounds. It is a finite study question, but supporting arbitrary type/regex/cache entries would cross into the general framework the proposal excludes.

Do not choose A by pretending cache residency is observable through counters, or B by treating a returned dictionary as a complete proof of original behavior. Initial unsupported inputs may use a specifically reviewed original path; mutation after admission must fail closed according to the proposed handoff contract. No silent re-prime/reseal/new class enrollment is part of either direction.

## What this establishes and what remains open

Established from source: a named small nominal record grammar; concrete cold/warm dependencies; why codec identity/cache counters are insufficient; why exact byte equality alone cannot qualify the later typed predicate; and a finite boundary that can be assessed without general schema support.

Not established: a native LRU representation, complete cold regex path, callback-safe recheck implementation, total behavior/container/binding count, admission of a genuine fresh-worker graph, complete-cost saving or Linux margin. The function/data inventory is a design checkpoint, not a claim of complete implemented coverage. Unknown counts do not demonstrate a cap failure.

The appropriate next measurement asks specifically how often this exact schema reaches original `_validate_record`, its completed versus unwound costs, selected byte sizes/repetitions and any overlap facts already present in authentic frames. Preserve every original call/return/exception/fence/timer and avoid retaining raw data/frames or issuing provisional authority. Review the observer before root releases any genuine fixture. Its output can justify stopping economically before any native cache/behavior prototype, or justify a subsequent finite model; it cannot qualify the predicate itself.

## Source binding

Project source hashes are in the companion study and unchanged by this work. Installed standard library root:
`/Users/spencer.karrat/.local/share/uv/python/cpython-3.12.13-macos-aarch64-none/lib/python3.12`.
Runtime identification: `3.12.13 (main, Jun 23 2026, 15:44:24) [Clang 22.1.3 ]`. This is the local runtime, not proof that a different Linux native build has the same private layout.

```
be92d60fb8382bb29ead21c128825d7c96d0e8c915b44f840791e49f5a8d554c  typing.py
d242aea5fcf6408b1c1f622442f88f68b9526ce1f8bd2890d74a144677c427d9  dataclasses.py
de4a1d37c795e2a065124b5c49357893433bc6bb111b41277ccc9930ef08d4c9  functools.py
d5d41e2c29049515d295d81a6d40b4890fbec8d8482cfb401630f8ef2f77e4d5  json/__init__.py
52bfb1b66029cc70fa3bd7fe11df9f2e03922d413407a341b387a22c987f24f8  json/encoder.py
382cd02af6f7efede5a6d4abbcda1015e5c7a75794b0016022878f9cf32a24f6  json/decoder.py
572958017eae8842eeddd0e3d18d3c56cc0a197348224915e1d87ce937841764  json/scanner.py
8ff3c37c63b917fcf8dc8d50993a502292a3dc159e41de4f4018c72a53d1c07b  re/__init__.py
c75620761098a70ed75b9accef63ef2881d8abb6d4e5cbfd10074bd165eefe4d  re/_compiler.py
a51a85b37cf3f44ba7ff25754da5f31306e4ccfa6eb3c017f9d37bdf4e770840  re/_parser.py
```
