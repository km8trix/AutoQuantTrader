# A2.6: finite pre-lease pure-work study

2026-09-27. Read-only source/evidence study in `codex/autonomous-development`, HEAD `55951fb`, under the owner's approval of the bounded A2.6 study. No project imports, prototype, tests, benchmarks, fixture, provider access or production edits. A standard-library-only command selected existing profile rows; it executed no project code. The acquisition-transition witness is being assessed separately; this report does not resolve it.

**Checkpoint: no pure-work prototype is ready for release, but A2.6 is not rejected.** The smallest concrete candidate is provisional canonicality of historical `runtime-clock-observation/1` journal payloads. Its nominal record graph is finite, but the existing APIs provide no qualified reuse seam and no transitive behavior predicate has been established. The profiles do not supply selected-schema repetitions, unique bytes or peak overlap counts. These remain concrete, bounded study questions. Reject only the insufficient same-codec-identity/one-returned-dictionary shortcut; continue static qualification of the CLOCK-only cold and warm reflection paths. A bounded original-only observation can answer the specific cost/frequency question under the existing study approval. It requires a reviewed plan before any genuine fixture release. Unknown quantities are neither cap failures nor proof of impossibility. No general schema/cache framework is proposed.

## Current call paths and the finite candidate

The factory already reads, decodes, canonicalizes and checks its inputs, venue model and producer map before acquisition (`apps/trader/continuous_simulation_factory.py:229`, `:257`, `:557`). Moving those three reads cannot create a new saving. Acquisition occurs at `:303`; actual-fence owners are constructed afterwards. `execute` at `:579` checks configuration/HALTED/Stop, enters `reader.original_factory_read()`, consumes original owner-bound values, revalidates the actual fence and keeps results provisional through terminal checks. `close` at `:635` releases the actual lease.

The historical journal path is:

1. `continuous_integrity.py:1954` `_validate` obtains a fresh coherent snapshot through `_capture` at `:1893`, including the actual commit-fence check. It requires exact snapshot equality before establishing committed-observation ownership.
2. `_validate_original` at `:1990` calls `_validate_journals` at `:2079`. That decodes each stream's `JournalKey`, checks canonical bytes/digest, selects a configured journal by its schema allowlist, and decodes each entry for `_OriginalObjects.inspect`. It then freshly captures the head and each append and calls `journal.resolve_snapshot`; chain and inventory checks and transactional rechecks follow.
3. `durable_journal.py:752` `resolve_snapshot` checks the current journal's original raw-capture owner, validates the stream, head entry and receipts, and creates a new `ResolvedJournalRead` owned by that actual journal.
4. `_receipt` at `:460` and the head validation call `_decode_entry` at `:429`. That validates the row, constructs `JournalRecord`/`JournalEntry`, checks their hashes and calls `_validate_record` at `:261`.
5. `_validate_record` runs `record.__post_init__`, resolves the expected class from the current journal allowlist, calls the codec decoder, requires the exact root type, and canonicalizes again. **It then discards the decoded value.** This is the narrow computational seam considered here.

The only selected work would be the successful typed decode/exact-root/canonical-payload predicate for fixed existing rows whose schema is exactly `runtime-clock-observation/1` and expected class is the original `RuntimeClockObservation`. Preserve `JournalRecord.__post_init__`, current allowlist lookup, row bounds, all fresh SQL captures, hashes, receipt/chain construction, raw-capture ownership and current-head/fence checks. Do not pre-own `JournalReadSnapshot`, `ResolvedJournalRead`, account/daily snapshots or receipts. Do not include the other seven configured journal types, arbitrary artifacts, semantic identity walks or global canonical hashing.

After a separately specified coherent acquisition handoff, only the actual newly constructed journal owner could consume a provisional computation for byte-for-byte equal rows and its exact original schema/class. The current code has no such consumer. A Boolean result, hash or same codec object does not confer this right. Existing `prepare_append` (`durable_journal.py:282`) is a different operation with its own original preparation owner and later writer path; it cannot be fabricated from historical bytes to serve as a restore token.

## Why this still needs a new behavior predicate

The nominal decoded clock graph contains exactly three dataclasses:

- `RuntimeClockObservation` (`runtime_operating_contracts.py:29`), with scalar, tuple-of-string, Literal and optional exact datetime/integer fields;
- `ContinuousAccountScope` (`continuous_persistence_contracts.py:26`), with strings and a Literal;
- `VersionPin` (`personal_contracts.py:154`), with three strings.

No ObjectRef, provider adapter, account fence or current clock sampler is part of this decoded graph. Its original constructor compares `policy` with the existing `CLOCK_POLICY` and validates sequence/profile/magnitude fields (`runtime_operating_contracts.py:51`). This is a concrete finite *nominal record inventory*, not proof that its current dynamic behavior is immutable or effect-free.

The native codec `_hints` cache is a specific lifecycle issue: `cache_clear()` can make a later original call evaluate `get_type_hints` again, and public `cache_info()` does not establish per-class residency or the key-to-dictionary mapping. Pinning the wrapper and one returned dictionary cannot justify warm-only reuse. This does not prove a finite CLOCK predicate impossible: qualifying both the relevant warm dictionary contents and the original cold reflection path could make residency irrelevant. That qualification must include inherited annotations and mutable cached dictionaries, not just the three root dataclasses. It remains source-only investigation, not an implemented predicate.

The original predicate transitively includes:

- `personal_codec.decode_record` at `:199`: JSON decoding with duplicate-key/number callbacks; `_mapping`, `_unpack`; all generated constructors and `__post_init__`; an internal `encode_record(value) == payload`; exception translation. The journal performs an additional original encode and exact-root check. Neither encode may simply be removed because it currently appears redundant.
- `_unpack` at `:116`: type aliases/unions/Literal/tuple handling, `fields`, class names, dataclass metadata, `get_origin/get_args`, and `_hints`. The `@lru_cache` at `:30` returns a mutable hint dictionary; the wrapper's identity does not pin returned cache contents or cold `get_type_hints` behavior.
- `ContractRecord.__post_init__` (`personal_contracts.py:143`) and its separate mutable `_TYPE_HINTS`/`_hints` at `:85`, `_check_type` at `:94`, `require_utc`, text/digest checks, each generated constructor, native slot descriptors, field order/name/type/init metadata, class/MRO/module/name/annotation bindings and instance reads. The scope and VersionPin validators add identifier/regex checks.
- `CLOCK_POLICY`'s original fields and VersionPin equality, not merely constant-object identity; exact datetime parsing/UTC and serialization behavior; JSON encoder/decoder/native helpers and their relevant globals/callbacks; standard-library typing/dataclass behavior actually exercised by the finite annotation graph.

Earlier constructor/schema/getter/global/callback changes are observable to the ordinary original path. Reusing a verdict must not silently claim the later invocation ran those callbacks or would return the same result. Even a three-record profile requires a transitively bounded qualification and mutation/error-order contract. The existing attempt fingerprint proof is for another projection and predicate; its seal cannot certify this codec/constructor path automatically. Copying that framework into a generic canonicality cache is not justified by A2.6.

The approved study permits assessing a finite provisional interpretation/handoff. It does not make the missing predicate proven, authorize production substitution, or allow ordinary/custom-codec APIs to change. If the original functions are rerun after acquisition to avoid this predicate problem, the pre-lease decode has saved no original work.

Existing tests establish the significance of the boundary: `tests/unit/test_personal_codec.py:66`, `:84`, `:96` require constructor/type/canonical rejection; `tests/unit/test_durable_journal.py:203`, `:217`, `:240` preserve typed validation, codec-free write transactions and detached callback behavior. No tests were rerun in this study.

## Effects and fresh observations that cannot move with the predicate

The pre-lease read of historical bytes is itself SQL I/O and needs the proposal's fixed coherent source binding. It is not pure work. `_capture_continuous_integrity_snapshot` (`database.py:282`) includes all declared financial tables plus six lease/control dependency tables and performs SQL-side type/size/foreign-key/inventory checks before detached values exist. Acquisition changes those dependencies, so equality to fresh post-acquisition rows cannot be weakened or rebased. The acquisition-owned predecessor/transition witness remains a prerequisite outside this report.

`_OriginalObjects.inspect/recheck` (`continuous_integrity.py:109`, `:139`), stream/key checks, all journal capture/recheck operations (`durable_journal.py:686`, `:889`), daily/account/source checks, `_recheck_final` (`continuous_integrity.py:1901`) and terminal/release checks remain in their original places. The clock record itself has no ObjectRef; that does not permit skipping another record's object walk or the overall fresh object closure.

Malformed selected bytes could fail before acquisition rather than during `_validate_record` inside integrity validation. Preparation may populate existing type-hint caches earlier and constructs/releases temporary objects earlier. Stop/timeout/failure ordering and cleanup therefore change even when data is valid. These must be specified, not described as a pure reschedule of an unchanged public API.

## Source-bound cost facts and equations

Both retained Linux profiles are valid **partial failed execute** observations. They exclude factory construction/preparation and cleanup. Inclusive times overlap; do not sum rows or infer per-schema cost from call counts.

| Existing profile row | 2a9fc2c calls / inclusive seconds | 26631c6 calls / inclusive seconds |
| --- | ---: | ---: |
| execute | 1 / 63.053374144 | 1 / 60.474704892 |
| all `decode_record` | 2,713 / 6.653211686 | 1,442 / 5.436825955 |
| all `encode_record` | 5,591 / 2.033580528 | 2,902 / 1.523782154 |
| all journal `_validate_record` | 1,666 / 3.268831496 | 915 / 2.888805987 |
| all journal `_decode_entry` | 1,666 / 3.484961838 | 915 / 3.085085226 |
| entire `_validate_journals` | 1 / 1.724442184 | 1 / 2.866650546 |
| all `canonical_json_bytes` | 40,499 / 15.680514345 | 20,735 / 13.309740106 |

The all-journal `_validate_record` totals are loose ceilings only for selected typed-validation work *already executed within each failed trace*. They do not bound a completed restore, identify selected-clock cost, establish distinct payload count, or prove repetition. The large canonical total includes unrelated live-in-memory semantic/fingerprint work and cannot be assigned to this candidate. New factory/preparation costs are absent entirely.

Let U be the number of distinct selected original rows, V their actual original typed-validation invocations, D_i each original invocation's measured pure cost, D_pre the total one-time selected preparation cost, F_extra added coherent capture/comparison cost, Q qualification/admission cost, M the sum of per-use exact matching/check costs and X cleanup/retirement cost. No values of U, V, D_pre, F_extra, Q, M or X for this schema are established here.

- Merely moving an otherwise once-only decode before acquisition shifts lease-held time; it does not reduce total work. A speculative decode followed by all original decodes adds D_pre plus preparation overhead.
- A correct finite reuse path would have `total saving = sum(D_i for admitted replaced invocations) - (D_pre + F_extra + Q + M + X)`. Each preserved validation call, fresh read, fence and original cleanup stays outside the removed-work term.
- `lease-held reduction = admitted replaced work - new post-acquisition matching/qualification/cleanup cost`; pre-lease D_pre still consumes the original operation/parent/worker budgets. A positive lease-held result alone does not establish total benefit.
- For one-time inputs, the removed first decode is paid again in D_pre. Only genuinely repeated selected computations can provide a total reduction before extra costs. U/V cannot be recovered from the all-schema aggregate profile rows.

There is no numerical saving estimate or Linux margin prediction. The missing selected-schema calls, repetitions, sizes and cost identify a concrete original-only observation question; absence of those measurements is not a reason to reject the study. No heavy fixture is released by this report: first review a finite observer preserving original calls, deadlines and failure/cleanup behavior.

## Overlap and unchanged resource accounting

Existing independent limit families remain distinct:

- SQL snapshot capture: 65,536 combined rows and 128 MiB combined transferred field bytes for the declared financial and six dependency tables (`database.py:177`, `:282`); every binary journal payload is at most 256 KiB and key/canonical payload at most 16 KiB before transfer (`:225`).
- Typed journal record: 256 KiB; append: 64 records / 1 MiB (`durable_journal_contracts.py:12`). The generic codec's 64 MiB input limit is not a new journal allowance.
- Detached object closure: 32 MiB (`continuous_persistence_contracts.py:12`; `_OriginalObjects`), unchanged. A byte-only manifest cannot allocate its own extra artifact pool.
- The active attempt proof shares 16,384 original containers and 131,072 bindings with its existing context/behavior costs. The handoff profile separately admits original/fresh structure containers under its explicit 32,768 combined-container limit (`continuous_integrity.py:403`). That fresh allowance is not automatically available to a third pre-lease owner.

For a concrete candidate lower-bound screen only, suppose each selected row retains one exact five-element tuple `(stream_key_sha256, sequence, schema_id, expected_class, payload_bytes)` and the manifest is one exact tuple of those U entries. Under the existing data-binding convention (`_factory_attempt_fingerprint.py:287`: one container and `2 + len(accessors) + len(values)` bindings), tuple accessors are empty, so **C_manifest >= U + 1** and **B_manifest >= 8U + 2**. This excludes all behavior records, owner/context/registration, row/snapshot metadata, matching indexes, pending sets, acquisition witness, construction and cleanup overlap. It is not an implemented or complete layout. Retaining only a digest instead of original bytes cannot establish exact equality and is not a permitted resource shortcut.

At every phase a valid design would need explicit sums, not independent caps for every pool:

`C_peak = C_existing_live + C_manifest_live + C_behavior_live + C_transition_live + C_temporary_live`

`B_peak = B_existing_live + B_manifest_live + B_behavior_live + B_transition_live + B_temporary_live`

Those must fit the applicable unchanged original/fresh/combined profile at that phase. The completed original-only observation recorded an active attempt charge of 7,387 containers / 66,259 bindings, leaving 8,997 / 64,813 in the original profile at that sampled moment. This is source-bound evidence, not a global peak or capacity reserved for the new manifest. If it survived into that same phase, even this lower bound would add `U+1` / `8U+2`; retiring it before proof issuance could avoid that overlap only if no later selected consumers remain, which has not been established.

For bytes and rows the corresponding proposed conservative peak accounting is `R_pre_live + R_fresh_live + R_temporary_live` and `bytes_pre_live + bytes_fresh_live + bytes_temporary_live`, charged against the existing applicable aggregate allowance. Existing per-capture checks alone do not prove a new overlapping preparation plus fresh capture fits. Referencing old immutable tuples does not make new retained owner/value edges free; exact aliases can avoid physical byte copies only when demonstrated, and fresh SQL bytes cannot be assumed to alias preparation bytes. The complete acquisition comparison may require holding the full pre-lease snapshot, not just selected clock payloads.

No existing observation provides selected U, payload bytes, full pre-/post-snapshot row/byte totals or complete new behavior/transition counts. Therefore **no measured cap exceedance or passing resource screen is claimed**. A general 65,536-row source bound is too loose to certify a manifest under the smaller structural caps.

## Disposition

The source establishes a finite named schema and a real discarded-result computational seam. It does not yet establish useful cost, qualified consumption or a fitting concrete complete layout. **Withhold substitution/prototype release; continue the bounded study.** The next source-only task is the exact CLOCK warm/cold reflection inventory. A reviewed, bounded original-only per-schema observation can then answer the identified frequency/cost/size question without substituting validation or creating authority. Neither needs new owner permission within the approved study. The native cache issue rules out an identity-only shortcut, not all finite CLOCK designs.

Do not convert this checkpoint into a final A2.6 rejection or a universal infeasibility claim. A later complete bounded resource/cost screen may admit or reject a specific layout. Preserve 60-second retained lease, 120-second operation wall time, applicable 150-second parent bound and separate worker limits; do not move timers, repeat work outside measured budgets or weaken fresh observations.

## SHA-256 source and evidence manifest

Paths are repository-relative unless stated otherwise. Hashes bind this read-only assessment, not an implementation or validation pass.

```
d60324477620f85866eba36a001751101f0c027e44f50ec2aa6206f1e3f56a26  apps/trader/continuous_simulation_factory.py
0713cc6c55b35a7cd93eb89cb92cc4639ad9ba249c4d0f4389390ebeff78023d  packages/persistence/continuous_integrity.py
ce6f67167d95ede5696bb11781d46c3bc5a83e871f51b18de8e421ff28324f71  packages/persistence/durable_journal.py
846fd7019ce65ca13dabf00132fb94d7dec003e3f0ae8be778dd342d4ddd26a0  packages/persistence/database.py
ef21916d22afe404a8ac3247d6f1202dc2e73a6182ba4b6f7cb96770674a9b9e  packages/application/personal_codec.py
e33f82ecfe99a35ee50fb516f22f8f99449a18caee408cf4cd9a69d37ebaf5e6  packages/domain/personal_contracts.py
f4ac0f196e1d4f40c92796280715476a9217383a1907be97d9402d5eceb720a0  packages/domain/runtime_operating_contracts.py
761337e51774165d773d4916973ab10eecfa345537b58d91a16e6936b7f17d7a  packages/domain/continuous_persistence_contracts.py
9bda533b65415988315f6350dee1f6ad027f8981003f79c9402300a8c7dd2e5e  packages/domain/durable_journal_contracts.py
4db8b5e9e41f790a39031f884f0a17a548352059ab824f42f983e2affd1d2e56  packages/persistence/_factory_attempt_fingerprint.py
d6a0abbd1b74895b1369f096ac09cd0bbd3768d7e9fa7db1d8c3b640c9b5bfa1  docs/reviews/2026-09-26-autonomy/prelease-restoration-decision-proposal.md
c0b290a9382ec1b555258d11664e0813f73be2a939748d4640764341704d6eeb  docs/reviews/2026-09-26-autonomy/linux-26631c6-diagnostic-profile.json
06d41f8495b48f51fbd7ebb1d7e5d3c2f6f93390f1dc554bc3a827b87c5040bb  docs/reviews/2026-09-26-autonomy/linux-2a9fc2c-diagnostic-profile.json
99789c8f6417efaf0650d11c1d4233556f9674300002bc1d67442e3d931d6ee9  docs/reviews/2026-09-26-autonomy/daily-identity-original-observation.json
010275958390e3f94d41cf3e24820e91b02fdae1571be2307c0263471983532c  tests/unit/test_durable_journal.py
7eb15a45670aadec0d99044c26589407c142569b0eba02cdf37e6bea3cd06f6b  tests/unit/test_personal_codec.py
```
