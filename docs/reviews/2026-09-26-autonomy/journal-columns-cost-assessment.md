# Journal projection cost assessment

2026-09-26, read-only source/evidence review. No project imports, timing experiment, database/fixture execution, provider access or repository edit.

**Result: no concrete small behavior-preserving cost repair is established. Do not reopen projection caching or change `_columns` on this evidence.** This is a bounded assessment of the named hotspot, not a claim that every possible optimization has been exhausted.

## Evidence and actual responsibility

Current `packages/persistence/durable_journal.py` SHA256 is `ce6f67167d95ede5696bb11781d46c3bc5a83e871f51b18de8e421ff28324f71`, identical to the previously rejected projection experiment's source hash.

The completed diagnostic artifact `linux-profile-2a9fc2c/profile.json` reports `_columns` at line 111: 15,807 calls, 5.510423777 s inclusive and 0.233116821 s self time. **The artifact completed; the instrumented `factory.execute` did not return.** It records 63.053374144 s in execute before failure. Inclusive times overlap and include SQLAlchemy expression construction; they are neither an available saving nor the cost of the short Python dispatch alone. Self time is about 4.2% of this helper's inclusive time. This profile does not identify a new safe shortcut.

The helper constructs fresh bounded SQL projections in current table-column order:

- A declared bounded `String` uses `substr(column, 1, length + 1)`.
- `LargeBinary` uses the current 16 KiB key bound or `MAX_RECORD_BYTES`, plus one rejection byte.
- `BigInteger` on SQLite uses `CASE typeof(column) = 'integer' THEN column ELSE NULL`; other supported dialects use the column.
- Other types reject with the existing static `JOURNAL_COLUMN_TRANSFER_UNBOUNDED` error.
- Every result is labeled using that column's current name.

The extra byte is intentional: callers transfer a bounded corruption witness and then reject it, rather than silently truncating a damaged record to an apparently valid value. The SQLite storage-class CASE prevents a corrupt numeric field from transferring an arbitrarily large text/blob before detached validation.

## Callers and observable boundaries

Direct call sites are `_entry_row` (line 175), `_stream_row` (189), both append/entry reads in `_capture_receipt` (199), and the bounded page query in `read_page` (981). They serve current capture, historical receipt/anchor reads, append/retry checks and account-transaction rechecks. `_capture_receipt` preserves its append query, bounded ordered entries query and conditional predecessor read. `capture_in_transaction` (686) and `recheck_in_transaction` (889) intentionally make fresh existing reads in the caller's transaction; they do not substitute previously detached rows for current SQL observations.

Schema/type/name/length, dialect, transfer limits and SQLAlchemy expression behavior remain mutable Python inputs. The existing code reads these lazily, per column and at each original construction point. In particular, repeated `column.type` reads and the conditional dialect lookup are part of the existing order. Hoisting them can change callback/error timing: unsupported earlier columns currently fail before a later dialect access, while type/name/length and expression/label hooks can affect later reads. No source-owned immutable-schema contract exists here that would justify removing those reads. Exact-type or new schema preflight branches have not demonstrated worthwhile compatible savings.

## Existing regression evidence

Repository tests already require the relevant transfer behavior:

- `tests/unit/test_durable_journal.py:360`: an oversized retained payload reaches decoding as exactly `MAX_RECORD_BYTES + 1`, then rejects.
- `:473`: every declared text/integer metadata column is corrupted with one MiB of SQLite text; text transfer is bounded to declared length + 1, integer transfer becomes `None`, and `_validate_row` rejects.
- `:503`: a blob stored in text metadata rejects with exact detached-type validation.
- Retained-head, chain, prefix/page, retry, prepared-readback, rollback and corruption tests preserve original evidence and refuse repair by reads.
- `tests/integration/test_durable_journal_postgres.py` covers exact retry/historical reads, outer rollback and concurrent stale/identical append semantics. Its presence is not evidence of a new performance candidate's acceptance.

The earlier experiment is still directly applicable:

- `journal-projection-rejection.json` and `journal-projection-verdict.md` report ten normal and 41 adverse cases over actual finite capture shapes. Guarded reuse/original median ratios were 1.561–1.598; guarded clone/original ratios were 2.319–2.452 (lower would be faster). All modes retained existing SQL reads/copies. There were 3,838 hits and 3,030 builds across 6,868 construction points, so the loss was not merely universal fallback.
- Adverse coverage included length/type/custom/unsupported type, dialect/table/function/limit changes; mutable expression literals, labels, function names, types and compiler methods; real row changes between reads; separate copies for duplicate receipt reads; and malformed/subclass bind inputs.
- `sql-projection-mutation-proof.json` demonstrates why unguarded reuse is not a free optimization: a previously exposed payload projection retained a changed bound of 524,288 while the fresh original used 262,145. Private deep cloning repaired that finite mutation only; it did not make schema/type/compiler state immutable or establish comprehensive compatibility.
- The finite guarded prototype was explicitly not a complete proof against arbitrary SQLAlchemy/quoted-name/compiler mutation, and its measured overhead already rejected it. Enlarging that guard or adding a new ownership framework would not be a small established repair.

## Disposition

No production change or additional fixture run is justified from this audit. Preserve each fresh bounded projection and original SQL observation. Reusing expressions, hoisting mutable schema/dialect decisions, direct raw-column selection, replacing dynamic SQLAlchemy factories, changing bind typing, coalescing duplicate reads or extending limits would require new behavioral evidence and/or a separately scoped contract; none follows from a 5.510-second inclusive hotspot.

The current evidence supports closing this narrow investigation without an implementation proposal. It does not attribute the Linux lease failure to `_columns` alone and does not establish that optimizing another part of startup is impossible.
