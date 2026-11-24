# Focused ownership checkpoint — 2026-10-11

This candidate starts at published `821f068` and contains one production change
file, six new test files, operating-guide updates and this public summary. The
[source manifest](source-manifest.json) binds exact reviewed Python bytes. CI,
runner, configuration, migrations and lockfiles are unchanged. Earlier published
evidence remains intact; the private local workflow archive is preserved separately.
This summary does not claim to be a lossless archive of that private evidence.

## Behavior and implementation

The original registries could retain a partially issued value after ownership
fields, fingerprints or finalizer registration failed. Capture/resolution could
likewise fail after a candidate became admissible. Failed calls must not grant
ownership when cleanup succeeds.

`continuous_account.py` now restores only the affected candidate's prior entries,
attempts each registry cleanup independently and detaches returned finalizer
handles where available. Actual primary and cleanup errors are preserved in
order. Earlier references, unrelated-key nested issuance and earlier journal
effects remain intact. Successful decode/construction/registration and original
invalid-reference exception translation remain unchanged. Previous objects must
pass existing ownership/fingerprint guards before decoding or planning.

The public resolver continues to invoke its configured codec/planner and all
original checks/transactions. An unused plan is not sufficient evidence that its
construction/authentication can be removed. No cache, reuse path, skipped check,
renewed lease, higher resource cap or timing remedy was adopted.

Cleanup faults explicitly leave unresolved entries; this does not promise
universal recovery from native allocation/OOM failure, same-key reentrancy,
replacement registries or registered-but-unreturned finalizer handles. The final
resolved-reference repair cannot retire successful `_own` finalizers whose
handles were not exposed; they remain attached until collection.

## Validation already completed on the same source

Meaningful unchanged-source baselines reproduced registration defects before
the repairs; failures remain preserved in local evidence. Final affected
validation collected 161 cases: 158 passes / 3 explicit PostgreSQL skips, including
all 78 new cases (11 plan, 23 ownership, 6 rollback-errors, 10 predecessor, 8 capture,
20 resolution). Architecture, configured Ruff/compilation and strict Darwin/Linux
types, 421 source files each pass. Independent source/result review passes.

A separate newly owned empty PostgreSQL16.15 linux/arm64 instance passes exactly
the 3 skipped repeatable-read restart/retry and deferred-commit rollback cases,
zero failures/errors/skips. Child time 3.981668s; 52 selected inputs match before/
after. Authenticated emptiness preceded database-wide migrations; exact owned
container/network removal and temporary authentication retirement were verified.
Its temporary launcher passes14 subprocess and 20 lifecycle cases after preserved
failed baselines. No existing service/data or production credential was used.

One unchanged two-record SQLite restart/retry diagnostic passes with 42 inert
tool cases. Its instrumented window is 1.171564083s; eleven combined row decoders
total 8.871335ms and three restores 90.650459ms inclusive. Inclusive resolver/restore
buckets overlap. This is no full-history cost attribution, scaling, safely
removable-work or uninstrumented speedup claim.

## Candidate validation and remaining gates

Fresh candidate architecture, configured seven-file Ruff format/lint and strict
Darwin/Linux types, 421 files each pass. One fresh ten-file checkpoint passes 158
cases with the 3 exact PostgreSQL skips,0 errors/failures,161 unique identities,
child 13.910491s. All five bounded commands exit0 with both EOF, no timeout,
overflow or reap failure and 16 equal selected Source pins. See the
[selected public validation summary](validation-summary.json); private workspace
arguments/temporary paths are omitted, so it is not a lossless original archive.
No exact candidate Linux acceptance is established. Publication updates existing
draft PR56 with a normal fast-forward descendant of821f068; read its current
head/checks before taking the next step. The full local evidence history stays separate.
See [TESTING](../../TESTING.md) for portable commands and isolation prerequisites.

Published821f068 [Linux run 36301402409](https://github.com/km8trix/AutoQuantTrader/actions/runs/36301402409)
remains 5,245 passes/two lease failures at 61.668/60.331s. A2 proof/capacity,
retained/worker/parent, genuine-source and Wave 4 acceptance remain open. Synthetic
metadata fixtures do not qualify production composer, account, concurrency races
or future profitability. Startup stays HALTED; no provider/live/initializer,
merge or deployment authority follows from this checkpoint.
