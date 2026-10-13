# Final factory proof economics review — 2026-09-26

Reviewer: spec_plan_audit. Read-only source/evidence review; no source edits,
provider/runtime effects, test rerun or heavy work. The reviewer authored the
behavior helper and observation plugin; architecture_audit independently reviewed
those artifacts. This document checks the resulting evidence and its limitations,
not independent authorship of those implementations.

## Finding

No blocking concern identified for publishing this bounded offline candidate for
required CI/review. The evidence supports continuing evaluation; it does not
establish a general startup improvement, exact-head Linux acceptance, production
readiness, live execution authority, or correctness on every supported Python
runtime. The separately revised genuine nested-data case must retain its own
source-bound validation result; root is running that case.

## Captured evidence

Reviewed `factory-complete-cost-first/economics.json` and
`factory-proof-combined-cost-first.txt` under `/private/tmp/aqt-autonomy-audit`.
The capture is valid, exit status zero, with no diagnostic faults. All captured
source/test/plugin hashes match before and after the run. The log ends with
`100 passed in 321.91s`; expected injected failure traces belong to passing adverse
cases, not concealed test failures. Original diagnostic execution returned once,
with 24 borrows, 72 private checks, 3 ordinary full source checks, 2 root retirement
returns and 1 source revocation. Both registries retired. All selected spans
returned normally. The 1,386 events / 693 spans and 7,923-byte JSON remain below
20,000 / 4,096 / 32,768-byte bounds.

Current production source and observer hashes still match the capture. The only
captured file now differing is the lifecycle test, whose nested-data case is being
strengthened separately. Therefore the 100-pass result describes its recorded
historical test revision, while the economic source measurement still matches
current production code. It must not be relabeled as a run of that amended test.

## Shared resources

Recomputed from the individual captured components:

- Containers: data 4,854 + source behavior 1,334 + root behavior 1,153 + source
  reserve 16 + root reserve 32 = **7,389**, below the original 16,384 cap.
- Bindings: data 55,933 + source behavior 5,110 + root behavior 4,452 + source
  reserve 256 + root reserve 512 = **66,263**, below the original 131,072 cap.

The source deducts these behavior inventories and lifecycle reserves before raw
admission. The proof retires before handoff construction, so this does not create
a second simultaneous independent allowance. These numbers are the project's
structural resource accounting, not bytes or a total Python heap measurement.

## Cost model and qualification

Independently recomputed from the raw aggregate spans:

- Estimated removed full fingerprint work: **2.345598024 seconds** (three ordinary
  fingerprint samples extrapolated across 72 replaced private checks).
- Approximate added cost: **1.042580999 seconds**, including actual issue and both
  root retirement calls, private checks after estimated unchanged-prefix
  subtraction, root wrapper/episode residual, and begin/end methods.
- Approximate saving: **1.303017025 seconds**.
- Candidate/original ratio: **0.4444840882**; lower means less modeled cost.

These are not paired before/after restore timings. The unchanged guard prefix
comes from only three actual ordinary checks of the selected graph; timing
variation in a roughly 70 ms prefix affects its 72-fold extrapolation. Monitoring
and the test observer contribute overhead. Episode residual includes unchanged
dispatch; a few added borrow branch/finally instructions are not isolated. The
6.094-second reported new-span envelope includes unchanged prefixes and is not a
rigorous upper bound on incremental work. The approximately 40.6-second observed
restore in this run is instrumented and is not itself an uninstrumented acceptance
result. The model provides a bounded reason to continue, not a universal speed or
profitability claim.

## Qualified native profile and fallback

Source review confirms raw admission requires the original CPython implementation
and version identities and exact CPython 3.12.13, pinned native helpers/descriptors,
and bounded recognized native proxy/ABC cache layouts. It probes only admitted
exact mapping proxies or the finite Mapping native cache state, preflights cache
sizes, uses native weakref dereference and existing cache witnesses, and fails
closed on changed identities/token/membership or unsupported layout. It does not
call arbitrary classification hooks to establish a new witness.

The behavior inventory checks the qualified runtime before building private
stdlib inventories. Only the explicit unsupported-profile exception disables its
baseline; source and root registration accept that disabled baseline and initial
issuance returns the original full path. Unknown genuine faults are not swallowed
as successful proofs. Once admitted, changed data/behavior/ownership fails the
operation rather than refreshing the proof. Ordinary public source validation and
all existing external/SQL/fence observations remain unchanged.

The earlier isolated unsupported-version probe demonstrated import/fallback wiring
on the verified 3.12.13 interpreter. It did not execute an actual Python 3.13 build.
The strict native profile means other otherwise-supported interpreters receive
full original validation with no promised performance benefit. Exact-source CI
and applicable normal validation remain required before integration.
