# Independent A2.6 CLOCK measurement assessment

2026-09-27. **Reject this CLOCK-only pre-lease canonicality candidate on observed economic grounds.** The unchanged original restore spends only 8.204370 ms in repeated successful selected codec work, about 0.01858% of its 44.154831-second instrumented execute. Even the complete selected validator total is only 9.688457 ms and contains checks the proposal preserves. This does not justify further cache/behavior qualification, acquisition handoff implementation or another fixture for this candidate.

This is not a measured negative speedup, a universal statement about pre-lease designs or a claim that resources exceed their caps. No substitution or pre-lease prototype was run. The completed observation resolves the prior missing CLOCK-specific cost question; it does not retroactively make the earlier unknown cost a valid rejection reason.

## Independent evidence verification

Read the actual JSON and original pytest log. Verified their SHA-256 values, the observer/test frozen hashes, equality of all 14 recorded before/after source hashes, and all 14 hashes against the current source/script files. No mismatches. Independently recomputed scalar sums, event/span reconciliation and the percentages below using only Python standard-library JSON/hash/arithmetic operations. No project import, test run, fixture, cache probe or repository edit occurred during this assessment.

- Original target: `tests/integration/test_continuous_simulation_factory_outcome.py::test_actual_signed_retained_outcome_restores_with_original_utc_and_lease`.
- Original log: **1 passed in 242.12 seconds**. JSON exit status 0; setup, call and teardown all passed.
- Capture status `valid`, extent `complete_execute`, `acceptance=false`; one execute entered/returned, zero unwind.
- Diagnostic faults empty; incomplete count 0; foreign-thread count 0.
- All 61 selected CLOCK validator calls returned, as did all 61 selected direct decoder and 61 selected outer encoder calls. No failed-only groups.
- Counters reconcile: 2,077 entered spans and 2,077 returned spans, 4,154 start/end events. Peak depth 3. Counts remain below fixed 16,384-span, 65,536-event and depth-8 limits.
- Three record digest groups and three payload digest/length groups use six keys, below the combined 4,096-key cap. Hash input 76,494 bytes is below 64 MiB. Fixed input checks admitted payloads under the existing journal bound. These are diagnostic limits, not a production resource qualification.

## Observed timings and arithmetic

| Quantity | Observed time |
| --- | ---: |
| Original instrumented execute | 44.154830875 s |
| Whole CLOCK validators, including preserved work | 9.688457 ms |
| Direct decoders under successful CLOCK parents | 7.118955 ms |
| Direct outer encoders under successful CLOCK parents | 1.488456 ms |
| Disjoint selected codec total | 8.607411 ms |
| First successful codec work per record group | 0.403041 ms |
| Repeated successful codec work | 8.204370 ms |
| Hash/group entry bookkeeping | 0.277794 ms |

Exact identities:

```
7,118,955 + 1,488,456 = 8,607,411 ns
403,041 + 8,204,370 = 8,607,411 ns
8,204,370 / 44,154,830,875 * 100 = 0.018580911391612255%
8,607,411 / 44,154,830,875 * 100 = 0.019493701661698417%
9,688,457 / 44,154,830,875 * 100 = 0.021942009080337124%
```

The 61 successes contain 58 repetitions beyond the first success in each of three observed record groups; maximum successful group repetition is 31. Distinct observed payload groups total 3,570 bytes; total payload bytes seen across admitted calls are 72,590. These are digest-based observational buckets. They are not proof of distinct SQL row count, exact-byte equality, original source ownership or pre-acquisition availability.

The decoder's own internal encoder remains inside decoder time. The separate outer encoder is its sibling call under the original validator; it is not added a second time inside decoder cost. The inclusive whole-validator total is not added to either child sum. Every reported selected child counted toward eligibility only after its exact original validator parent returned successfully.

## Why the candidate stops here

The proposed work was specifically typed canonicality of fixed CLOCK journal payloads at `SqlDurableJournal._validate_record`, not generic canonical encoding, arbitrary schemas, object validation or account restoration. The measured repeated part is approximately eight milliseconds in this completed local original workload. The first per-group work would still have to run during preparation. Every extra pre-lease capture, fixed transition witness, fresh coherent comparison, cache/behavior qualification, per-use matching, retained-byte accounting and retirement has nonnegative cost and remains unmeasured.

The observation does not prove that those costs exceed eight milliseconds, and no such claim is needed. The selected work is too small to justify the new contract and machinery as a repair for the known retained-startup failures. Even treating all selected validator time as removable would be an overly generous approximately 9.69 ms observed envelope, still only approximately 0.02194% of execute, and the proposal explicitly preserves part of that validator. Neither fraction predicts Linux behavior or a changed program's speedup.

Accordingly, do not implement or benchmark a CLOCK canonicality reuse proof, release another history fixture for this same question, increase caps, or expand automatically to other schemas. Stop this candidate before building the unqualified native-cache/behavior and acquisition-handoff machinery. The independent acquisition study and any other design must retain their own explicit scope and evidence; this finding grants no wider authority.

## Limits and preserved failures

- One instrumented local original run, not paired before/after performance or Linux acceptance. Execute includes callback overhead; selected spans exclude some entry bookkeeping but include nested callback overhead. Global filtered unwind overhead is not bounded by selected-event counts. No unprofiled saving follows.
- Setup/construction, new pre-lease work and outside-execute cleanup are not timed by this observer. The passing original test and teardown establish only their existing assertions, not a new preparation contract. Original 60/120/150-second applicable bounds remain unchanged.
- The 3,570 observed distinct payload bytes do not prove a new preparation's resource fit. Full retained/fresh snapshots, transition owner, behavior metadata, caches, temporary objects and overlap were not measured. No resource admission or cap failure is claimed.
- Other factory-journal and unclassified-owner validator totals remain outside this CLOCK candidate. They do not identify a new permitted schema or justify automatic expansion.
- Existing failed exact-revision Linux gates remain failed evidence. A local original pass and valid observation do not accept the current production pilot, repair those failures, confer trading authority or approve a production implementation.

## Frozen files

All paths below are relative to `/private/tmp/aqt-autonomy-audit`.

```
e6100ad083df91acaa79edc6958e617fba43e2ff6e51f1b651014b6ce462c768  prelease-clock-original-first.json
c9674d49ff12c97bd8d333ce0f9bc6e8bc1a5b5326a41b3ba5827621174cf832  prelease-clock-original-first.log
71b13b67ae6a5293bf1c979a044e2ceacacdac6b93e6695673e6b83b4a73246c  aqt_prelease_clock_cost.py
15f26dcc27a8a53552358c5c5e1c56fb0e0a742e1d2040397cb9506b74f91149  test_aqt_prelease_clock_cost.py
170100c286202a606ceb041140b8b0fd30bd86fde1afba42877f29858ba53f72  test_aqt_prelease_clock_cost_independent.py
b6d10e581717ad777f1c96f971e41c5397cce53c24068ad8ea3a05de1d580d4a  prelease-clock-mechanics-independent-review.md
```

The raw JSON contains the complete 14-file source manifest. All its values matched the recorded before/after manifest and current files during this independent review.
