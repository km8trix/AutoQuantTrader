# Independent assessment: original daily identity measurement

2026-09-26. Inputs: `daily-identity-original-first.json` and its `.log`, the reviewed observer/decision assessment, PLAN A2.4, and the existing failed Linux `linux-profile-2a9fc2c/profile.json`/`test-exit.json`. Read-only interpretation; no repeated fixture, repository change or new proof implementation.

**The measurement answers A2.4's original-path questions. It does not provide sufficient net-benefit or admissibility evidence to extend the production proof scope. Preserve the original daily checks; do not infer approval or automatically implement the proposed daily proof.**

## Result and arithmetic verified

The JSON reports `capture_status=valid`, `observation_extent=complete_execute`, no diagnostic faults and `test_exitstatus=0`. The log independently reports **1 passed in 246.33s**. All nine before/after hashes match each other and the current files. The observer and mechanics hashes match the independently reviewed frozen versions:

- Observer: `8f01789d2b3cd8f9cde5957c82060c274e4093541bbcc2567f7b0fe947641691`.
- Mechanics: `9cb4f7cdbf2ed47cd067ebbb27dcc974b4369dc1209e3ed4a8edc9c67de9cfa8`.

The 313 started spans all returned; 626 events equal one start and one terminal event per span. These comprise one execute, 24 borrows, 72 first/72 second public calls and 72 first/72 second builder calls. Each completed borrow therefore has the expected three checks at each position. No selected span unwound. All 144 public calls used the existing attempt-proof wrapper route; zero used its ordinary fallback. This route observation does not substitute for proof authority, but the original calls and complete test returned successfully. There were 94 excluded builder calls, without counter saturation; their cost must not be attributed to the proposed seam.

| Observed original work | Returned inclusive seconds |
| --- | ---: |
| Selected factory execute | 44.306357708 |
| 24 selected borrows | 17.428821582 |
| Both public daily check positions together | 2.465310748 |
| Both builder positions together | 2.167500330 |
| One scalar summary's observer work | 0.010365000 |

The two builder-position totals are disjoint and may be summed; the two public-position totals likewise. Builder, public, borrow and execute spans are nested and must not be added together. Builder mean is 15.052ms across 144 calls; public mean is 17.120ms. The builder sum is 4.892% of this instrumented execute, and the public sum is 5.564%. These are observed local proportions, not predicted savings. The public total includes ownership/comparison/observer work, some of which must remain. Any new issuer, fresh data/behavior checks, use lifecycle and retirement would consume time; zero-cost elimination is not the proposed design.

The builder timer stops before the one summary, while enclosing spans include its cost. Global filtered unwind monitoring contributes additional unisolated overhead. The 246.33s whole-test duration includes signed-history setup and other work outside execute. Factory close is not separately instrumented; the successful original test outcome is the available cleanup evidence.

## Shape and simultaneous budget

The first summary is `public_returned`, so this vector completed its original public identity comparison; it is no longer provisional. Its 54,690 returned bindings match the stored original vector length. The histogram sums exactly to 54,690; `seen_size=9,356`. The 9,923 unknown edges are 18.144% of the vector. They are unclassified by the deliberately finite inventory, not proved unsupported.

Existing attempt-proof arithmetic is internally consistent:

| Original charge | Containers | Bindings |
| --- | ---: | ---: |
| Data | 4,852 | 55,929 |
| Source behavior | 1,334 | 5,110 |
| Root behavior | 1,153 | 4,452 |
| Root reserve | 32 | 512 |
| Source reserve | 16 | 256 |
| **Total** | **7,387** | **66,259** |
| Original cap | 16,384 | 131,072 |
| **Remaining** | **8,997** | **64,813** |

A hypothetical design charging one new binding per original vector edge would use 54,690 of the remaining 64,813, leaving **10,123 bindings before any additional schema, behavior, context, temporary or bookkeeping charges**. It is therefore not rejected by that binding-only screen, but is not shown to fit either. A design charging one container per `seen` entry would exceed the remaining container allowance by 359 before further charges; that rejects only that stated layout. The original `seen` set includes visited opaque leaves and is not a proposed proof-container inventory.

Histogram counts describe repeated edge types, not unique graph nodes. They do not establish original schema/field access, exact dict backing of proxies, class/ABC witness availability, cycle treatment, permitted opaque-leaf behavior or the complete simultaneous allocation peak. The attempt canonical proof's profile remains semantically different from daily identity traversal. No graph admission or new proof charge follows from these counts.

## Linux comparison is descriptive only

The earlier Linux cProfile was valid but its original execute failed: 12 borrow entries and 36 attempt private-check entries were observed, with execute inclusive time 63.053s and log restore elapsed about 63.075s. Entries alone did not establish returns. Its identity-builder row was 6.879s across 109 mixed calls, and public daily row 6.853s across 99 mixed calls; those rows were not restricted to these two selected positions or this selected snapshot.

The new local result records 24 completed borrows and 144 selected successful daily comparisons under different instrumentation and a different execution environment. It is not a before/after pair. Do not divide the timings, extrapolate a Linux saving from the local percentages, scale the 12-entry failure into a complete run, or claim the daily proof would repair the unchanged lease/deadline failures. The result also does not close the separate worker observation failure.

## Decision implication

A2.4 can record a reviewed, valid, source-bound original-path measurement. A2/A2.3 and failed Linux acceptance remain open. The narrow daily seam has measurable cost, but this result supplies neither a demonstrated complete-proof speedup nor a qualified graph and joint resource budget. On present evidence, the bounded candidate is **insufficient for automatic production expansion**.

No repeat of this diagnostic is justified by the questions it was designed to answer. A further daily-proof experiment would require a separate concrete scope decision acknowledging its new daily-owner authority and stricter post-issuance hook/schema contract, followed by actual complete-cost/admission evidence within the unchanged shared caps. The current result is not that decision and does not justify increasing limits, skipping checks, extending to public/prepared/live paths or creating a generic graph-proof framework.
