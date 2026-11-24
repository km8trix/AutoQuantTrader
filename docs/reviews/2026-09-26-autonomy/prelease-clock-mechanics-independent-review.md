# Independent CLOCK observer mechanics review

2026-09-27. Reviewer: independent spec/plan audit worker. **No blocking mechanics finding.** The frozen observer is suitable for the parent's separately controlled single original-only measurement, subject to its reviewed run plan. This review does not release a fixture itself or qualify a pre-lease reuse predicate.

Reviewed the plan, frozen temporary observer and author's synthetic tests. Added only `test_aqt_prelease_clock_cost_independent.py` under the audit directory. No production/repository edits, project imports, source substitution, native cache probing or original retained fixture. The test harness uses primitive fake classes and functions and never accesses original ownership registries.

## Independent execution

Exact command run from `/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development`:

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/private/tmp/aqt-autonomy-audit PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -B -m pytest -q -p no:cacheprovider /private/tmp/aqt-autonomy-audit/test_aqt_prelease_clock_cost.py /private/tmp/aqt-autonomy-audit/test_aqt_prelease_clock_cost_independent.py > /private/tmp/aqt-autonomy-audit/prelease-clock-mechanics-independent-tests.txt 2>&1
```

Result: **42 passed in 0.11 seconds**, comprising 29 author cases and 13 additional independent cases. CPython 3.12.13, sanitized environment, no plugin autoload and no pytest cache. No architecture check was needed for this run because neither test module imports project code.

## Verified mechanics and interpretation

- The original direct-child decoder and outer encoder spans are disjoint. Encode nested within decode is excluded from its own selected span; its time remains inside decoder time. Parent-inclusive time must not be added to children.
- Successful child work enters eligible totals only when its exact original CLOCK validator parent returns. The author's decode-success/outer-failure and both-children-success/parent-failure cases pass. Independent success→failure→success verifies only the two successful parents contribute, with one first-success and one repeated-success allocation.
- Failed-only groups contribute no successful first/repeated work. Identical payloads under two different record IDs form one payload bucket and two observational record buckets, not a repeated-record success. The report does not emit original record IDs, payloads or digest keys. Grouping is explicitly collision-limited and cannot prove exact bytes, row identity, pre-acquisition availability or ownership.
- Decoded values are released after their parents return; the observer retains no tested decoded instance, frame, original owner or exception. No extra original calls occur.
- A second selected execute still runs normally but invalidates the one-run diagnostic. Foreign operation/owner/thread cases remain excluded or separately classified by the author tests.
- Fixed span/event/depth/key/hash/payload bounds invalidate/truncate rather than interrupting the original computation. Exact boundary cases pass; output byte overflow is rejected before creating a file. Exclusive output rejects an existing path.
- Partial installation failure cleans registered callbacks and frees the tool. Ordinary stop attempts every mask, callback and free operation even after cleanup failure. Existing occupied tool and profiler are preserved. Hook-generator close cleans the monitor.
- Original TimeoutError, KeyboardInterrupt and SystemExit identities survive a new observer SystemExit during their unwind. An original KeyboardInterrupt also survives monitor cleanup failure during execute unwind. Entry/return observer faults propagate and mark the diagnostic invalid; preserving an already-unwinding original failure is explicit.
- Independent source-manifest checks cover every declared source plus the observer/author test files, detect a changed codec file and invalidate the report. The measured report will bind its real before/after sources, rather than these synthetic fixture files.
- A valid complete execute observation can coexist with a failed original teardown: the report preserves exit status 1, teardown failure and `acceptance=false`. Valid capture is not successful restore, completed lease release, qualified handoff or Linux acceptance.

Monitoring callback/hash overhead remains present. Global filtered unwind events are not bounded by selected-event counts. First/repeated successful codec totals are observed work, not net savings; new preparation, capture, behavior qualification, matching, acquisition ownership, overlap and cleanup costs remain unmeasured. The observer excludes setup/construction and outside-execute cleanup timing; original test/teardown status remains authoritative. No result interpretation beyond these limits is approved by the synthetic checks.

## Frozen artifact binding

The observer and author's test hashes still match the ready signal after the independent run. Paths below are relative to `/private/tmp/aqt-autonomy-audit`.

```
71b13b67ae6a5293bf1c979a044e2ceacacdac6b93e6695673e6b83b4a73246c  aqt_prelease_clock_cost.py
15f26dcc27a8a53552358c5c5e1c56fb0e0a742e1d2040397cb9506b74f91149  test_aqt_prelease_clock_cost.py
170100c286202a606ceb041140b8b0fd30bd86fde1afba42877f29858ba53f72  test_aqt_prelease_clock_cost_independent.py
a95a04c8efbf2682ab6651b8bd5b7e4490b090b1c1332b4485f40e6f10b6295f  prelease-clock-mechanics-independent-tests.txt
2fe60cb8addaf2b7552ac258e5ed8c99c8ceb606113201c7a7a1ed18efb34807  prelease-clock-observer-plan.md
c26e4722497484173f3b854bdf1b83e564dcc94fc5f2dcb467ebcf7991c67767  prelease-clock-observer-run-plan.md
```
