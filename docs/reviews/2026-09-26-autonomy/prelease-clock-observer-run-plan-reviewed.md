# Original CLOCK observation: exact run plan

2026-09-27. Owner-approved A2.6 original-only study. This records the command before one genuine run. Final independent frozen-code/mechanics review is required before root releases it. No substitution or acquisition change.

Frozen observer SHA256: `71b13b67ae6a5293bf1c979a044e2ceacacdac6b93e6695673e6b83b4a73246c`.
Frozen primary mechanics SHA256: `15f26dcc27a8a53552358c5c5e1c56fb0e0a742e1d2040397cb9506b74f91149`.
Production source remains unchanged from tested `26631c6`; current checkout HEAD `e83d0ac` adds study documentation only. Architecture passed before project imports. Primary mechanics: 29 passed; exact node collection: 1 collected in 3.05s.

Run from `/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development`. No parallel CPU-heavy tests. Preserve original 60-second lease, 120-second operation wall timer, applicable 150-second parent limit and all original worker/resource limits; the fixture setup/teardown are outside the execute measurement. The ordinary pytest result remains authoritative.

```sh
env -i PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/private/tmp/aqt-autonomy-audit:/Users/spencer.karrat/Documents/AutoQuantTrader/autonomous-development PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 TZ=UTC AQT_PRELEASE_CLOCK_OBSERVATION_PATH=/private/tmp/aqt-autonomy-audit/prelease-clock-original-first.json /Users/spencer.karrat/Documents/AutoQuantTrader/.wave4-runtime/2026-09-13/venv/bin/python -B -m pytest -q -p no:cacheprovider -p aqt_prelease_clock_cost tests/integration/test_continuous_simulation_factory_outcome.py::test_actual_signed_retained_outcome_restores_with_original_utc_and_lease
```

Capture stdout/stderr in a new `prelease-clock-original-first.log`, preserving the process exit code; refuse either existing output before launch. The JSON is exclusive mode0600 after test/teardown, <=64KiB. No raw payload, account/stream ID, object/frame ID or exception text enters that metadata. Group digests remain internal and are not equality/origin proof.

Question: returned disjoint direct decode+outer encode costs for CLOCK records under the original dedicated factory journal, grouped by first versus subsequent successful observed digest group. Parent inclusive cost is not added to children. All validators, source/SQL/fence reads, cleanup and assertions remain. A failed/partial/invalid capture is preserved, not rerun automatically or extrapolated. A completed instrumented observation is neither net savings nor Linux acceptance. Preparation, acquisition and complete candidate costs remain unmeasured.
