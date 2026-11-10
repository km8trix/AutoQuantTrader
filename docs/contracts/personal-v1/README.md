# Frozen personal-v1 contract pack

Contract pack `personal-v1/1`, frozen at the completed Wave 0 contract gate on 2026-09-08. Reviewed code remains `107fa791bb52e9fa42cbce65992ea1ce9168834e`; these specifications do not implement or activate runtime behavior. [ARCHITECTURE.md](../../ARCHITECTURE.md) remains the only architecture; [IMPLEMENTATION_PLAN.md](../../IMPLEMENTATION_PLAN.md) remains the only delivery plan and status register.

| Supporting contract | Review purpose |
|---|---|
| [Scope/defaults](scope-defaults.md) | Daily ETF/cash/E*TRADE product, execution versus historical proxy schedule, research/evaluation/resource defaults and future external inputs |
| [Core/engine](core-engine.md) | Versioned data/run/report contracts, deterministic causal state, accounting/valuation/flow timing, evaluation and retention/caller map |
| [Economics cases](economics-cases.json) | Independent declarative numerical oracles for later implementation |
| [Account/runtime](account-runtime.md) | Daily risk producers, identities/reconciliation/tolerances, serialization, clock/secret/process boundaries and effect-specific broker recovery |
| [Native dependency map](native-dependency-map.md) | Active/runtime/build/schema/test/CI consumers and replacement gates; full compact [file inventory](native-dependency-files.tsv) |
| [Migration ownership](migration-ownership.md) | Exclusive files, shared-schema/migration sequencing, canonical engine/risk cutover and W1–W5 ownership |

[Baseline and preserved task closeout](../../reviews/2026-09-08-wave0/baseline.md) records exact input/document hashes, checks, limitations and the architecture checker failures. [Task closeout](../../reviews/2026-09-08-wave0/stale-task-closeout.md) preserves unfinished native work without treating it as accepted personal-v1 implementation.

The orchestrator resolved defaults and cross-lane interfaces through a two-worker review. New contract version identifiers in this pack are reserved normative targets; they are not claims that Python models, database tables, API endpoints or positive research admission exist yet. Existing persisted contracts retain their original semantics until versioned replacement and integration gates pass. History, factual timestamps, policy/attempt bindings, reservation holds and financial journals are never silently upgraded.

Where implementation reveals a necessary contract change, the orchestrator changes the affected specification/version and acceptance evidence before parallel consumers proceed. No unresolved owner choice prevents this Wave 0 freeze: actual access/rights/accounts/quotes/host inputs and live amounts are explicitly future qualification gates. Only a new user-authorized Wave 1 turn begins the next wave.
