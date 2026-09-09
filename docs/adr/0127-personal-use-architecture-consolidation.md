# ADR 0127: personal-use architecture and roadmap consolidation

- Status: Accepted target design; implementation and operational qualification pending
- Date: 2026-09-08
- Review baseline: `107fa79`

## Decision

The owner requested an independent personal-use design, comparison with existing plans/code, and one consolidated plan/architecture, with proposed improvements taking priority. Adopt [ARCHITECTURE.md](../ARCHITECTURE.md) as the sole current target and [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md) as the sole wave roadmap. The [design review](../reviews/2026-09-08-design-review.md) records the comparison and code evidence.

This ADR records precedence rather than duplicating the design or backlog:

- Retain the single-owner/account/strategy ETF cash scope, E*TRADE target, financial reducers, PostgreSQL persistence, atomic reservations and uncertainty invariants. Daily-first implementation narrows the initial cadence.
- Add a versioned exploratory historical-data class and owner-reviewed admission without claiming unavailable historical PIT evidence. This changes future research eligibility requirements associated with ADRs 0002/0008/0009 and later captured-data qualification, not the meaning of historical provider proofs.
- Replace multiple fixture product paths with one causal economic engine. Preserve golden cases as tests and existing ledger semantics.
- Add a supported daily risk profile while preserving the historical ADR 0068 paper profile and all existing reservation/policy bindings. No live limit inherits approval from paper.
- Defer the custom native trusted-time/signing/remote-anchor lifecycle, including the future activation program in ADRs 0092–0095 and 0097–0126 where they concern that lifecycle, outside personal-v1 requirements. Standard time health, ownership, stop, recovery and replacement tests are mandatory. E*TRADE and research ADRs in that numeric interval retain their unrelated semantics.
- Supersede the future topology assumptions in ADRs 0005/0088 where they require remote identity, a particular cloud/paper provider or historical smoke composition for the new personal runtime. Preserve scoped historical smoke records.
- Retain ADR 0096's broker-specific Preview/Place/Cancel and uncertainty boundaries. No second broker becomes a prerequisite.
- Replace old phase/subphase/wave scheduling with the current plan's outcome waves and global maximum of three additional tasks under one orchestrator.

## Consequences

Existing accepted ADRs remain immutable records of the contracts and evidence they described. Where this target differs, this ADR and its linked canonical design take precedence for future implementation. An old implementation contract is not silently changed: its callers, data, policy and tests migrate through the relevant wave, and operational facts are requalified.

Only documents change in this planning revision. No code guards are bypassed, no native component/resource/worktree is removed, and no data source, broker request, runtime, live account or capital is activated. New operational permissions remain explicit and scoped. Historical signatures, source captures, paper limits and fixture passes do not transfer to the replacement runtime.
