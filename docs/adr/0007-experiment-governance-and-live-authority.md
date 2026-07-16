# ADR 0007: experiment governance and live authority

- Status: Accepted
- Date: 2026-07-15

## Context

Repeated strategy trials can leak holdout information and inflate confidence.
Separately, a profitable research result must never grant broker authority by
itself.

## Decision

Every research attempt belongs to an immutable experiment family that records
completed, failed, canceled, and abandoned trials. Dataset manifests, feature
artifacts, code and runtime digests, parameters, random seeds, costs, validation
windows, multiple-testing treatment, and holdout access are durable provenance.
Final-holdout access is audited and promotion criteria are frozen before reveal.

Research promotion, paper arming, and live arming are separate human decisions.
No metric, scheduled job, process restart, deployment, or paper result may
implicitly cross those boundaries. Live requires a signed candidate artifact,
completed paper-soak evidence, a distinct live-environment promotion record,
live-scoped credentials, current operational readiness, and an explicit human
arm action. Pause, halt, process restart, or readiness loss clears runtime
authority; recovery requires reconciliation and manual re-arm.

## Consequences

Evidence is always labeled as backtest, replay/shadow, paper, or live-canary.
The application may automate evidence collection and gate evaluation, but it
cannot automatically authorize live trading.
