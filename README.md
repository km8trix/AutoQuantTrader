# AutoQuantTrader security-audit snapshot

This isolated branch carries current application source for the requested Daybreak
security audit. It is not a release, deployment, production merge, or evidence of
operational readiness. See `AUDIT_SCOPE.json` for exact file hashes and scope.

The source checkpoint is `f016c30d5895bae88c85089046235c92c22af1df`, plus the
current missing-head negative integration test. Source files were copied without
code changes. This branch has no local development ancestry. Private review
history, runtime data, credentials, and uncommitted planning documents are omitted.

## Safety boundary

The application remains HALTED with trading authority false. Do not contact
providers, read real credentials or account data, start services, place orders,
change financial limits, deploy, merge, or activate the application. Existing
retained-history, diagnostic, fixture-budget, runtime, and release holds remain.
Security scanning does not authorize those actions.

## Coverage and checks

Includes application/packages, tests and synthetic fixtures, native and build
support, scripts, infrastructure definitions, dependency locks, API schema, and
frozen product contracts. The example environment file contains placeholders.
Targeted publication checks found no live credential patterns or private local
paths. This is not a proof that the source is vulnerability-free.

No application tests were rerun for publication. The checked-in CI triggers only
on pull requests, pushes to main, or explicit dispatch. No PR, merge, or workflow
dispatch is part of this snapshot.
