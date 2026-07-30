# Operational runbooks

These runbooks are conservative defaults. Broker-specific commands, deployed
alert routes/recipients, telemetry export policy, authoritative re-arm
composition, and measured provider/deployment fault-drill results must be
supplied and exercised before paper-soak readiness.

- [Startup and shutdown](startup-shutdown.md)
- [Unknown broker submission](unknown-submission.md)
- [Reconciliation mismatch](reconciliation-mismatch.md)
- [Risk controls and kill states](risk-controls.md)
- [Operational control](operational-control.md) — local authenticated commands,
  proof-only re-arm, strategy-failure trips, and the provider-neutral alert
  boundary
- [Phase 5 deterministic fault drills](phase5-fault-drills.md) — exact local
  test evidence and the explicit boundary to unperformed deployment drills
- [Paper smoke deployment](paper-smoke-deployment.md) — supervised local Mac,
  Supabase Free, Sentry diagnostic preflight, explicit unavailable external
  notifications, and rollback
