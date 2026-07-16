# Risk controls and kill states

## State meanings

- `PAUSED`: blocks new exposure; cancels and authorized reduce-only actions stay
  available.
- `DRAINING`: cancels working orders and completes only after terminal broker
  state plus clean reconciliation.
- `FLATTENING`: cancels working orders and repeatedly reconciles toward zero
  under the dedicated flatten policy. It may finish with reported residual risk
  if markets are closed, halted, or illiquid.
- `HALTED`: blocks strategy submissions. Separately authenticated cancel and
  emergency reduce-only actions remain available.

## Operator procedure

1. Prefer `PAUSE` or `HALT` immediately when state is uncertain.
2. Confirm the durable command receipt and authoritative state transition.
3. Inspect data, broker, database, lease, unknown-order, and reconciliation
   health before choosing drain or flatten.
4. For flatten, type the account/environment confirmation and reauthenticate.
5. Monitor every cancel/fill and the residual position report.
6. Use the broker dashboard/manual channel if the application or database is
   unavailable.
7. Never auto-resume. Re-arm requires current readiness, clean reconciliation,
   incident disposition, and authenticated human approval.
