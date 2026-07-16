# Startup and shutdown

## Startup

1. Confirm the paper/live hostname and account identifier.
2. Verify database, object storage, market-data, broker, clock, and alert health.
3. Acquire the account lease and new fencing generation.
4. Enter `RECONCILING`; connect and buffer broker events.
5. Run the convergent stream/snapshot reconciliation barrier.
6. Confirm there are no unknown submissions or unexplained external activities.
7. Load the signed strategy, data, risk, and runtime configuration.
8. Start in `SHADOW`; enter `RUNNING` only after explicit human arming.

## Graceful shutdown

1. Enter `PAUSED` to block new exposure.
2. Decide explicitly whether working orders should remain or be drained.
3. Reconcile all submission attempts, broker orders, fills, ledger, and positions.
4. Persist the final heartbeat and operator-visible state.
5. Release the account lease only after no broker call is in flight.
6. Verify the broker dashboard remains available for manual intervention.

Process restart never implies strategy resume.
