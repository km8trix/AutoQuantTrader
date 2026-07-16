# Unknown broker submission

Use this runbook when a broker submission response is ambiguous or times out.

1. Mark the immutable attempt `UNKNOWN`; do not create a new client order ID.
2. Block new account exposure while preserving cancel and authenticated
   reduce-only recovery actions.
3. Query the broker by the same deterministic client order ID with bounded
   backoff. An immediate “not found” is not proof of rejection.
4. Buffer and deduplicate broker stream events during lookup.
5. Fetch recent orders, fills, and activities with an overlap window.
6. If accepted, bind the broker order ID and continue normal lifecycle handling.
7. If rejected, persist the broker evidence and release reservations.
8. If still unresolved at the configured deadline, enter `HALTED`, alert the
   operator, and reconcile through the broker dashboard/manual channel.
9. Record the incident and add a regression fixture before re-arm.

Never blindly retry a broker side effect.
