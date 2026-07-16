# Reconciliation mismatch

1. Enter `RECONCILING` and block new exposure.
2. Connect to the broker event stream and buffer updates.
3. Fetch paginated account, position, open/recent order, fill, fee, dividend,
   corporate-action, and other activity snapshots with overlap.
4. Apply stream and snapshot events through the deduplicating inbox and shared
   reducers.
5. Repeat until two views converge or the reconciliation deadline expires.
6. Classify each difference as bounded provider lag, known external activity,
   recoverable local projection error, or critical unexplained activity.
7. Rebuild projections from immutable ledger/events when local corruption is
   suspected; do not edit positions directly.
8. Any unexplained broker activity or unresolved economic difference transitions
   the account to `HALTED` and requires operator disposition.
9. Resume only after a clean barrier, current market data/clock, and explicit
   re-arm.
