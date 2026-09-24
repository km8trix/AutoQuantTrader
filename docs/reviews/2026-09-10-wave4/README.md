# Wave 4 — applied reconciliation and continuous simulation

Status: implementation in progress; no W4 exit gate is claimed complete.

Base: verified W3 merge `e1bcea18eaa18ad144bc3b03a4891d11ecdd9b06` from [PR #54](https://github.com/km8trix/AutoQuantTrader/pull/54). [Closeout verification](wave3-merged-verification.json) binds the identical tested/merged tree, 147 accepted artifacts and passing PR CI. Post-merge CI also passed all gates with 1,999 Python tests.

The [canonical plan](../../IMPLEMENTATION_PLAN.md#19-current-wave-4-handoff) controls scope and ownership. Root integrates the existing causal engine and accounting/attempt boundaries. A supplies applied facts/reconciliation, B serialized account risk/commands, and C independent stateful venue/forward observations. Initial work defines bounded immutable records and pure checks before shared persistence/transport integration.

Required outcomes: a restartable session using the sole economic engine; atomic account capacity under competing owners; explained independent venue versus ledger comparisons; retained UNKNOWN/manual/correction/cancel/gap behavior; stale-input denial while observations continue; actual captured-session decision replay and separate authorized provider-read reconciliation. Fixture success cannot substitute for provider identity, rights, cash/liability, coverage, quota or quote freshness evidence.

Source contracts, implementation checks and independent acceptance evidence will be bound to the actual revised source. Earlier W3 source pins remain unchanged. Trading authority stays false.

Read the [September 12 offline progress record](offline-progress-2026-09-12.md) for the finite coordinator, Stop and source-boundary checks, current session/resource findings and pending owner inputs. Component passes and test collection do not close this wave.

The [September 20 recovery record](recovery-2026-09-20.md) identifies the persistent exact source trees, durable source checkpoint, reverified runtime and limits of the recovered task history. Use that record for current paths; the former temporary workspace files are missing.
