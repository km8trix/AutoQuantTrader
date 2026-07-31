# Phase 5 deterministic fault drills

This runbook executes the bounded local Phase 5 fault evidence that can be
proved without a broker, alert provider, telemetry backend, deployment, secret,
or new control-policy decision. It is a regression drill, not a paper-trading
game day and not evidence that an external operator received an alert.

The machine-readable catalog is
`tests/fixtures/phase5_fault_drills.json`. Its validation test rejects stale
test node IDs, duplicate drill identities, missing required failure classes,
or any deployment drill represented as local evidence.

## Run the exact catalog

From the repository root:

```console
.venv/bin/python scripts/run_phase5_fault_drills.py
```

The runner first executes the catalog validator, then every unique exact pytest
node referenced by the local drills. Parametrized threshold and re-arm cases
remain parametrized; the runner does not replace them with a single selected
example. A passing run means only that all checked-in
deterministic contracts still hold at the tested fake-clock and SQL boundaries.

Do not update a node ID merely to make catalog validation pass. Review the
renamed or removed test and confirm that its replacement proves the same
failure and expected outcome.

## Local drill matrix

| Drill | Injected or replayed fault | Required local outcome |
|---|---|---|
| Strategy claim and restart | Stop after durable claim or interrupt the runner | No second runner call; pending until the fixed boundary; one deterministic `CRASH` recovery |
| Strategy start authorization | Race or replay the winning permit/sealed proof, cross a process boundary, delay to one-second equality, or interrupt request preparation | Exactly one supported runner use; every loser fails before `Popen`; retained claims recover without rerun |
| Strategy finalization boundaries | Stop before commit, lose the response after commit, or abort the finalization insert | Pre-commit recovery never reruns; post-commit retry returns the retained result; SQL facts roll back together |
| Strategy current-fence recovery | Cleanly hand ownership to a new fencing generation before orphan recovery | Only the new current fence may record recovery; the runner remains uncalled |
| Alert primary and fallback | Confirm/fail primary or first evaluate exactly at 15 seconds | Confirmation closes delivery; failure waits without I/O; equality selects only fallback |
| Alert unresolved restart | Restart after a claim without a result | Authenticate history first and never resend the unresolved claim |
| Alert atomic total-failure control | Replay a terminal escalation failure, reach 30-second equality with an unresolved escalation, or attempt the retired split writer path | A provider-called terminal result waits for durable replay; the same-store atomic binder appends exactly one fixed `PAUSED` receipt/control command; the legacy split path fails before either callback |
| Advanced-risk enforcement | Evaluate equality, pretrade breach, and runtime breach | Strict equality stays in the lower band; pretrade rejects without holds; runtime trips to greatest severity |
| Advanced-risk atomic rollback | Reject evidence or abort a late admission insert | No partial advanced-risk, Phase 2, control, admission, or outcome prefix |
| Data gap/unavailable | Break a causal chain, omit bars, expire quote freshness, or mark applicable evidence incomplete | Preserve unavailable/gap state; reject pretrade and request PAUSED at runtime instead of inventing a value |
| Uncertain order exposure | Retain pending cancel or unresolved `UNKNOWN` state | Keep exposure reserved/frozen and reject re-arm |
| Database and lease loss | Fail the database probe, expire a lease, or replace its generation | Remove readiness/effect authority and permanently reject the historical fence |
| Manual re-arm only | Recover health, complete a later strategy run, restart, or omit the verifier | Preserve the non-running head until a human request carries fresh server-constructed proof |

The alert cases exercise the fixed local `PAUSED` policy and migration 0032's
same-transaction failure receipt/control binding. That local policy remains
unwired and is not deployment authority. The SQL admission fault uses a
temporary SQLite trigger and asserts exact pre-call row counts after rollback;
it does not alter migrations or production schema.

## Failure response

If any local drill fails:

1. Treat the affected safety property as unproven.
2. Do not enable advanced-risk enforcement, assign a paper account, or infer
   `RUNNING` from an unavailable control/readiness result.
3. Preserve the failing database and sanitized test output when practical.
4. Identify the earliest durable prefix that differs from the matrix outcome.
5. Fix the contract or implementation and rerun the exact catalog.
6. Use only the separately authenticated manual re-arm workflow after its full
   authoritative proof is available; a green rerun is not re-arm authority.

## Evidence this runbook does not claim

The catalog deliberately marks the following drills `not_run`:

- delivery through owner-approved independent primary/fallback alert providers,
  destinations, recipients, escalation roster, secret references, route
  probes, and deployed worker cadence;
- approval to activate the fixed `PAUSED` total-alert-failure policy with its
  exact authority and policy digests;
- telemetry exporter/backend authentication, sampling, retention, access, and
  outage behavior;
- the exact paper-account deployment with authoritative SIP/NBBO, broker
  control, correction-safe fills, reconciliation, risk assignment, and signed
  strategy sandbox; and
- wall-clock kill-state, strategy-failure, alert-failure, data-gap,
  broker-disconnect, and risk-trip game days with audited response times and
  residual exposure.

Those are deployment or owner-authority decisions. Local fake clocks and
provider ports cannot close them. After those decisions are approved and the
authoritative components are deployed, record timed drill evidence separately;
do not rewrite the local matrix to imply external completion.
