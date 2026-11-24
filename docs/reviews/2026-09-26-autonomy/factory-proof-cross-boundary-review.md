# Factory proof cross-boundary review

Read-only review of root/source lifecycle by spec_plan_audit, 2026-09-26.
The reviewer implemented the separate behavior helper; its independent review
belongs to architecture_audit. This document does not self-approve that helper.

## Reviewed source checkpoint

- `packages/persistence/continuous_integrity.py`: `0713cc6c55b35a7cd93eb89cb92cc4639ad9ba249c4d0f4389390ebeff78023d`
- `packages/persistence/continuous_runtime_attempt_sources.py`: `e12577f7fdf5519fb60d963e48da9d3034f5a11e050f5fc7cc4a752565688d1f`
- `packages/persistence/_factory_attempt_fingerprint.py`: `4db8b5e9e41f790a39031f884f0a17a548352059ab824f42f983e2affd1d2e56`
- `packages/persistence/_factory_attempt_behavior.py`: `48b76a5c4d7e0eac6b08c4c3eb5f0d542a94eec0b4a681a6337727195e53108a`

## Result and limits

No remaining source-level lifecycle blocker identified at this checkpoint under
the approved ordinary-Python integrity and trusted private verifier/baseline/
registry fault model. This is not genuine-path acceptance, a startup speed claim,
or protection against arbitrary replacement of the verifier and its stored
baseline. Actual nonempty signed-history adverse tests, complete proof economics,
original retained restore, and exact-source Linux acceptance remain required.

## Preserved original boundaries

- The public source `require_resolved` remains the ordinary full path. The new
  private body preserves `_require`, account-reference, historical-descriptor,
  and outcome guard order, substituting only its final resolved fingerprint.
- Existing full original-daily entry checks remain before any proof. Issuance
  performs an additional full original owner check under an unchanged ABC token;
  the original outer-tuple visit supplies the native negative-cache witness.
- Each of the three original borrow graph boundaries remains. Object rereads,
  committed-account observation checks, daily SQL rechecks, coordinator
  revalidation, and actual fence observations remain at their existing sites.
- `_validate_original` retains its full `_require_daily_episode` before
  `_recheck_final`; later full factory terminal guards remain. Proof retirement
  precedes `_FactoryResult` and handoff-structure construction.
- The source deducts both behavior inventories plus root/source lifecycle
  reserves from the existing container/binding caps before raw-data admission.
  The actual raw-data and handoff inventories do not overlap in retained lifetime.

## Ownership and cleanup review

- Issuance requires the actual registered factory reader, entering operation,
  original thread/daily episode/source/value, HALTED state and composer binding.
  Possession of an opaque context/proof alone supplies no authority.
- A ready/checking/complete one-use permit binds one original borrow. Reentrant,
  copied, foreign, stale or incomplete use cannot return an accepted source.
  Rejected use poisons its owning operation through the original failure path.
- Source issuance registers only after full authentication and data admission,
  rolls back its registry entry on any later BaseException, and uses a weak proof
  callback to release an unreturned token. The source state does not strongly
  retain its owner or factory context.
- Root retirement retains retiring authority while invoking original source
  revocation even after a damaged borrow. Source retirement authenticates exact
  source/context then pops its entry in finally. Root then clears only its own
  context/reader/daily/use bindings, without traversing foreign operations.
- Existing primary exceptions remain primary. Normal cleanup failure prevents
  successful completion. Original failure/retirement callback identities are
  saved at module registration; changed callback code is not executed as cleanup.
- Unsupported method/runtime/data profiles before issuance keep full validation.
  An issued proof is not refreshed or reissued after a failed check.

## Findings corrected during review

1. Failed-borrow retirement previously discarded root authority before source
   revocation. The revocation now occurs before root registrations are removed.
2. Contextmanager wrapper code did not cover its generator closure. Original
   wrapped generators and required permit/failure predicates are explicit
   dependency entries; composer class lookup is also bound.
3. Instance method shadows bypass class-namespace checks. Bounded exact reader,
   composer and source dictionaries now reject method shadows before the new
   path invokes those methods; raw original descriptors avoid prequalification
   property callbacks.
4. Rebound cleanup module attributes could execute replacement callbacks after
   behavior rejection. Cleanup now uses saved original callable identities.
5. Raw data review identified quoted-key ordering, enum dataclass-marker
   classification, and proxy-backing conversion-role gaps. Their owners applied
   fixes; pure adverse coverage and actual admission are separately validated.

## Reviewer-local validation

- Personal architecture check passed before project imports.
- Behavior helper: 23 adverse tests passed in 1.35 seconds, scoped Ruff and format
  checks passed, scoped mypy passed. The test file is owned independently by
  validation_audit. Independent behavior source review is architecture_audit's.
- An isolated sentinel probe simulated an unsupported version only while
  importing the behavior helper, restored actual CPython 3.12.13, and confirmed
  ordinary source/root imports succeed with both behavior baselines disabled.
  This establishes fallback wiring, not execution on an actual Python 3.13 build.
- No provider calls, credentials, live accounts, process activation, graph-value
  output, or heavy retained fixture run was performed by this reviewer.
