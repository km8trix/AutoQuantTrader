# ADR 0122: bounded fixture economic-segment execution and isolation

- Status: Accepted
- Date: 2026-08-26
- Extends: [ADR 0117](0117-durable-fixture-segment-worker.md) and
  [ADR 0119](0119-authenticated-fixture-segment-provenance-views.md)

## Context

ADR 0117 can durably carry one repository-owned, parity-certified feature and
target transcript through a governed attempt. ADR 0119 can expose a narrow
authenticated proof view of that history. Both deliberately stop before
economic evaluation. Reusing the Phase 2 fixture backtest would merge different
governance, dataset, strategy, and report meanings, while accepting arbitrary
code, a caller-selected command, or a caller-selected fixture would cross the
still-open general research-execution boundary.

The next safe slice is therefore one closed economic model for only the exact
completed Phase 3F reference transcript. It needs a real process boundary and
enforced resource limits so an implementation cannot call an in-process
function an isolation gate. It must also remain an internal, recomputable
artifact rather than widening Phase 3G's intentionally redacted public views or
claiming that repository hashes authenticate an external tape.

## Decision

1. Define Phase 3H in `packages.domain.fixture_segment_economics` and
   `packages.application.fixture_segment_economics`. An economic request can be
   constructed only from an exact, fully revalidated, `COMPLETED` Phase 3F job
   projection and the exact `CertifiedFeatureTargetReplay` named by its target
   artifact. The request cross-binds the authenticated Phase 3F job, family,
   attempt, configuration, segment, governed completion receipt, target
   artifact, certification, and transcript roots. A queued, running, failed,
   corrupted, or transcript-substituted input fails before process launch.
2. Freeze the only supported model as
   `immediate-causal-close-zero-cost-v1`. It starts with exactly USD 100,000,
   treats every READY full target as an immediate long-only whole-share fill at
   that same causal complete batch's close, carries positions through WAITING
   rows, applies no fee, spread, slippage, dividend, corporate action, interest,
   or external cash flow, and marks the final position at the final complete
   row. It returns exact ending cash, market value, equity, net P&L, gross traded
   notional, trade and target counts, and final positions. All Decimal
   arithmetic is exact under the repository's 64-digit/e63 policy; floats are
   impossible.
3. Admit at most 2,048 complete rows and 64 canonically ordered instruments,
   with one stable nonempty universe, strictly increasing source sequence and
   causal time, unique target identities, at least one READY target, positive
   prices, and nonnegative whole-share targets. The canonical request is at
   most 256 KiB. Phase 3H does not generalize to fitted code, arbitrary
   strategy or fixture loading, universe changes, captured tapes, or caller-
   supplied economics.
4. Execute the request through exactly one repository-owned standalone stdlib
   child. The public function accepts only the completed projection and target
   certification. There is no public or internal parameter for executable,
   module, source code, argv, environment, working directory, fixture path,
   model, timeout, or resource policy. The parent resolves and hashes the one
   sibling child file and invokes the absolute current Python executable with
   exact flags `-I -S -B` and that absolute child path. It uses `shell=False`,
   `close_fds=True`, a new process session, three pipes, a newly created empty
   working directory, and a fixed minimal environment. Darwin's injected
   `__CF_USER_TEXT_ENCODING` value is reset to the same fixed child policy
   before input is read.
5. The child must successfully apply and read back every hard resource limit
   before it reads the request: two CPU seconds, 16 file descriptors, zero core
   bytes, zero regular-file output bytes, and zero child processes. Linux uses
   a 512 MiB address-space cap. Darwin uses a 1 TiB address-space cap because
   its process image maps the system shared cache into a very large virtual
   range; lower `RLIMIT_AS` values reject the already-started interpreter. This
   is an explicit coarse Darwin ceiling, not equivalent memory containment.
   Missing limit constants, unsupported platforms, setting failures, or
   readback differences fail closed; there is no reduced-isolation fallback.
6. The parent independently enforces a three-second wall deadline, 64 KiB
   stdout, 16 KiB stderr, and 256 KiB stdin. It reads both output pipes
   concurrently, starts a new process group, kills only that group on timeout,
   pipe failure, or output overflow, and performs bounded wait/pipe/thread
   cleanup on every normal and exceptional post-spawn path. Success requires a
   reaped zero-exit child, nonempty bounded stdout, and empty stderr.
7. Use a strict canonical UTF-8 JSON protocol with an exact field allowlist,
   duplicate-key rejection, no JSON floats or non-finite constants, an exact
   protocol version, a digest over the canonical request payload, and the
   Phase 3H semantic request identity. The child reports the fixed environment,
   exact read-back limits, and distinct child PID/session identity. Any missing,
   extra, malformed, noncanonical, cross-request, reduced-isolation, same-
   process, or same-session value fails closed as `protocol_error` without
   retaining raw stderr or exception text.
8. Independently recompute the complete economic result in the parent from the
   bound request. A child result can produce a
   `FixtureEconomicSegmentReceipt` only when it equals that recomputation and
   carries exact successful process evidence. The receipt is content-addressed
   and cross-bound to the existing authenticated Phase 3F/governance root. Its
   hashes alone do not authenticate an external source, runtime host, or tape.
9. Keep the receipt internal. Add no SQL table, migration, repository write,
   API, CLI, browser field, Phase 3G view, report download, comparison surface,
   promotion criterion, or deployment input. The child is unreachable from all
   application entry points and workers. Every captured-tape-evidence,
   promotion, public-view, provider-I/O, broker-effect, and trading-authority
   flag remains exactly false.

## Consequences

One already-governed repository fixture can now produce exact economic evidence
through a real bounded process and a strict independently checked protocol.
Completed Phase 3F lineage cannot be replaced by a plausible standalone JSON
result, and child crashes, timeout, resource overflow, diagnostics, protocol
drift, or missing limits produce no receipt.

This child is not a hostile-code sandbox. It relies on a fixed reviewed program
with no project import, caller code, network operation, or fixture/filesystem
loader; it does not install a syscall filter, namespace, container, or MAC
policy. The Darwin address-space ceiling is intentionally coarse. The economic
model is also deliberately optimistic and incomplete. It establishes neither
captured-tape validity nor performance quality: costs, fill uncertainty,
benchmarks, reconnect behavior, walk-forward schedules, statistical
uncertainty, multiple-testing treatment, frozen-criteria adjudication,
promotion, deployment, and all provider/broker/trading effects remain open.

No database migration is necessary because this bounded receipt is not durable
or public. Persisting it, joining it to a comparison/report API, or widening the
worker beyond this fixed artifact requires a separate reviewed ADR and schema.
