"""Normalize retained independent-venue captures without applying economics."""

from dataclasses import replace
from datetime import datetime
from hashlib import sha256

from packages.application.personal_codec import encode_record
from packages.domain.accounting_contracts import (
    AccountingCommand,
    AccountingContext,
    ExecutionAccountingPort,
)
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import ClosedEngineFrontier, ContinuousEngineInputs
from packages.domain.continuous_reconciliation_contracts import ContinuousReconciliationBatch
from packages.domain.engine_contracts import EngineEvent, ObservationProvenance
from packages.domain.identifiers import canonical_id
from packages.domain.ledger_reducer import CashFlowKind, create_cash_flow
from packages.domain.personal_contracts import ReductionPoint, content_digest, require_utc
from packages.domain.reconciliation_contracts import FactApplication
from packages.domain.venue_reconciliation_contracts import RetainedVenueCapture

VENUE_FRONTIER_VERSION = "personal-continuous-venue-frontier/1"


def continuous_initial_cash_application(
    checkpoint: CausalEngineCheckpoint, *, accounting: ExecutionAccountingPort
) -> FactApplication:
    """Derive the engine's initial-capital receipt from its authenticated transcript.

    Only the exact engine-created capital fact is supported. The caller must
    authenticate the checkpoint's account journal; a constructor is not that proof.
    No observed amount matching, invented application time, or replayed cash occurs.
    """
    if type(checkpoint.inputs) is not ContinuousEngineInputs:
        raise ValueError("continuous initial cash requires the actual continuous checkpoint")
    spec = checkpoint.inputs.spec
    initial = create_cash_flow(
        kind=CashFlowKind.CONTRIBUTION,
        currency="USD",
        amount=spec.initial_cash,
        effective_at=spec.initialized_at,
        recorded_at=spec.initialized_at,
        external_reference=canonical_id("initial-capital", spec.run_id),
    )
    rows = tuple(row for row in checkpoint.flows if row.origin == "initial_capital")
    traces = tuple(
        row
        for row in checkpoint.trace
        if row.event_id == initial.cash_flow_id and row.kind == "LedgerCashFlow"
    )
    if len(rows) != 1 or len(traces) != 1:
        raise ValueError("initial capital requires its unique actual engine flow and trace")
    flow, trace = rows[0], traces[0]
    post = next(
        (row for row in checkpoint.valuations if row.row_id == flow.post_valuation_id), None
    )
    pre = next((row for row in checkpoint.valuations if row.row_id == flow.pre_valuation_id), None)
    command = AccountingCommand(initial.cash_flow_id, initial)
    if (
        flow.flow != initial
        or initial not in checkpoint.state.cash_flows
        or dict(checkpoint.state.commands).get(command.command_id) != command.semantic_sha256
        or trace.point.stage != 1
        or trace.point.reduction_sequence != flow.sequence
        or trace.point.knowledge_at != initial.recorded_at
        or post is None
        or pre is None
        or "baseline" not in post.roles
        or "post_flow" not in post.roles
        or "pre_flow" not in pre.roles
        or post.row_id != checkpoint.baseline_id
        or post.snapshot.journal_sha256 != flow.journal_sha256
        or pre.paired_row_id != post.row_id
        or post.paired_row_id != pre.row_id
    ):
        raise ValueError("initial capital transcript differs from its exact canonical fact")
    current = accounting.project(
        state=checkpoint.state,
        context=AccountingContext(
            spec.run_id,
            ReductionPoint(checkpoint.frontier, checkpoint.sequence, checkpoint.now, 1),
            checkpoint.economic,
            "initial-capital-link-read",
            checkpoint.mark_session,
            spec.instruments,
        ),
        policy=spec.execution_policy,
    )
    links = tuple(
        sorted(
            entry.entry_id
            for entry in current.journal_entries
            if entry.source_sha256 == initial.semantic_sha256
        )
    )
    if not links:
        raise ValueError("initial capital has no actual canonical journal entries")
    return FactApplication(
        initial.cash_flow_id,
        initial.semantic_sha256,
        trace.point.knowledge_at,
        links,
        (),
        (initial.cash_flow_id,),
    )


def project_continuous_venue_frontier(
    *,
    checkpoint: CausalEngineCheckpoint,
    capture: RetainedVenueCapture,
    prior_applications: tuple[FactApplication, ...],
    frontier_id: str,
    admitted_at: datetime,
) -> ClosedEngineFrontier:
    """Select an exact captured inventory and retain each original page receipt.

    The durable composer authenticates the venue capture journal and this complete
    inventory before publication. Venue facts stay simulated even when input quotes
    were recorded from a provider. This function does not qualify a provider account.
    """
    require_utc(admitted_at, "venue frontier admission")
    if type(checkpoint.inputs) is not ContinuousEngineInputs:
        raise ValueError("venue frontier requires a continuous checkpoint")
    spec, scope = checkpoint.inputs.spec, capture.observed.scope
    if (
        scope.account_id != spec.account_id
        or scope.binding_sha256 != spec.account_binding_sha256
        or scope.environment != spec.environment
        or admitted_at <= checkpoint.now
        or capture.observed.completed_at > admitted_at
    ):
        raise ValueError("venue frontier account or original observation time differs")
    payload = ContinuousReconciliationBatch(
        scope=scope,
        facts=capture.facts,
        source_receipts=capture.observed.pages,
        prior_applications=prior_applications,
        source_order=capture.source_order,
        source_closure_sha256=capture.semantic_sha256,
    )
    event_id = canonical_id("continuous-venue-capture", capture.semantic_sha256)
    old = next((event for event in checkpoint.events if event.event_id == event_id), None)
    if old is not None:
        if (
            type(old.payload) is not ContinuousReconciliationBatch
            or replace(payload, prior_applications=old.payload.prior_applications) != old.payload
        ):
            raise ValueError("retained venue capture normalization conflicts")
        event = old
    else:
        recorded = spec.source_mode == "recorded_as_observed"
        event = EngineEvent(
            event_id,
            admitted_at,
            admitted_at,
            payload,
            ObservationProvenance(
                spec.data_class,
                scope.provider_id + ".captured-model-facts",
                content_digest(payload),
                observed_at=capture.observed.completed_at if recorded else None,
                simulated_available_at=None if recorded else capture.observed.completed_at,
                assumption_id=None if recorded else "explicit-stateful-simulation/1",
                raw_sha256=sha256(encode_record(capture)).hexdigest(),
                limitations=(VENUE_FRONTIER_VERSION, "modeled-venue-not-provider-qualification"),
            ),
        )
    return ClosedEngineFrontier(
        frontier_id=frontier_id,
        stream_id=spec.run_id,
        previous_checkpoint_sha256=checkpoint.semantic_sha256,
        source_frontier_sha256=content_digest(
            (VENUE_FRONTIER_VERSION, capture.semantic_sha256, admitted_at)
        ),
        knowledge_at=admitted_at,
        events=(event,),
    )
