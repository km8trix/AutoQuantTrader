"""Bind original application times to an authenticated continuous transcript.

This detached check does not authenticate SQL or grant an execution permission.
The caller supplies a store-restored checkpoint; canonical financial links are
independently checked by the existing reconciliation evidence preparer.
"""

from packages.application.account_reconciliation import apply_reconciliation_facts
from packages.application.continuous_venue_frontier import continuous_initial_cash_application
from packages.domain.accounting_contracts import AccountingContext, ExecutionAccountingPort
from packages.domain.causal_checkpoint import CausalEngineCheckpoint
from packages.domain.continuous_engine_contracts import ContinuousEngineInputs
from packages.domain.continuous_reconciliation_contracts import ContinuousReconciliationBatch
from packages.domain.engine_contracts import EngineTraceRow
from packages.domain.personal_contracts import ReductionPoint
from packages.domain.reconciliation_application_contracts import ReconciliationFactCommand
from packages.domain.reconciliation_contracts import FactApplication, ReconciliationPage
from packages.domain.venue_reconciliation_contracts import RetainedVenueCapture


def validate_continuous_application_times(
    checkpoint: CausalEngineCheckpoint,
    *,
    capture: RetainedVenueCapture,
    applications: tuple[FactApplication, ...],
    accounting: ExecutionAccountingPort,
) -> None:
    """Require each original stage-1 trace, retaining the original source item.

    A new observation of an existing fact has a new page/source-item digest. Its
    original application trace must match the earlier item retained in checkpoint
    events, never a reinterpreted timestamp or the new delivery's source hash.
    """
    if (
        type(checkpoint) is not CausalEngineCheckpoint
        or type(checkpoint.inputs) is not ContinuousEngineInputs
    ):
        raise ValueError("ACTUAL_CONTINUOUS_APPLICATION_CHECKPOINT_REQUIRED")
    scope, spec = capture.manifest.scope, checkpoint.inputs.spec
    if (
        scope.account_id != spec.account_id
        or scope.binding_sha256 != spec.account_binding_sha256
        or scope.environment != spec.environment
        or scope.source_class != "stateful_simulation"
        or type(applications) is not tuple
        or len(applications) > 4096
        or any(type(value) is not FactApplication for value in applications)
    ):
        raise ValueError("CONTINUOUS_APPLICATION_SCOPE_OR_INVENTORY_DIFFERS")
    identities = tuple(application.fact_id for application in applications)
    facts = {item.observation.fact_id: item for item in capture.facts}
    if identities != tuple(sorted(set(identities))) or not set(identities) <= facts.keys():
        raise ValueError("CONTINUOUS_APPLICATION_SOURCE_INVENTORY_DIFFERS")
    if not applications:
        return
    initial = continuous_initial_cash_application(checkpoint, accounting=accounting)
    traces: dict[str, list[EngineTraceRow]] = {}
    for trace in checkpoint.trace:
        if trace.point.stage == 1:
            traces.setdefault(trace.event_id, []).append(trace)
    original_items: dict[str, list[ReconciliationFactCommand]] = {}
    original_pages: dict[str, ReconciliationPage] = {}
    verification_facts = []
    verification_applications = []
    for event in checkpoint.events:
        if type(event.payload) is ContinuousReconciliationBatch and event.payload.scope == scope:
            for page in event.payload.source_receipts:
                original_pages[page.semantic_sha256] = page
            for item in event.payload.facts:
                original_items.setdefault(item.command.command_id, []).append(item)
    commands = dict(checkpoint.state.commands)
    for application in applications:
        item = facts[application.fact_id]
        if application.fact_sha256 != item.observation.fact_sha256 or (
            application.applied_at > checkpoint.now
        ):
            raise ValueError("CONTINUOUS_ORIGINAL_APPLICATION_CONTENT_DIFFERS")
        if application.fact_id == initial.fact_id:
            if application != initial:
                raise ValueError("CONTINUOUS_ORIGINAL_INITIAL_APPLICATION_DIFFERS")
            continue
        selected = tuple(
            trace
            for trace in traces.get(item.command.command_id, ())
            if trace.kind == type(item.command.payload).__name__
        )
        if len(selected) != 1 or (
            selected[0].point.knowledge_at != application.applied_at
            or commands.get(item.command.command_id) != item.command.semantic_sha256
        ):
            raise ValueError("CONTINUOUS_ORIGINAL_APPLICATION_TRACE_DIFFERS")
        trace = selected[0]
        originals = tuple(
            value
            for value in original_items.get(item.command.command_id, ())
            if value.command == item.command
            and value.observation.fact_id == application.fact_id
            and value.observation.fact_sha256 == application.fact_sha256
            and value.semantic_sha256 == trace.causal_input_sha256
            and value.observation.received_at <= trace.point.knowledge_at
        )
        if not originals:
            raise ValueError("CONTINUOUS_ORIGINAL_APPLICATION_SOURCE_TRACE_DIFFERS")
        verification_facts.append(originals[0])
        verification_applications.append(application)

    if not verification_facts:
        return
    context = AccountingContext(
        spec.run_id,
        ReductionPoint(checkpoint.frontier, checkpoint.sequence, checkpoint.now, 1),
        checkpoint.economic,
        "continuous-original-application-links",
        checkpoint.mark_session,
        spec.instruments,
    )
    current = accounting.project(
        state=checkpoint.state, context=context, policy=spec.execution_policy
    )
    checked = apply_reconciliation_facts(
        scope=scope,
        state=checkpoint.state,
        facts=tuple(verification_facts),
        source_receipts=tuple(
            original_pages[key]
            for key in sorted({item.source_sha256 for item in verification_facts})
        ),
        prior_applications=tuple(verification_applications),
        context=context,
        accounting=accounting,
        policy=spec.execution_policy,
    )
    if (
        checked.state != checkpoint.state
        or checked.current.snapshot != current.snapshot
        or checked.applications != tuple(verification_applications)
    ):
        raise ValueError("CONTINUOUS_ORIGINAL_APPLICATION_CANONICAL_LINKS_DIFFER")
