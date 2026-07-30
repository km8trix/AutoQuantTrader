"""Restart-safe composition of the Phase 4J/I/K/L UNKNOWN evidence path.

The workflow accounts for every authenticated lookup already attached to the
durable recovery schedule before it may issue one new scheduled lookup.  It
also repairs the narrow crash prefix in which Phase 4I committed a lookup
receipt but Phase 4J did not yet attach it.  Phase 4K normalization and Phase
4L non-application are then resumed from their source-indexed durable facts.

No transaction spans broker I/O.  Safety comes from deterministic source
identities, source-authenticated reads, idempotent downstream writes, and
performing all durable-prefix repair before the next one-shot schedule step.
The result is historical evidence only and grants no lifecycle, reconciliation,
reservation, retry, or trading authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from packages.adapters.broker.alpaca_paper_lookup_runtime import (
    AlpacaPaperAuthenticatedLookupReceipt,
)
from packages.application.alpaca_paper_reconciliation_normalization import (
    AlpacaPaperAuthenticatedLookupLoader,
    AlpacaPaperIngressReceiptLoader,
    AlpacaPaperSubmissionAttemptLoader,
    normalize_and_record_authenticated_alpaca_paper_lookup,
)
from packages.application.alpaca_paper_unknown_recovery import (
    AlpacaPaperUnknownLookupExecutor,
    AlpacaPaperUnknownRecoveryClaimPort,
    AlpacaPaperUnknownRecoveryResult,
    AlpacaPaperUnknownRecoverySchedulePort,
    run_alpaca_paper_unknown_recovery_once,
)
from packages.application.broker_inbox_admission import (
    admit_authenticated_alpaca_paper_reconciliation_fact,
)
from packages.domain.account_coordinator import AccountFence
from packages.domain.broker_inbox import (
    BrokerInboxNonApplicationDecisionReceipt,
    BrokerInboxRepository,
)
from packages.domain.broker_reconciliation import (
    BrokerReconciliationFact,
    BrokerReconciliationRepository,
)
from packages.domain.unknown_submission_recovery import (
    UnknownSubmissionRecoveryPlan,
    UnknownSubmissionRecoveryTicket,
)

ALPACA_PAPER_UNKNOWN_RECOVERY_PIPELINE_CONTRACT_VERSION = (
    "phase4ac-unknown-recovery-evidence-pipeline-v1"
)


class AlpacaPaperUnknownRecoveryPipelineError(RuntimeError):
    """The bounded J/I/K/L composition failed closed."""


class AlpacaPaperUnknownRecoveryPipelineConflict(AlpacaPaperUnknownRecoveryPipelineError):
    """A port or durable source conflicts with the exact recovery pipeline."""


class AlpacaPaperUnknownRecoveryPipelineExecutionError(AlpacaPaperUnknownRecoveryPipelineError):
    """A bounded workflow stage failed with sanitized diagnostics."""


class AlpacaPaperUnknownRecoveryDispatchProgressPort(Protocol):
    """One authenticated durable Phase 4J dispatch and optional observation."""

    @property
    def claim(self) -> AlpacaPaperUnknownRecoveryClaimPort: ...

    @property
    def lookup_receipt(self) -> AlpacaPaperAuthenticatedLookupReceipt | None: ...


class AlpacaPaperUnknownRecoveryProgressPort(Protocol):
    """Authenticated Phase 4J plan and dispatch history projection."""

    @property
    def plan(self) -> UnknownSubmissionRecoveryPlan: ...

    @property
    def dispatches(
        self,
    ) -> tuple[AlpacaPaperUnknownRecoveryDispatchProgressPort, ...]: ...


class AlpacaPaperUnknownRecoveryPipelineSchedule(
    AlpacaPaperUnknownRecoverySchedulePort,
    Protocol,
):
    """Phase 4J schedule with a restart-safe authenticated history projection."""

    @property
    def runtime_store_identity(self) -> int: ...

    def load_progress(
        self,
        plan_id: str,
    ) -> AlpacaPaperUnknownRecoveryProgressPort | None: ...


class AlpacaPaperUnknownRecoveryPipelineExecutor(
    AlpacaPaperUnknownLookupExecutor,
    Protocol,
):
    """Bound Phase 4I executor whose durable ports share one local store."""

    @property
    def runtime_store_identity(self) -> int: ...


class AlpacaPaperUnknownRecoveryLookupRepository(
    AlpacaPaperAuthenticatedLookupLoader,
    Protocol,
):
    """Authenticated Phase 4I receipt loader with deterministic ingress lookup."""

    @property
    def runtime_store_identity(self) -> int: ...

    def load_by_ingress_receipt_id(
        self,
        ingress_receipt_id: str,
    ) -> AlpacaPaperAuthenticatedLookupReceipt | None: ...


class AlpacaPaperUnknownRecoveryAttemptLoader(
    AlpacaPaperSubmissionAttemptLoader,
    Protocol,
):
    """Phase 2 attempt loader pinned to the pipeline's local durable store."""

    @property
    def runtime_store_identity(self) -> int: ...


class AlpacaPaperUnknownRecoveryIngressLoader(
    AlpacaPaperIngressReceiptLoader,
    Protocol,
):
    """Phase 4C raw loader pinned to the pipeline's local durable store."""

    @property
    def runtime_store_identity(self) -> int: ...


class AlpacaPaperUnknownRecoveryReconciliationRepository(
    BrokerReconciliationRepository,
    Protocol,
):
    """Phase 4K repository with a source-indexed authenticated read."""

    @property
    def runtime_store_identity(self) -> int: ...

    def load_by_lookup_receipt_id(
        self,
        lookup_receipt_id: str,
    ) -> BrokerReconciliationFact | None: ...


class AlpacaPaperUnknownRecoveryInboxRepository(
    BrokerInboxRepository,
    Protocol,
):
    """Phase 4L repository with a source-indexed authenticated read."""

    @property
    def runtime_store_identity(self) -> int: ...

    def load_by_reconciliation_fact_id(
        self,
        reconciliation_fact_id: str,
    ) -> BrokerInboxNonApplicationDecisionReceipt | None: ...


class _NoUnknownRecoveryPipelineAuthority:
    """Make the composition's deliberately absent authority explicit."""

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def inbox_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_completion_authorized(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperUnknownRecoveryAccountedObservation(_NoUnknownRecoveryPipelineAuthority):
    """Exact J claim, I receipt, K fact, and L non-application receipt."""

    claim: AlpacaPaperUnknownRecoveryClaimPort
    lookup_receipt: AlpacaPaperAuthenticatedLookupReceipt
    reconciliation_fact: BrokerReconciliationFact
    inbox_decision: BrokerInboxNonApplicationDecisionReceipt

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperUnknownRecoveryAccountedObservation must be workflow-produced")

    @property
    def ticket(self) -> UnknownSubmissionRecoveryTicket:
        return self.claim.ticket

    def _validate(self) -> None:
        try:
            ticket = self.claim.ticket
            issued_at = _require_utc(
                self.claim.issued_at,
                "accounted Phase 4J claim issued_at",
            )
            valid_until = _require_utc(
                self.claim.valid_until,
                "accounted Phase 4J claim valid_until",
            )
        except AlpacaPaperUnknownRecoveryPipelineError:
            raise
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "accounted observation requires an exact Phase 4J claim"
            ) from None
        if type(ticket) is not UnknownSubmissionRecoveryTicket:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "accounted observation requires an exact Phase 4J ticket"
            )
        if type(self.lookup_receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "accounted observation requires an exact Phase 4I receipt"
            )
        if type(self.reconciliation_fact) is not BrokerReconciliationFact:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "accounted observation requires an exact Phase 4K fact"
            )
        if type(self.inbox_decision) is not BrokerInboxNonApplicationDecisionReceipt:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "accounted observation requires an exact Phase 4L decision"
            )
        try:
            ticket._validate()
            self.lookup_receipt._validate()
            self.reconciliation_fact._validate()
            self.inbox_decision._validate()
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "accounted observation contains invalid durable evidence"
            ) from None
        _require_receipt_matches_ticket(
            ticket=ticket,
            receipt=self.lookup_receipt,
            issued_at=issued_at,
            valid_until=valid_until,
            plan=None,
        )
        evidence = self.reconciliation_fact.evidence
        if (
            evidence.source_lookup_receipt_id != self.lookup_receipt.receipt_id
            or evidence.source_lookup_receipt_sha256 != self.lookup_receipt.semantic_sha256
            or evidence.source_ingress_receipt_id != self.lookup_receipt.ingress_receipt_id
            or evidence.source_ingress_receipt_sha256 != self.lookup_receipt.ingress_receipt_sha256
            or self.inbox_decision.request.source_fact != self.reconciliation_fact
        ):
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "accounted J/I/K/L evidence does not form one exact source chain"
            )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperUnknownRecoveryPipelineResult(_NoUnknownRecoveryPipelineAuthority):
    """Authenticated bounded-step result over the observed Phase 4J prefix."""

    plan: UnknownSubmissionRecoveryPlan
    recovery_result: AlpacaPaperUnknownRecoveryResult
    accounted_observations: tuple[
        AlpacaPaperUnknownRecoveryAccountedObservation,
        ...,
    ]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("AlpacaPaperUnknownRecoveryPipelineResult must be workflow-produced")

    def _validate(self) -> None:
        if type(self.plan) is not UnknownSubmissionRecoveryPlan:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "pipeline result requires an exact recovery plan"
            )
        if type(self.recovery_result) is not AlpacaPaperUnknownRecoveryResult:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "pipeline result requires an exact Phase 4J result"
            )
        if type(self.accounted_observations) is not tuple or any(
            type(value) is not AlpacaPaperUnknownRecoveryAccountedObservation
            for value in self.accounted_observations
        ):
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "pipeline result observations must be an exact immutable tuple"
            )
        try:
            self.plan._validate()
            self.recovery_result.__post_init__()
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "pipeline result contains invalid schedule evidence"
            ) from None
        if (
            self.recovery_result.evaluation.plan_id != self.plan.plan_id
            or self.recovery_result.evaluation.plan_sha256 != self.plan.semantic_sha256
        ):
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "pipeline result schedule evaluation belongs to another plan"
            )
        ticket_ids: set[str] = set()
        receipt_ids: set[str] = set()
        previous_scheduled_at: datetime | None = None
        for observation in self.accounted_observations:
            observation._validate()
            ticket = observation.ticket
            if (
                ticket.plan_id != self.plan.plan_id
                or ticket.plan_sha256 != self.plan.semantic_sha256
                or ticket.ticket_id in ticket_ids
                or observation.lookup_receipt.receipt_id in receipt_ids
                or (
                    previous_scheduled_at is not None
                    and ticket.scheduled_at <= previous_scheduled_at
                )
            ):
                raise AlpacaPaperUnknownRecoveryPipelineConflict(
                    "pipeline result observation order or identity conflicts"
                )
            _require_receipt_matches_ticket(
                ticket=ticket,
                receipt=observation.lookup_receipt,
                issued_at=None,
                valid_until=None,
                plan=self.plan,
            )
            ticket_ids.add(ticket.ticket_id)
            receipt_ids.add(observation.lookup_receipt.receipt_id)
            previous_scheduled_at = ticket.scheduled_at
        fresh_receipt = self.recovery_result.lookup_receipt
        if fresh_receipt is not None and fresh_receipt.receipt_id not in receipt_ids:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "fresh Phase 4I receipt is absent from the accounted prefix"
            )

    @property
    def lookup_executed(self) -> bool:
        return self.recovery_result.lookup_executed

    @property
    def observed_source_count(self) -> int:
        return len(self.accounted_observations)

    @property
    def observed_prefix_accounted(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class _DispatchSnapshot:
    claim: AlpacaPaperUnknownRecoveryClaimPort
    ticket: UnknownSubmissionRecoveryTicket
    issued_at: datetime
    valid_until: datetime
    lookup_receipt: AlpacaPaperAuthenticatedLookupReceipt | None


@dataclass(frozen=True, slots=True)
class _ProgressSnapshot:
    plan: UnknownSubmissionRecoveryPlan
    dispatches: tuple[_DispatchSnapshot, ...]


def _require_utc(value: object, field_name: str) -> datetime:
    if (
        type(value) is not datetime
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise AlpacaPaperUnknownRecoveryPipelineConflict(f"{field_name} must be exact UTC")
    return value


def _runtime_store_identity(value: object, field_name: str) -> int:
    try:
        identity = value.runtime_store_identity  # type: ignore[attr-defined]
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            f"{field_name} durable-store identity is unavailable"
        ) from None
    if type(identity) is not int or identity <= 0:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            f"{field_name} durable-store identity is invalid"
        )
    return identity


def _validate_ports(
    *,
    schedule: object,
    executor: object,
    lookup_repository: object,
    attempt_loader: object,
    ingress_loader: object,
    reconciliation_repository: object,
    inbox_repository: object,
) -> None:
    ports = (
        (schedule, "Phase 4J schedule"),
        (executor, "Phase 4I executor"),
        (lookup_repository, "Phase 4I lookup repository"),
        (attempt_loader, "submission attempt loader"),
        (ingress_loader, "Phase 4C ingress loader"),
        (reconciliation_repository, "Phase 4K repository"),
        (inbox_repository, "Phase 4L repository"),
    )
    identities = tuple(_runtime_store_identity(value, field_name) for value, field_name in ports)
    if len(set(identities)) != 1:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "UNKNOWN recovery pipeline ports do not share one durable store"
        )
    required_methods = (
        (schedule, "load_progress", "Phase 4J progress loader"),
        (schedule, "evaluate", "Phase 4J schedule evaluator"),
        (schedule, "record_observation", "Phase 4J observation recorder"),
        (executor, "execute", "Phase 4I lookup executor"),
        (lookup_repository, "load", "Phase 4I receipt loader"),
        (
            lookup_repository,
            "load_by_ingress_receipt_id",
            "Phase 4I ingress-source loader",
        ),
        (attempt_loader, "get", "submission attempt loader"),
        (ingress_loader, "load", "Phase 4C ingress loader"),
        (reconciliation_repository, "record", "Phase 4K recorder"),
        (reconciliation_repository, "load", "Phase 4K fact loader"),
        (
            reconciliation_repository,
            "load_by_lookup_receipt_id",
            "Phase 4K lookup-source loader",
        ),
        (inbox_repository, "record", "Phase 4L recorder"),
        (inbox_repository, "load", "Phase 4L decision loader"),
        (
            inbox_repository,
            "load_by_reconciliation_fact_id",
            "Phase 4L reconciliation-source loader",
        ),
    )
    for value, method_name, field_name in required_methods:
        try:
            method = getattr(value, method_name)
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                f"{field_name} access failed"
            ) from None
        if not callable(method):
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                f"UNKNOWN recovery pipeline requires a {field_name}"
            )


def _require_receipt_matches_ticket(
    *,
    ticket: UnknownSubmissionRecoveryTicket,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    issued_at: datetime | None,
    valid_until: datetime | None,
    plan: UnknownSubmissionRecoveryPlan | None,
) -> None:
    if (
        receipt.account_id != ticket.account_id
        or receipt.attempt_id != ticket.attempt_id
        or receipt.demand_id != ticket.demand_id
        or receipt.ingress_receipt_id != ticket.delivery_id
        or receipt.requested_at < ticket.scheduled_at
        or receipt.requested_at >= ticket.recovery_deadline_at
        or (issued_at is not None and receipt.requested_at < issued_at)
        or (valid_until is not None and receipt.requested_at >= valid_until)
        or (
            plan is not None
            and (
                receipt.attempt_sha256 != plan.attempt_sha256
                or receipt.terminal_event_id != plan.unknown_event_id
                or receipt.terminal_event_sha256 != plan.unknown_event_sha256
                or receipt.terminal_event_sequence != plan.unknown_sequence_number
                or receipt.client_order_id != plan.client_order_id
            )
        )
    ):
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4I receipt conflicts with its exact Phase 4J ticket"
        )


def _load_progress(
    *,
    schedule: AlpacaPaperUnknownRecoveryPipelineSchedule,
    plan: UnknownSubmissionRecoveryPlan,
) -> _ProgressSnapshot | None:
    try:
        raw_progress = schedule.load_progress(plan.plan_id)
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineExecutionError(
            "UNKNOWN recovery durable progress could not be authenticated"
        ) from None
    if raw_progress is None:
        return None
    progress = raw_progress
    try:
        durable_plan = progress.plan
        raw_dispatches = progress.dispatches
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "UNKNOWN recovery durable progress has an invalid shape"
        ) from None
    if (
        type(durable_plan) is not UnknownSubmissionRecoveryPlan
        or durable_plan != plan
        or type(raw_dispatches) is not tuple
    ):
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "UNKNOWN recovery durable progress conflicts with the exact plan"
        )

    dispatches: list[_DispatchSnapshot] = []
    ticket_ids: set[str] = set()
    delivery_ids: set[str] = set()
    previous_scheduled_at: datetime | None = None
    for raw_dispatch in raw_dispatches:
        dispatch = raw_dispatch
        try:
            claim = dispatch.claim
            ticket = claim.ticket
            issued_at = _require_utc(
                claim.issued_at,
                "recovery dispatch issued_at",
            )
            valid_until = _require_utc(
                claim.valid_until,
                "recovery dispatch valid_until",
            )
            receipt = dispatch.lookup_receipt
        except AlpacaPaperUnknownRecoveryPipelineError:
            raise
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "UNKNOWN recovery durable dispatch has an invalid shape"
            ) from None
        if type(ticket) is not UnknownSubmissionRecoveryTicket:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "UNKNOWN recovery durable dispatch lacks an exact ticket"
            )
        try:
            ticket._validate()
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "UNKNOWN recovery durable dispatch ticket is invalid"
            ) from None
        if (
            ticket.plan_id != plan.plan_id
            or ticket.plan_sha256 != plan.semantic_sha256
            or ticket.account_id != plan.account_id
            or ticket.attempt_id != plan.attempt_id
            or ticket.lookup_correlation_sha256 != plan.lookup_correlation_sha256
            or ticket.ticket_id in ticket_ids
            or ticket.delivery_id in delivery_ids
            or not ticket.scheduled_at <= issued_at < valid_until
            or valid_until > ticket.recovery_deadline_at
            or (previous_scheduled_at is not None and ticket.scheduled_at <= previous_scheduled_at)
        ):
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "UNKNOWN recovery durable dispatch conflicts with its plan or order"
            )
        if receipt is not None:
            if type(receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
                raise AlpacaPaperUnknownRecoveryPipelineConflict(
                    "UNKNOWN recovery dispatch carries a non-canonical lookup receipt"
                )
            try:
                receipt._validate()
            except Exception:
                raise AlpacaPaperUnknownRecoveryPipelineConflict(
                    "UNKNOWN recovery dispatch carries invalid lookup evidence"
                ) from None
            _require_receipt_matches_ticket(
                ticket=ticket,
                receipt=receipt,
                issued_at=issued_at,
                valid_until=valid_until,
                plan=plan,
            )
        dispatches.append(
            _DispatchSnapshot(
                claim=claim,
                ticket=ticket,
                issued_at=issued_at,
                valid_until=valid_until,
                lookup_receipt=receipt,
            )
        )
        ticket_ids.add(ticket.ticket_id)
        delivery_ids.add(ticket.delivery_id)
        previous_scheduled_at = ticket.scheduled_at
    return _ProgressSnapshot(
        plan=durable_plan,
        dispatches=tuple(dispatches),
    )


def _recover_unacknowledged_lookup_receipts(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    fence: AccountFence,
    schedule: AlpacaPaperUnknownRecoveryPipelineSchedule,
    lookup_repository: AlpacaPaperUnknownRecoveryLookupRepository,
) -> _ProgressSnapshot | None:
    progress = _load_progress(schedule=schedule, plan=plan)
    if progress is None:
        return None
    recovered: dict[str, AlpacaPaperAuthenticatedLookupReceipt] = {}
    for dispatch in progress.dispatches:
        if dispatch.lookup_receipt is not None:
            continue
        try:
            receipt = lookup_repository.load_by_ingress_receipt_id(dispatch.ticket.delivery_id)
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineExecutionError(
                "Phase 4I crash-prefix lookup could not be authenticated"
            ) from None
        if receipt is None:
            continue
        if type(receipt) is not AlpacaPaperAuthenticatedLookupReceipt:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "Phase 4I crash-prefix loader returned a non-canonical receipt"
            )
        try:
            receipt._validate()
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "Phase 4I crash-prefix loader returned invalid evidence"
            ) from None
        _require_receipt_matches_ticket(
            ticket=dispatch.ticket,
            receipt=receipt,
            issued_at=dispatch.issued_at,
            valid_until=dispatch.valid_until,
            plan=plan,
        )
        try:
            acknowledged = schedule.record_observation(
                plan_id=plan.plan_id,
                claim=dispatch.claim,
                receipt=receipt,
                fence=fence,
            )
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineExecutionError(
                "persisted Phase 4I lookup could not be attached to Phase 4J"
            ) from None
        if (
            type(acknowledged) is not AlpacaPaperAuthenticatedLookupReceipt
            or acknowledged != receipt
        ):
            raise AlpacaPaperUnknownRecoveryPipelineConflict(
                "Phase 4J acknowledged different lookup evidence"
            )
        recovered[dispatch.ticket.ticket_id] = receipt
    if not recovered:
        return progress

    reloaded = _load_progress(schedule=schedule, plan=plan)
    if reloaded is None:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4J progress disappeared after crash-prefix repair"
        )
    attached = {
        dispatch.ticket.ticket_id: dispatch.lookup_receipt for dispatch in reloaded.dispatches
    }
    if any(attached.get(ticket_id) != receipt for ticket_id, receipt in recovered.items()):
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4J crash-prefix repair failed exact durable reload"
        )
    return reloaded


def _validate_reconciliation_fact(
    *,
    receipt: AlpacaPaperAuthenticatedLookupReceipt,
    fact: object,
) -> BrokerReconciliationFact:
    if type(fact) is not BrokerReconciliationFact:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4K returned a non-canonical reconciliation fact"
        )
    try:
        fact._validate()
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4K returned invalid durable evidence"
        ) from None
    evidence = fact.evidence
    if (
        evidence.source_lookup_receipt_id != receipt.receipt_id
        or evidence.source_lookup_receipt_sha256 != receipt.semantic_sha256
        or evidence.source_ingress_receipt_id != receipt.ingress_receipt_id
        or evidence.source_ingress_receipt_sha256 != receipt.ingress_receipt_sha256
    ):
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4K fact conflicts with its exact Phase 4I source"
        )
    return fact


def _validate_inbox_decision(
    *,
    fact: BrokerReconciliationFact,
    decision: object,
) -> BrokerInboxNonApplicationDecisionReceipt:
    if type(decision) is not BrokerInboxNonApplicationDecisionReceipt:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4L returned a non-canonical inbox decision"
        )
    try:
        decision._validate()
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4L returned invalid durable evidence"
        ) from None
    if decision.request.source_fact != fact:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4L decision conflicts with its exact Phase 4K source"
        )
    return decision


def _account_observation(
    *,
    dispatch: _DispatchSnapshot,
    lookup_repository: AlpacaPaperUnknownRecoveryLookupRepository,
    attempt_loader: AlpacaPaperUnknownRecoveryAttemptLoader,
    ingress_loader: AlpacaPaperUnknownRecoveryIngressLoader,
    reconciliation_repository: (AlpacaPaperUnknownRecoveryReconciliationRepository),
    inbox_repository: AlpacaPaperUnknownRecoveryInboxRepository,
) -> AlpacaPaperUnknownRecoveryAccountedObservation:
    receipt = dispatch.lookup_receipt
    if receipt is None:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "only an attached Phase 4J observation can be accounted"
        )
    try:
        fact = reconciliation_repository.load_by_lookup_receipt_id(receipt.receipt_id)
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineExecutionError(
            "Phase 4K crash-prefix read failed"
        ) from None
    if fact is None:
        try:
            fact = normalize_and_record_authenticated_alpaca_paper_lookup(
                receipt.receipt_id,
                lookup_loader=lookup_repository,
                attempt_loader=attempt_loader,
                ingress_loader=ingress_loader,
                reconciliation_repository=reconciliation_repository,
            )
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineExecutionError(
                "Phase 4K normalization failed for an authenticated lookup"
            ) from None
    fact = _validate_reconciliation_fact(receipt=receipt, fact=fact)

    try:
        decision = inbox_repository.load_by_reconciliation_fact_id(fact.fact_id)
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineExecutionError(
            "Phase 4L crash-prefix read failed"
        ) from None
    if decision is None:
        try:
            decision = admit_authenticated_alpaca_paper_reconciliation_fact(
                fact.fact_id,
                reconciliation_loader=reconciliation_repository,
                inbox_repository=inbox_repository,
            )
        except Exception:
            raise AlpacaPaperUnknownRecoveryPipelineExecutionError(
                "Phase 4L non-application failed for an authenticated fact"
            ) from None
    decision = _validate_inbox_decision(fact=fact, decision=decision)

    value = object.__new__(AlpacaPaperUnknownRecoveryAccountedObservation)
    object.__setattr__(value, "claim", dispatch.claim)
    object.__setattr__(value, "lookup_receipt", receipt)
    object.__setattr__(value, "reconciliation_fact", fact)
    object.__setattr__(value, "inbox_decision", decision)
    value._validate()
    return value


def _account_progress(
    *,
    progress: _ProgressSnapshot | None,
    lookup_repository: AlpacaPaperUnknownRecoveryLookupRepository,
    attempt_loader: AlpacaPaperUnknownRecoveryAttemptLoader,
    ingress_loader: AlpacaPaperUnknownRecoveryIngressLoader,
    reconciliation_repository: (AlpacaPaperUnknownRecoveryReconciliationRepository),
    inbox_repository: AlpacaPaperUnknownRecoveryInboxRepository,
) -> tuple[AlpacaPaperUnknownRecoveryAccountedObservation, ...]:
    if progress is None:
        return ()
    return tuple(
        _account_observation(
            dispatch=dispatch,
            lookup_repository=lookup_repository,
            attempt_loader=attempt_loader,
            ingress_loader=ingress_loader,
            reconciliation_repository=reconciliation_repository,
            inbox_repository=inbox_repository,
        )
        for dispatch in progress.dispatches
        if dispatch.lookup_receipt is not None
    )


def _pipeline_result(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    recovery_result: AlpacaPaperUnknownRecoveryResult,
    accounted_observations: tuple[
        AlpacaPaperUnknownRecoveryAccountedObservation,
        ...,
    ],
) -> AlpacaPaperUnknownRecoveryPipelineResult:
    value = object.__new__(AlpacaPaperUnknownRecoveryPipelineResult)
    object.__setattr__(value, "plan", plan)
    object.__setattr__(value, "recovery_result", recovery_result)
    object.__setattr__(
        value,
        "accounted_observations",
        accounted_observations,
    )
    value._validate()
    return value


def run_alpaca_paper_unknown_recovery_pipeline_once(
    *,
    plan: UnknownSubmissionRecoveryPlan,
    fence: AccountFence,
    schedule: AlpacaPaperUnknownRecoveryPipelineSchedule,
    executor: AlpacaPaperUnknownRecoveryPipelineExecutor,
    lookup_repository: AlpacaPaperUnknownRecoveryLookupRepository,
    attempt_loader: AlpacaPaperUnknownRecoveryAttemptLoader,
    ingress_loader: AlpacaPaperUnknownRecoveryIngressLoader,
    reconciliation_repository: (AlpacaPaperUnknownRecoveryReconciliationRepository),
    inbox_repository: AlpacaPaperUnknownRecoveryInboxRepository,
) -> AlpacaPaperUnknownRecoveryPipelineResult:
    """Repair the durable prefix, execute at most one J/I step, then K/L.

    Existing observations are fully accounted before ``schedule.evaluate`` can
    consume another slot.  A Phase 4I receipt found under a ticket's
    deterministic raw-ingress identity is attached to that exact Phase 4J
    claim before downstream work.  A second bounded repair pass after the
    schedule step catches a receipt that became durable while an existing
    active claim was being observed.
    """

    if type(plan) is not UnknownSubmissionRecoveryPlan:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "UNKNOWN recovery pipeline requires an exact plan"
        )
    if type(fence) is not AccountFence:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "UNKNOWN recovery pipeline requires an exact account fence"
        )
    try:
        plan._validate()
        fence.__post_init__()
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "UNKNOWN recovery pipeline input evidence is invalid"
        ) from None
    if fence.account_id != plan.account_id:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "UNKNOWN recovery pipeline fence belongs to another account"
        )
    _validate_ports(
        schedule=schedule,
        executor=executor,
        lookup_repository=lookup_repository,
        attempt_loader=attempt_loader,
        ingress_loader=ingress_loader,
        reconciliation_repository=reconciliation_repository,
        inbox_repository=inbox_repository,
    )

    prefix = _recover_unacknowledged_lookup_receipts(
        plan=plan,
        fence=fence,
        schedule=schedule,
        lookup_repository=lookup_repository,
    )
    _account_progress(
        progress=prefix,
        lookup_repository=lookup_repository,
        attempt_loader=attempt_loader,
        ingress_loader=ingress_loader,
        reconciliation_repository=reconciliation_repository,
        inbox_repository=inbox_repository,
    )

    try:
        recovery_result = run_alpaca_paper_unknown_recovery_once(
            plan=plan,
            schedule=schedule,
            executor=executor,
            fence=fence,
        )
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineExecutionError(
            "scheduled UNKNOWN recovery step failed after durable-prefix accounting"
        ) from None
    if type(recovery_result) is not AlpacaPaperUnknownRecoveryResult:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4J workflow returned a non-canonical result"
        )
    try:
        recovery_result.__post_init__()
    except Exception:
        raise AlpacaPaperUnknownRecoveryPipelineConflict(
            "Phase 4J workflow returned invalid schedule evidence"
        ) from None

    final_progress = _recover_unacknowledged_lookup_receipts(
        plan=plan,
        fence=fence,
        schedule=schedule,
        lookup_repository=lookup_repository,
    )
    accounted = _account_progress(
        progress=final_progress,
        lookup_repository=lookup_repository,
        attempt_loader=attempt_loader,
        ingress_loader=ingress_loader,
        reconciliation_repository=reconciliation_repository,
        inbox_repository=inbox_repository,
    )
    return _pipeline_result(
        plan=plan,
        recovery_result=recovery_result,
        accounted_observations=accounted,
    )


__all__ = [
    "ALPACA_PAPER_UNKNOWN_RECOVERY_PIPELINE_CONTRACT_VERSION",
    "AlpacaPaperUnknownRecoveryAccountedObservation",
    "AlpacaPaperUnknownRecoveryAttemptLoader",
    "AlpacaPaperUnknownRecoveryDispatchProgressPort",
    "AlpacaPaperUnknownRecoveryInboxRepository",
    "AlpacaPaperUnknownRecoveryIngressLoader",
    "AlpacaPaperUnknownRecoveryLookupRepository",
    "AlpacaPaperUnknownRecoveryPipelineConflict",
    "AlpacaPaperUnknownRecoveryPipelineError",
    "AlpacaPaperUnknownRecoveryPipelineExecutionError",
    "AlpacaPaperUnknownRecoveryPipelineExecutor",
    "AlpacaPaperUnknownRecoveryPipelineResult",
    "AlpacaPaperUnknownRecoveryPipelineSchedule",
    "AlpacaPaperUnknownRecoveryProgressPort",
    "AlpacaPaperUnknownRecoveryReconciliationRepository",
    "run_alpaca_paper_unknown_recovery_pipeline_once",
]
