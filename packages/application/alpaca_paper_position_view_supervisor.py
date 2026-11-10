"""Bounded restart-safe supervision for two authenticated Alpaca position views.

Phase 4W derives one transition from two exact Phase 4U durable states.  One
invocation may execute the earlier capture, wait without I/O, execute the later
capture, or append the Phase 4V comparison.  It never loops, sleeps, retries a
single-use claim, or treats equal historical values as convergence.  A stalled
state observed at invocation fails before effects.  Because this application
contract has no pair lock, a concurrent mutation of the unselected plan is
detected by post-effect reload; deployed composition must supply exclusive pair
coordination before relying on a stronger pre-effect guarantee.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from packages.adapters.broker.alpaca_paper_position_snapshot_comparison import (
    ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION,
    AlpacaPaperPositionSnapshotComparisonDisposition,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotConflict,
    AlpacaPaperPositionSnapshotPreparationReceipt,
    AlpacaPaperPositionSnapshotRuntimePlan,
)
from packages.application.alpaca_paper_position_snapshot_comparison import (
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256,
    AlpacaPaperAuthenticatedPositionViewComparisonError,
    AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
    AlpacaPaperAuthenticatedPositionViewComparisonReceipt,
    AlpacaPaperAuthenticatedPositionViewComparisonResult,
    AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
    compare_and_record_authenticated_alpaca_paper_position_snapshots,
    create_authenticated_alpaca_paper_position_view_comparison_plan,
)
from packages.domain.account_coordinator import AccountCoordinatorError, AccountFence
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.clock import Clock
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_CONTRACT_VERSION = (
    "phase4w-bounded-authenticated-position-view-supervisor-v1"
)
ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_ID = (
    "phase4w-one-durable-transition-position-supervisor-policy-v1"
)
ALPACA_PAPER_POSITION_VIEW_MINIMUM_START_SEPARATION = (
    ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _duration_microseconds(value: timedelta) -> int:
    if type(value) is not timedelta:
        raise TypeError("supervisor duration must be an exact timedelta")
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_CONTRACT_VERSION,
        "supervisor_policy",
        ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_ID,
        ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
        ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_CONTRACT_VERSION,
        ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_COMPARISON_POLICY_SHA256,
        _duration_microseconds(ALPACA_PAPER_POSITION_VIEW_MINIMUM_START_SEPARATION),
        "authenticated_durable_source_stage_required",
        "one_process_local_durable_store_identity_for_all_ports",
        "initially_observed_stalled_single_use_claims_fail_before_effects",
        "earlier_capture_first",
        "one_exact_capture_or_one_comparison_per_invocation",
        "no_loop_sleep_or_retry",
        "later_capture_requires_trusted_clock_gate",
        "later_capture_requires_authenticated_preparation_request_and_receive_gate",
        "later_capture_requires_strict_raw_ingress_order",
        "comparison_receipt_reloaded_from_same_repository",
        "historical_non_authorizing_result",
    )
)


class AlpacaPaperAuthenticatedPositionViewSupervisorError(RuntimeError):
    """Phase 4W cannot safely perform its next bounded transition."""


class AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
    AlpacaPaperAuthenticatedPositionViewSupervisorError
):
    """Durable state or a delegated transition conflicts with exact evidence."""


class AlpacaPaperAuthenticatedPositionViewSupervisorStalled(
    AlpacaPaperAuthenticatedPositionViewSupervisorConflict
):
    """At least one single-use source is conservatively non-resumable."""


class AlpacaPaperPositionSnapshotSupervisorSourceStage(StrEnum):
    """Meanings of the exact durable Phase 4U plan/receipt state."""

    ABSENT = "absent"
    STALLED = "stalled"
    COMPLETE = "complete"


class AlpacaPaperPositionViewSupervisorStage(StrEnum):
    """The one transition, or no-I/O waiting decision, made by a call."""

    EARLIER_CAPTURE_RECORDED = "earlier_capture_recorded"
    WAITING_MINIMUM_SEPARATION = "waiting_minimum_separation"
    LATER_CAPTURE_RECORDED = "later_capture_recorded"
    COMPARISON_RECORDED = "comparison_recorded"


class _NoPositionViewSupervisorAuthority:
    __slots__ = ()

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def snapshot_isolation_qualified(self) -> bool:
        return False

    @property
    def provider_snapshot_complete(self) -> bool:
        return False

    @property
    def snapshot_complete(self) -> bool:
        return False

    @property
    def monotonic_timing_qualified(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def canonical_position_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_account_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_cash_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_ledger_fact_authorized(self) -> bool:
        return False

    @property
    def normalized_fact_authorized(self) -> bool:
        return False

    @property
    def inbox_application_authorized(self) -> bool:
        return False

    @property
    def lifecycle_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_application_authorized(self) -> bool:
        return False

    @property
    def reconciliation_completion_authorized(self) -> bool:
        return False

    @property
    def reconciliation_complete(self) -> bool:
        return False

    @property
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
        return False

    @property
    def dispatch_preflight_ready(self) -> bool:
        return False

    @property
    def paper_startup_ready(self) -> bool:
        return False

    @property
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def transport_submission_ready(self) -> bool:
        return False

    @property
    def submission_authorized(self) -> bool:
        return False

    @property
    def transport_authorized(self) -> bool:
        return False

    @property
    def broker_call_authorized(self) -> bool:
        return False

    @property
    def trading_effect_authorized(self) -> bool:
        return False

    @property
    def converged(self) -> bool:
        return False


def _require_sha256(value: object, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return value


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            f"{field_name} must be an exact datetime"
        )
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(str(error)) from error
    return value


def _require_plan(
    value: object,
    field_name: str,
) -> AlpacaPaperPositionSnapshotRuntimePlan:
    if type(value) is not AlpacaPaperPositionSnapshotRuntimePlan:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            f"{field_name} must be an exact Phase 4T runtime plan"
        )
    try:
        value.__post_init__()
    except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            f"{field_name} is invalid"
        ) from error
    return value


def _validate_plan_pair(
    earlier_plan: AlpacaPaperPositionSnapshotRuntimePlan,
    later_plan: AlpacaPaperPositionSnapshotRuntimePlan,
) -> None:
    if (
        earlier_plan.plan_id == later_plan.plan_id
        or earlier_plan.description.capture_id == later_plan.description.capture_id
    ):
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position-view supervision requires two distinct plans"
        )
    if earlier_plan.description.account_id != later_plan.description.account_id:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position-view supervision plans cross local account identities"
        )
    if (
        earlier_plan.reference.expected_provider_account_id
        != later_plan.reference.expected_provider_account_id
    ):
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position-view supervision plans cross provider account identities"
        )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedPositionSnapshotSupervisorState(_NoPositionViewSupervisorAuthority):
    """Repository-produced authentication of one Phase 4U source stage."""

    stage: AlpacaPaperPositionSnapshotSupervisorSourceStage
    plan: AlpacaPaperPositionSnapshotRuntimePlan
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt | None
    receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedPositionSnapshotSupervisorState must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.stage) is not AlpacaPaperPositionSnapshotSupervisorSourceStage:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "position supervisor source state has an invalid stage"
            )
        plan = _require_plan(self.plan, "position supervisor source plan")
        if self.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT:
            if self.preparation is not None or self.receipt is not None:
                raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                    "absent position source carries durable claim evidence"
                )
            return
        if type(self.preparation) is not AlpacaPaperPositionSnapshotPreparationReceipt:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "claimed position source requires an exact preparation"
            )
        try:
            self.preparation._validate()
        except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "position source preparation is invalid"
            ) from error
        if self.preparation.plan != plan:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "position source preparation substituted another plan"
            )
        if self.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.STALLED:
            if self.receipt is not None:
                raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                    "stalled position source cannot carry a completed receipt"
                )
            return
        if (
            self.stage is not AlpacaPaperPositionSnapshotSupervisorSourceStage.COMPLETE
            or type(self.receipt) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt
        ):
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "complete position source requires an exact Phase 4U receipt"
            )
        try:
            self.receipt._validate()
        except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError) as error:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "complete position source receipt is invalid"
            ) from error
        if self.receipt.plan != plan or self.receipt.evidence.preparation != self.preparation:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "complete position source conflicts with its exact durable claim"
            )

    @property
    def complete(self) -> bool:
        self._validate()
        return self.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.COMPLETE

    @property
    def source_sha256(self) -> str | None:
        self._validate()
        if self.receipt is not None:
            return self.receipt.semantic_sha256
        if self.preparation is not None:
            return self.preparation.semantic_sha256
        return None

    @property
    def state_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-authenticated-position-snapshot-supervisor-state",
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_SHA256,
            self.plan.plan_id,
            self.plan.semantic_sha256,
            self.stage,
            self.source_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        return (
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_CONTRACT_VERSION,
            "authenticated_position_snapshot_supervisor_state",
            self.state_id,
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_ID,
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_SHA256,
            self.stage,
            self.plan.plan_id,
            self.plan.semantic_sha256,
            None if self.preparation is None else self.preparation.semantic_sha256,
            None if self.receipt is None else self.receipt.receipt_id,
            None if self.receipt is None else self.receipt.semantic_sha256,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _alpaca_paper_authenticated_position_snapshot_supervisor_state(
    *,
    stage: AlpacaPaperPositionSnapshotSupervisorSourceStage,
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt | None,
    receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None,
) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
    """Construct one exact repository-authenticated durable source state."""

    value = object.__new__(AlpacaPaperAuthenticatedPositionSnapshotSupervisorState)
    for field_name, field_value in (
        ("stage", stage),
        ("plan", plan),
        ("preparation", preparation),
        ("receipt", receipt),
    ):
        object.__setattr__(value, field_name, field_value)
    value._validate()
    return value


class AlpacaPaperPositionSnapshotSupervisorStateLoader(Protocol):
    """Authenticate the durable Phase 4U stage and exact completed receipt."""

    @property
    def runtime_store_identity(self) -> int:
        """Opaque process-local identity shared by coherently wired SQL ports."""

        ...

    def load_state(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState: ...

    def load(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt | None: ...


class AlpacaPaperPositionSnapshotSupervisorCaptureWorkflow(Protocol):
    """Execute the injected Phase 4T workflow for one exact unclaimed plan."""

    @property
    def runtime_store_identity(self) -> int: ...

    def capture_once(
        self,
        plan: AlpacaPaperPositionSnapshotRuntimePlan,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt: ...


class AlpacaPaperPositionViewSupervisorComparisonRepository(Protocol):
    """Record and reload the exact Phase 4V comparison receipt."""

    @property
    def runtime_store_identity(self) -> int: ...

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedPositionViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt: ...

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedPositionViewComparisonReceipt | None: ...


AlpacaPaperPositionViewSupervisorValue = (
    AlpacaPaperAuthenticatedPositionSnapshotReceipt
    | AlpacaPaperAuthenticatedPositionViewComparisonReceipt
    | None
)


def _value_material(
    value: AlpacaPaperPositionViewSupervisorValue,
) -> tuple[str, str | None, str | None]:
    if value is None:
        return ("none", None, None)
    if type(value) is AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        return ("authenticated_position_receipt", value.receipt_id, value.semantic_sha256)
    if type(value) is AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
        return (
            "authenticated_position_comparison_receipt",
            value.receipt_id,
            value.semantic_sha256,
        )
    raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
        "position supervisor result has an invalid value"
    )


def _validate_exact_capture(
    before: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    after: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    *,
    fence: AccountFence,
) -> None:
    if (
        before.stage is not AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT
        or after.stage is not AlpacaPaperPositionSnapshotSupervisorSourceStage.COMPLETE
        or after.plan != before.plan
        or after.receipt != receipt
        or after.preparation != receipt.evidence.preparation
        or receipt.evidence.pre_fence_receipt.fence != fence
        or receipt.evidence.post_fence_receipt.fence != fence
        or receipt.evidence.final_fence_receipt.fence != fence
        or receipt.commit_fence_receipt.fence != fence
    ):
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "capture result does not prove one exact same-fence single-use transition"
        )


def _require_later_capture_gate(
    earlier: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    later: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    *,
    eligible_at: datetime,
    selected_at: datetime | None = None,
) -> None:
    if not earlier.complete or not later.complete:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "later-capture gate requires two complete authenticated sources"
        )
    earlier_receipt = earlier.receipt
    later_receipt = later.receipt
    assert earlier_receipt is not None
    assert later_receipt is not None
    later_observation = later_receipt.persisted_snapshot.observation
    earlier_ingress = earlier_receipt.persisted_snapshot.receipt
    later_ingress = later_receipt.persisted_snapshot.receipt
    if selected_at is not None:
        selected_at = _require_utc(
            selected_at,
            "later position capture selected_at",
        )
    if (
        later_receipt.evidence.preparation.prepared_at < eligible_at
        or (
            selected_at is not None and later_receipt.evidence.preparation.prepared_at < selected_at
        )
        or later_receipt.evidence.request.started_at < eligible_at
        or later_observation.received_at < eligible_at
        or later_ingress.ingress_sequence <= earlier_ingress.ingress_sequence
    ):
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "later position source lacks authenticated gate-separated start evidence"
        )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedPositionViewSupervisorResult(_NoPositionViewSupervisorAuthority):
    """One deterministic historical, non-authorizing Phase 4W outcome."""

    stage: AlpacaPaperPositionViewSupervisorStage
    prior_earlier_state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState
    prior_later_state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState
    earlier_state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState
    later_state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState
    fence: AccountFence
    checked_at: datetime | None
    eligible_at: datetime | None
    value: AlpacaPaperPositionViewSupervisorValue

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedPositionViewSupervisorResult must be proof-constructed"
        )

    def _validate(self) -> None:
        if type(self.stage) is not AlpacaPaperPositionViewSupervisorStage:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "position supervisor result has an invalid stage"
            )
        states = (
            self.prior_earlier_state,
            self.prior_later_state,
            self.earlier_state,
            self.later_state,
        )
        for state in states:
            if type(state) is not AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
                raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                    "position supervisor result requires exact durable source states"
                )
            state._validate()
        earlier = self.earlier_state
        later = self.later_state
        _validate_plan_pair(earlier.plan, later.plan)
        if (
            self.prior_earlier_state.plan != earlier.plan
            or self.prior_later_state.plan != later.plan
        ):
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "position supervisor result changed its exact round plans"
            )
        if type(self.fence) is not AccountFence:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "position supervisor result requires an exact account fence"
            )
        try:
            self.fence.__post_init__()
        except (AccountCoordinatorError, TypeError, ValueError) as error:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "position supervisor result fence is invalid"
            ) from error
        if self.fence.account_id != earlier.plan.description.account_id:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "position supervisor result fence crosses account identities"
            )

        if self.stage is AlpacaPaperPositionViewSupervisorStage.EARLIER_CAPTURE_RECORDED:
            if (
                type(self.value) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt
                or self.prior_later_state.stage
                is not AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT
                or self.later_state != self.prior_later_state
                or self.checked_at is not None
                or self.eligible_at is not None
            ):
                raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                    "earlier-capture result conflicts with exact source states"
                )
            _validate_exact_capture(
                self.prior_earlier_state,
                earlier,
                self.value,
                fence=self.fence,
            )
            return

        if self.prior_earlier_state != earlier or not earlier.complete:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "later position supervision requires an unchanged complete earlier source"
            )
        earlier_receipt = earlier.receipt
        assert earlier_receipt is not None
        expected_eligible_at = (
            earlier_receipt.persisted_snapshot.observation.received_at
            + ALPACA_PAPER_POSITION_VIEW_MINIMUM_START_SEPARATION
        )
        if self.eligible_at != expected_eligible_at:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "position supervisor result uses another eligibility instant"
            )

        if self.stage is AlpacaPaperPositionViewSupervisorStage.WAITING_MINIMUM_SEPARATION:
            checked_at = _require_utc(
                self.checked_at,
                "position supervisor separation checked_at",
            )
            if (
                self.value is not None
                or self.prior_later_state != later
                or later.stage is not AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT
                or checked_at >= expected_eligible_at
            ):
                raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                    "waiting result conflicts with exact position source state"
                )
            return

        if self.stage is AlpacaPaperPositionViewSupervisorStage.LATER_CAPTURE_RECORDED:
            if (
                type(self.value) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt
                or self.prior_later_state.stage
                is not AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT
            ):
                raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                    "later-capture result conflicts with exact source states"
                )
            checked_at = _require_utc(
                self.checked_at,
                "position supervisor separation checked_at",
            )
            if checked_at < expected_eligible_at:
                raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                    "later capture was selected before its trusted clock gate"
                )
            _validate_exact_capture(
                self.prior_later_state,
                later,
                self.value,
                fence=self.fence,
            )
            _require_later_capture_gate(
                earlier,
                later,
                eligible_at=expected_eligible_at,
                selected_at=checked_at,
            )
            return

        if (
            self.stage is not AlpacaPaperPositionViewSupervisorStage.COMPARISON_RECORDED
            or type(self.value) is not AlpacaPaperAuthenticatedPositionViewComparisonReceipt
            or self.prior_later_state != later
            or not later.complete
            or self.checked_at is not None
        ):
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "comparison result conflicts with exact terminal position states"
            )
        earlier_source = earlier.receipt
        later_source = later.receipt
        assert earlier_source is not None
        assert later_source is not None
        if (
            self.value.evidence.earlier_receipt != earlier_source
            or self.value.evidence.later_receipt != later_source
            or self.value.evidence.comparison.disposition
            is AlpacaPaperPositionSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
        ):
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "comparison receipt conflicts with gate-separated source bindings"
            )
        _require_later_capture_gate(
            earlier,
            later,
            eligible_at=expected_eligible_at,
        )

    @property
    def round_id(self) -> str:
        self._validate()
        return alpaca_paper_position_view_supervisor_round_id(
            self.earlier_state.plan,
            self.later_state.plan,
        )

    @property
    def result_id(self) -> str:
        self._validate()
        value_kind, value_id, value_sha256 = _value_material(self.value)
        return canonical_id(
            "alpaca-paper-authenticated-position-view-supervisor-result",
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_SHA256,
            self.round_id,
            self.stage,
            self.prior_earlier_state.semantic_sha256,
            self.prior_later_state.semantic_sha256,
            self.earlier_state.semantic_sha256,
            self.later_state.semantic_sha256,
            self.fence.semantic_sha256,
            self.checked_at,
            self.eligible_at,
            value_kind,
            value_id,
            value_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        value_kind, value_id, value_sha256 = _value_material(self.value)
        return (
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_CONTRACT_VERSION,
            "authenticated_position_view_supervisor_result",
            self.result_id,
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_ID,
            ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_SHA256,
            self.round_id,
            self.stage,
            self.prior_earlier_state.semantic_sha256,
            self.prior_later_state.semantic_sha256,
            self.earlier_state.semantic_sha256,
            self.later_state.semantic_sha256,
            self.fence.semantic_sha256,
            self.checked_at,
            self.eligible_at,
            value_kind,
            value_id,
            value_sha256,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _alpaca_paper_authenticated_position_view_supervisor_result(
    *,
    stage: AlpacaPaperPositionViewSupervisorStage,
    prior_earlier_state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    prior_later_state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    earlier_state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    later_state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    fence: AccountFence,
    checked_at: datetime | None,
    eligible_at: datetime | None,
    value: AlpacaPaperPositionViewSupervisorValue,
) -> AlpacaPaperAuthenticatedPositionViewSupervisorResult:
    result = object.__new__(AlpacaPaperAuthenticatedPositionViewSupervisorResult)
    for field_name, field_value in (
        ("stage", stage),
        ("prior_earlier_state", prior_earlier_state),
        ("prior_later_state", prior_later_state),
        ("earlier_state", earlier_state),
        ("later_state", later_state),
        ("fence", fence),
        ("checked_at", checked_at),
        ("eligible_at", eligible_at),
        ("value", value),
    ):
        object.__setattr__(result, field_name, field_value)
    result._validate()
    return result


def alpaca_paper_position_view_supervisor_round_id(
    earlier_plan: AlpacaPaperPositionSnapshotRuntimePlan,
    later_plan: AlpacaPaperPositionSnapshotRuntimePlan,
) -> str:
    """Return the stable identity for one exact ordered Phase 4W plan pair."""

    earlier = _require_plan(earlier_plan, "earlier position-view plan")
    later = _require_plan(later_plan, "later position-view plan")
    _validate_plan_pair(earlier, later)
    return canonical_id(
        "alpaca-paper-authenticated-position-view-supervisor-round",
        ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_SHA256,
        earlier.plan_id,
        earlier.semantic_sha256,
        later.plan_id,
        later.semantic_sha256,
    )


def _load_exact_state(
    plan: AlpacaPaperPositionSnapshotRuntimePlan,
    *,
    state_loader: AlpacaPaperPositionSnapshotSupervisorStateLoader,
) -> AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
    try:
        state = state_loader.load_state(plan)
    except AlpacaPaperAuthenticatedPositionViewSupervisorError:
        raise
    except Exception as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "authenticated position source state could not be loaded"
        ) from error
    if type(state) is not AlpacaPaperAuthenticatedPositionSnapshotSupervisorState:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position source-state loader returned a non-canonical value"
        )
    state._validate()
    if state.plan != plan:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position source-state loader substituted another plan"
        )
    return state


def _trusted_now(clock: Clock) -> datetime:
    if not callable(getattr(clock, "now", None)):
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position-view supervision requires a trusted clock"
        )
    try:
        value = clock.now()
    except Exception as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position-view supervisor clock failed"
        ) from error
    return _require_utc(value, "position-view supervisor checked_at")


def _capture_exactly_once(
    state: AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    *,
    state_loader: AlpacaPaperPositionSnapshotSupervisorStateLoader,
    capture_workflow: AlpacaPaperPositionSnapshotSupervisorCaptureWorkflow,
    fence: AccountFence,
) -> tuple[
    AlpacaPaperAuthenticatedPositionSnapshotSupervisorState,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
]:
    if state.stage is not AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "only an absent position source may execute its single-use capture"
        )
    try:
        receipt = capture_workflow.capture_once(state.plan, fence=fence)
    except AlpacaPaperAuthenticatedPositionViewSupervisorError:
        raise
    except Exception as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "injected Phase 4T position capture workflow failed"
        ) from error
    if type(receipt) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "Phase 4T capture workflow returned a non-canonical receipt"
        )
    try:
        receipt._validate()
    except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "Phase 4T capture workflow returned invalid evidence"
        ) from error
    advanced = _load_exact_state(state.plan, state_loader=state_loader)
    if advanced.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.STALLED:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorStalled(
            "position capture workflow left its single-use claim stalled"
        )
    _validate_exact_capture(state, advanced, receipt, fence=fence)
    return advanced, receipt


def _validate_ports(
    *,
    state_loader: object,
    capture_workflow: object,
    comparison_repository: object,
    clock: object,
) -> None:
    for value, method_name, field_name in (
        (state_loader, "load_state", "authenticated source-state loader"),
        (state_loader, "load", "Phase 4U receipt loader"),
        (capture_workflow, "capture_once", "Phase 4T one-capture workflow"),
        (comparison_repository, "record", "Phase 4V comparison recorder"),
        (comparison_repository, "load", "Phase 4V comparison loader"),
        (clock, "now", "trusted clock"),
    ):
        if not callable(getattr(value, method_name, None)):
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                f"position-view supervision requires a {field_name}"
            )
    identities = tuple(
        getattr(value, "runtime_store_identity", None)
        for value in (
            state_loader,
            capture_workflow,
            comparison_repository,
        )
    )
    if (
        any(type(identity) is not int or identity <= 0 for identity in identities)
        or len(set(identities)) != 1
    ):
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position-view supervision ports do not share one runtime durable store"
        )


def supervise_authenticated_alpaca_paper_position_views_once(
    earlier_plan: AlpacaPaperPositionSnapshotRuntimePlan,
    later_plan: AlpacaPaperPositionSnapshotRuntimePlan,
    *,
    fence: AccountFence,
    clock: Clock,
    state_loader: AlpacaPaperPositionSnapshotSupervisorStateLoader,
    capture_workflow: AlpacaPaperPositionSnapshotSupervisorCaptureWorkflow,
    comparison_repository: AlpacaPaperPositionViewSupervisorComparisonRepository,
) -> AlpacaPaperAuthenticatedPositionViewSupervisorResult:
    """Perform at most one exact capture execution or one Phase 4V append."""

    earlier_plan = _require_plan(earlier_plan, "earlier position-view plan")
    later_plan = _require_plan(later_plan, "later position-view plan")
    _validate_plan_pair(earlier_plan, later_plan)
    if type(fence) is not AccountFence:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position-view supervision requires an exact account fence"
        )
    try:
        fence.__post_init__()
    except (AccountCoordinatorError, TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position-view supervision fence is invalid"
        ) from error
    if fence.account_id != earlier_plan.description.account_id:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "position-view supervision fence crosses account identities"
        )
    _validate_ports(
        state_loader=state_loader,
        capture_workflow=capture_workflow,
        comparison_repository=comparison_repository,
        clock=clock,
    )

    earlier = _load_exact_state(earlier_plan, state_loader=state_loader)
    later = _load_exact_state(later_plan, state_loader=state_loader)
    stalled = [
        label
        for label, state in (("earlier", earlier), ("later", later))
        if state.stage is AlpacaPaperPositionSnapshotSupervisorSourceStage.STALLED
    ]
    if stalled:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorStalled(
            f"{' and '.join(stalled)} position-view source is conservatively stalled"
        )

    if not earlier.complete:
        if later.stage is not AlpacaPaperPositionSnapshotSupervisorSourceStage.ABSENT:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "later position source completed before the earlier source"
            )
        advanced, receipt = _capture_exactly_once(
            earlier,
            state_loader=state_loader,
            capture_workflow=capture_workflow,
            fence=fence,
        )
        reloaded_later = _load_exact_state(later_plan, state_loader=state_loader)
        if reloaded_later != later:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "unselected later position source changed during earlier capture"
            )
        return _alpaca_paper_authenticated_position_view_supervisor_result(
            stage=AlpacaPaperPositionViewSupervisorStage.EARLIER_CAPTURE_RECORDED,
            prior_earlier_state=earlier,
            prior_later_state=later,
            earlier_state=advanced,
            later_state=reloaded_later,
            fence=fence,
            checked_at=None,
            eligible_at=None,
            value=receipt,
        )

    earlier_receipt = earlier.receipt
    assert earlier_receipt is not None
    eligible_at = (
        earlier_receipt.persisted_snapshot.observation.received_at
        + ALPACA_PAPER_POSITION_VIEW_MINIMUM_START_SEPARATION
    )
    if not later.complete:
        checked_at = _trusted_now(clock)
        if checked_at < eligible_at:
            return _alpaca_paper_authenticated_position_view_supervisor_result(
                stage=AlpacaPaperPositionViewSupervisorStage.WAITING_MINIMUM_SEPARATION,
                prior_earlier_state=earlier,
                prior_later_state=later,
                earlier_state=earlier,
                later_state=later,
                fence=fence,
                checked_at=checked_at,
                eligible_at=eligible_at,
                value=None,
            )
        advanced, receipt = _capture_exactly_once(
            later,
            state_loader=state_loader,
            capture_workflow=capture_workflow,
            fence=fence,
        )
        _require_later_capture_gate(
            earlier,
            advanced,
            eligible_at=eligible_at,
            selected_at=checked_at,
        )
        reloaded_earlier = _load_exact_state(earlier_plan, state_loader=state_loader)
        if reloaded_earlier != earlier:
            raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
                "unselected earlier position source changed during later capture"
            )
        return _alpaca_paper_authenticated_position_view_supervisor_result(
            stage=AlpacaPaperPositionViewSupervisorStage.LATER_CAPTURE_RECORDED,
            prior_earlier_state=earlier,
            prior_later_state=later,
            earlier_state=reloaded_earlier,
            later_state=advanced,
            fence=fence,
            checked_at=checked_at,
            eligible_at=eligible_at,
            value=receipt,
        )

    _require_later_capture_gate(earlier, later, eligible_at=eligible_at)
    comparison_plan = create_authenticated_alpaca_paper_position_view_comparison_plan(
        earlier_plan=earlier_plan,
        later_plan=later_plan,
    )
    try:
        comparison_result = compare_and_record_authenticated_alpaca_paper_position_snapshots(
            comparison_plan,
            fence=fence,
            snapshot_loader=state_loader,
            comparison_repository=comparison_repository,
        )
    except AlpacaPaperAuthenticatedPositionViewComparisonError as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "Phase 4V comparison workflow failed"
        ) from error
    if type(comparison_result) is not AlpacaPaperAuthenticatedPositionViewComparisonResult:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "Phase 4V workflow returned a non-canonical result"
        )
    comparison_result._validate()
    comparison_receipt = comparison_result.receipt
    try:
        reloaded = comparison_repository.load(comparison_receipt.receipt_id)
    except Exception as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "Phase 4V comparison receipt could not be reauthenticated"
        ) from error
    if type(reloaded) is not AlpacaPaperAuthenticatedPositionViewComparisonReceipt:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "Phase 4V comparison loader returned a non-canonical receipt"
        )
    try:
        reloaded._validate()
    except (
        AlpacaPaperAuthenticatedPositionViewComparisonError,
        AlpacaPaperAuthenticatedPositionViewComparisonSourceConflict,
        TypeError,
        ValueError,
    ) as error:
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "Phase 4V comparison loader returned invalid evidence"
        ) from error
    assert earlier.receipt is not None
    assert later.receipt is not None
    if (
        reloaded != comparison_receipt
        or comparison_receipt.evidence.earlier_receipt != earlier.receipt
        or comparison_receipt.evidence.later_receipt != later.receipt
        or comparison_receipt.evidence.comparison.disposition
        is AlpacaPaperPositionSnapshotComparisonDisposition.WAITING_MINIMUM_SEPARATION
    ):
        raise AlpacaPaperAuthenticatedPositionViewSupervisorConflict(
            "Phase 4V result conflicts with current terminal source bindings"
        )
    return _alpaca_paper_authenticated_position_view_supervisor_result(
        stage=AlpacaPaperPositionViewSupervisorStage.COMPARISON_RECORDED,
        prior_earlier_state=earlier,
        prior_later_state=later,
        earlier_state=earlier,
        later_state=later,
        fence=fence,
        checked_at=None,
        eligible_at=eligible_at,
        value=comparison_receipt,
    )


__all__ = [
    "ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_CONTRACT_VERSION",
    "ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_ID",
    "ALPACA_PAPER_AUTHENTICATED_POSITION_VIEW_SUPERVISOR_POLICY_SHA256",
    "ALPACA_PAPER_POSITION_VIEW_MINIMUM_START_SEPARATION",
    "AlpacaPaperAuthenticatedPositionSnapshotSupervisorState",
    "AlpacaPaperAuthenticatedPositionViewSupervisorConflict",
    "AlpacaPaperAuthenticatedPositionViewSupervisorError",
    "AlpacaPaperAuthenticatedPositionViewSupervisorResult",
    "AlpacaPaperAuthenticatedPositionViewSupervisorStalled",
    "AlpacaPaperPositionSnapshotSupervisorCaptureWorkflow",
    "AlpacaPaperPositionSnapshotSupervisorSourceStage",
    "AlpacaPaperPositionSnapshotSupervisorStateLoader",
    "AlpacaPaperPositionViewSupervisorComparisonRepository",
    "AlpacaPaperPositionViewSupervisorStage",
    "AlpacaPaperPositionViewSupervisorValue",
    "alpaca_paper_position_view_supervisor_round_id",
    "supervise_authenticated_alpaca_paper_position_views_once",
]
