"""Bounded restart-safe supervision for two authenticated Alpaca order views.

Phase 4Q performs one durable transition per invocation.  It never loops,
sleeps, or infers executability from a Phase 4O prefix alone: an injected
durable-state port must distinguish absent, active, stalled, exhausted, and
bounded-truncated sources.  Stalled sources fail closed before broker I/O.
The later source must also retain authenticated preparation, request-start,
and observation instants at or after the scheduling gate.  This is conservative
local restart evidence, not qualified provider timing, snapshot isolation, or
convergence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from packages.adapters.broker.alpaca_paper_order_snapshot_comparison import (
    ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION,
)
from packages.adapters.broker.alpaca_paper_order_snapshot_runtime import (
    ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    AlpacaPaperOrderSnapshotConflict,
    AlpacaPaperOrderSnapshotPagePreparationReceipt,
)
from packages.adapters.broker.alpaca_paper_order_snapshots import (
    ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
    AlpacaPaperOrderSnapshotCapture,
    AlpacaPaperOrderSnapshotPageDescription,
    AlpacaPaperOrderSnapshotPlan,
)
from packages.application.alpaca_paper_order_snapshot_comparison import (
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256,
    AlpacaPaperAuthenticatedOrderViewComparisonError,
    AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
    AlpacaPaperAuthenticatedOrderViewComparisonReceipt,
    compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes,
)
from packages.domain.account_coordinator import AccountCoordinatorError, AccountFence
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.clock import Clock
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_CONTRACT_VERSION = (
    "phase4q-bounded-authenticated-order-view-supervisor-v2"
)
ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_ID = (
    "phase4q-one-durable-transition-supervisor-policy-v2"
)
ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION = (
    ALPACA_PAPER_ORDER_SNAPSHOT_MINIMUM_UTC_SEPARATION
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _duration_microseconds(value: timedelta) -> int:
    if type(value) is not timedelta:
        raise TypeError("supervisor duration must be an exact timedelta")
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_CONTRACT_VERSION,
        "supervisor_policy",
        ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_ID,
        ALPACA_PAPER_ORDER_SNAPSHOT_CONTRACT_VERSION,
        ALPACA_PAPER_ORDER_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
        ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_CONTRACT_VERSION,
        ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_COMPARISON_POLICY_SHA256,
        _duration_microseconds(ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION),
        "authenticated_durable_source_stage_required",
        "all_stalled_sources_fail_closed",
        "earlier_capture_first",
        "one_exact_page_or_one_comparison_per_invocation",
        "no_loop_or_sleep",
        "later_first_page_requires_trusted_clock_gate",
        "later_source_requires_authenticated_preparation_and_observed_separation",
        "comparison_receipt_reloaded_from_same_repository",
        "one_process_local_durable_store_required",
        "historical_non_authorizing_result",
    )
)


class AlpacaPaperAuthenticatedOrderViewSupervisorError(RuntimeError):
    """Phase 4Q cannot safely perform its next bounded transition."""


class AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
    AlpacaPaperAuthenticatedOrderViewSupervisorError
):
    """Durable state or a delegated transition conflicts with exact evidence."""


class AlpacaPaperAuthenticatedOrderViewSupervisorStalled(
    AlpacaPaperAuthenticatedOrderViewSupervisorConflict
):
    """At least one source is conservatively non-resumable."""


class AlpacaPaperOrderSnapshotSupervisorSourceStage(StrEnum):
    """Authenticated durable Phase 4O source-head meanings consumed by Phase 4Q."""

    ABSENT = "absent"
    ACTIVE = "active"
    STALLED = "stalled"
    CURSOR_EXHAUSTED = "cursor_exhausted"
    BOUNDED_TRUNCATED = "bounded_truncated"


class AlpacaPaperOrderViewSupervisorStage(StrEnum):
    """The single durable transition, or waiting decision, made by one call."""

    EARLIER_PAGE_ADVANCED = "earlier_page_advanced"
    WAITING_MINIMUM_SEPARATION = "waiting_minimum_separation"
    LATER_PAGE_ADVANCED = "later_page_advanced"
    COMPARISON_RECORDED = "comparison_recorded"


class _NoOrderViewSupervisorAuthority:
    __slots__ = ()

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def raw_response_persisted(self) -> bool:
        return False

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def capture_authenticated(self) -> bool:
        return False

    @property
    def durable_source_positions_authenticated(self) -> bool:
        return False

    @property
    def snapshot_isolation_qualified(self) -> bool:
        return False

    @property
    def provider_snapshot_complete(self) -> bool:
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
    def unknown_resolution_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def reconciliation_ready(self) -> bool:
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
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return value


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            f"{field_name} must be an exact datetime"
        )
    try:
        require_utc(value, field_name)
    except ValueError as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(str(error)) from error
    return value


def _require_plan(value: object, field_name: str) -> AlpacaPaperOrderSnapshotPlan:
    if type(value) is not AlpacaPaperOrderSnapshotPlan:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            f"{field_name} must be an exact Phase 4M plan"
        )
    try:
        value.__post_init__()
    except (TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            f"{field_name} is invalid"
        ) from error
    return value


def _capture(
    prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
) -> AlpacaPaperOrderSnapshotCapture:
    try:
        return prefix.capture
    except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "supervisor source prefix failed authenticated reconstruction"
        ) from error


def _terminal_stage(
    capture: AlpacaPaperOrderSnapshotCapture,
) -> AlpacaPaperOrderSnapshotSupervisorSourceStage | None:
    if capture.pagination_exhausted:
        return AlpacaPaperOrderSnapshotSupervisorSourceStage.CURSOR_EXHAUSTED
    if capture.bounded_truncation:
        return AlpacaPaperOrderSnapshotSupervisorSourceStage.BOUNDED_TRUNCATED
    return None


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedOrderSnapshotSupervisorState(_NoOrderViewSupervisorAuthority):
    """Authenticated durable source-head state supplied to the Phase 4Q supervisor."""

    stage: AlpacaPaperOrderSnapshotSupervisorSourceStage
    prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix
    preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt | None
    source_head_sha256: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedOrderSnapshotSupervisorState must be repository-produced"
        )

    def _validate(self) -> None:
        if type(self.stage) is not AlpacaPaperOrderSnapshotSupervisorSourceStage:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "supervisor source state has an invalid stage"
            )
        if type(self.prefix) is not AlpacaPaperAuthenticatedOrderSnapshotPrefix:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "supervisor source state requires an exact Phase 4O prefix"
            )
        capture = _capture(self.prefix)
        terminal_stage = _terminal_stage(capture)
        next_description = capture.next_page_description

        if self.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.ABSENT:
            if (
                self.prefix.page_receipts
                or self.preparation is not None
                or self.source_head_sha256 is not None
                or next_description is None
            ):
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "absent supervisor source conflicts with durable prefix evidence"
                )
            return

        _require_sha256(
            self.source_head_sha256,
            "supervisor durable source head",
        )
        if self.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.ACTIVE:
            if (
                not self.prefix.page_receipts
                or self.preparation is not None
                or next_description is None
                or terminal_stage is not None
            ):
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "active supervisor source conflicts with durable prefix evidence"
                )
            return

        if self.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED:
            if (
                type(self.preparation) is not AlpacaPaperOrderSnapshotPagePreparationReceipt
                or next_description is None
                or terminal_stage is not None
            ):
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "stalled supervisor source requires its exact pending preparation"
                )
            try:
                self.preparation._validate()
            except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError) as error:
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "stalled supervisor preparation is invalid"
                ) from error
            previous = None if not self.prefix.page_receipts else self.prefix.page_receipts[-1]
            if (
                self.preparation.description != next_description
                or self.preparation.prefix_capture_sha256 != capture.semantic_sha256
                or self.preparation.prefix_page_count != len(self.prefix.page_receipts)
                or self.preparation.previous_page_receipt_id
                != (None if previous is None else previous.receipt_id)
                or self.preparation.previous_page_receipt_sha256
                != (None if previous is None else previous.semantic_sha256)
            ):
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "stalled supervisor preparation conflicts with its exact prefix"
                )
            return

        if self.preparation is not None or self.stage is not terminal_stage:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "terminal supervisor source conflicts with durable prefix evidence"
            )

    @property
    def plan(self) -> AlpacaPaperOrderSnapshotPlan:
        self._validate()
        return self.prefix.plan

    @property
    def capture(self) -> AlpacaPaperOrderSnapshotCapture:
        self._validate()
        return self.prefix.capture

    @property
    def page_count(self) -> int:
        self._validate()
        return len(self.prefix.page_receipts)

    @property
    def terminal(self) -> bool:
        self._validate()
        return self.stage in (
            AlpacaPaperOrderSnapshotSupervisorSourceStage.CURSOR_EXHAUSTED,
            AlpacaPaperOrderSnapshotSupervisorSourceStage.BOUNDED_TRUNCATED,
        )

    @property
    def state_id(self) -> str:
        self._validate()
        return canonical_id(
            "alpaca-paper-authenticated-order-snapshot-supervisor-state",
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256,
            self.prefix.plan.snapshot_id,
            self.stage,
            self.prefix.semantic_sha256,
            (None if self.preparation is None else self.preparation.semantic_sha256),
            self.source_head_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        preparation_sha256 = None if self.preparation is None else self.preparation.semantic_sha256
        state_id = canonical_id(
            "alpaca-paper-authenticated-order-snapshot-supervisor-state",
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256,
            self.prefix.plan.snapshot_id,
            self.stage,
            self.prefix.semantic_sha256,
            preparation_sha256,
            self.source_head_sha256,
        )
        return (
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_CONTRACT_VERSION,
            "authenticated_order_snapshot_supervisor_state",
            state_id,
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_ID,
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256,
            self.stage,
            self.prefix.plan.snapshot_id,
            self.prefix.plan.semantic_sha256,
            self.prefix.prefix_id,
            self.prefix.semantic_sha256,
            preparation_sha256,
            self.source_head_sha256,
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


def _alpaca_paper_authenticated_order_snapshot_supervisor_state(
    *,
    stage: AlpacaPaperOrderSnapshotSupervisorSourceStage,
    prefix: AlpacaPaperAuthenticatedOrderSnapshotPrefix,
    preparation: AlpacaPaperOrderSnapshotPagePreparationReceipt | None,
    source_head_sha256: str | None,
) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
    """Construct one exact authenticated durable source-head state."""

    value = object.__new__(AlpacaPaperAuthenticatedOrderSnapshotSupervisorState)
    for field_name, field_value in (
        ("stage", stage),
        ("prefix", prefix),
        ("preparation", preparation),
        ("source_head_sha256", source_head_sha256),
    ):
        object.__setattr__(value, field_name, field_value)
    value._validate()
    return value


class AlpacaPaperOrderSnapshotSupervisorStateLoader(Protocol):
    """Authenticate both the durable head stage and its exact Phase 4O prefix."""

    @property
    def runtime_store_identity(self) -> int:
        """Opaque process-local identity shared by coherently wired SQL ports."""

        ...

    def load_state(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState: ...

    def load_prefix(
        self,
        plan: AlpacaPaperOrderSnapshotPlan,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPrefix: ...


class AlpacaPaperOrderSnapshotSupervisorPageWorkflow(Protocol):
    """Execute the injected Phase 4O workflow for exactly one description."""

    @property
    def runtime_store_identity(self) -> int: ...

    def advance_one_page(
        self,
        description: AlpacaPaperOrderSnapshotPageDescription,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedOrderSnapshotPageReceipt: ...


class AlpacaPaperOrderViewSupervisorComparisonRepository(Protocol):
    """Record through Phase 4P and reauthenticate the resulting durable receipt."""

    @property
    def runtime_store_identity(self) -> int: ...

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedOrderViewComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt: ...

    def load(
        self,
        receipt_id: str,
    ) -> AlpacaPaperAuthenticatedOrderViewComparisonReceipt | None: ...


AlpacaPaperOrderViewSupervisorValue = (
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt
    | AlpacaPaperAuthenticatedOrderViewComparisonReceipt
    | None
)


def _value_material(
    value: AlpacaPaperOrderViewSupervisorValue,
) -> tuple[str, str | None, str | None]:
    if value is None:
        return ("none", None, None)
    if type(value) is AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        return ("authenticated_page_receipt", value.receipt_id, value.semantic_sha256)
    if type(value) is AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
        return ("authenticated_comparison_receipt", value.receipt_id, value.semantic_sha256)
    raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
        "supervisor result has an invalid value"
    )


def _validate_exact_page_append(
    before: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    after: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    receipt: AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
    *,
    fence: AccountFence,
) -> None:
    if before.stage not in (
        AlpacaPaperOrderSnapshotSupervisorSourceStage.ABSENT,
        AlpacaPaperOrderSnapshotSupervisorSourceStage.ACTIVE,
    ) or after.stage not in (
        AlpacaPaperOrderSnapshotSupervisorSourceStage.ACTIVE,
        AlpacaPaperOrderSnapshotSupervisorSourceStage.CURSOR_EXHAUSTED,
        AlpacaPaperOrderSnapshotSupervisorSourceStage.BOUNDED_TRUNCATED,
    ):
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "page result does not bind an executable source transition"
        )
    description = before.prefix.capture.next_page_description
    expected_receipts = (*before.prefix.page_receipts, receipt)
    if (
        description is None
        or after.prefix.plan != before.prefix.plan
        or after.prefix.page_receipts != expected_receipts
        or receipt != after.prefix.page_receipts[-1]
        or receipt.description != description
        or after.source_head_sha256 is None
        or after.source_head_sha256 == before.source_head_sha256
        or receipt.evidence.pre_fence_receipt.fence != fence
        or receipt.evidence.post_fence_receipt.fence != fence
        or receipt.commit_fence_receipt.fence != fence
    ):
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "page result does not prove one exact same-fence append"
        )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedOrderViewSupervisorResult(_NoOrderViewSupervisorAuthority):
    """One deterministic, historical, non-authorizing Phase 4Q outcome."""

    stage: AlpacaPaperOrderViewSupervisorStage
    prior_earlier_state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState
    prior_later_state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState
    earlier_state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState
    later_state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState
    fence: AccountFence
    checked_at: datetime | None
    eligible_at: datetime | None
    value: AlpacaPaperOrderViewSupervisorValue

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedOrderViewSupervisorResult must be proof-constructed"
        )

    def _validate(self) -> None:
        if type(self.stage) is not AlpacaPaperOrderViewSupervisorStage:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "supervisor result has an invalid stage"
            )
        states = (
            self.prior_earlier_state,
            self.prior_later_state,
            self.earlier_state,
            self.later_state,
        )
        for state in states:
            if type(state) is not AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "supervisor result requires exact authenticated source states"
                )
            state._validate()
        if type(self.fence) is not AccountFence:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "supervisor result requires an exact account fence"
            )
        try:
            self.fence.__post_init__()
        except (AccountCoordinatorError, TypeError, ValueError) as error:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "supervisor result account fence is invalid"
            ) from error
        prior_earlier = self.prior_earlier_state
        prior_later = self.prior_later_state
        earlier = self.earlier_state
        later = self.later_state
        _validate_plan_pair(earlier.prefix.plan, later.prefix.plan)
        if (
            prior_earlier.prefix.plan != earlier.prefix.plan
            or prior_later.prefix.plan != later.prefix.plan
            or self.fence.account_id != earlier.prefix.plan.account_id
        ):
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "supervisor result changed its exact round binding"
            )

        if self.stage is AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED:
            if (
                type(self.value) is not AlpacaPaperAuthenticatedOrderSnapshotPageReceipt
                or prior_earlier.terminal
                or prior_earlier.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED
                or prior_later.stage is not AlpacaPaperOrderSnapshotSupervisorSourceStage.ABSENT
                or later != prior_later
                or self.checked_at is not None
                or self.eligible_at is not None
            ):
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "earlier-page result conflicts with exact supervisor state"
                )
            _validate_exact_page_append(
                prior_earlier,
                earlier,
                self.value,
                fence=self.fence,
            )
            return

        if prior_earlier != earlier or not earlier.terminal:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "later supervisor result requires a terminal earlier source"
            )
        earlier_capture = earlier.prefix.capture
        expected_eligible_at = (
            earlier_capture.pages[-1].observation.received_at
            + ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION
        )
        if self.eligible_at != expected_eligible_at:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "supervisor result uses another later-capture eligibility instant"
            )

        if self.stage is AlpacaPaperOrderViewSupervisorStage.WAITING_MINIMUM_SEPARATION:
            checked_at = _require_utc(
                self.checked_at,
                "supervisor separation checked_at",
            )
            if (
                self.value is not None
                or prior_later != later
                or later.stage is not AlpacaPaperOrderSnapshotSupervisorSourceStage.ABSENT
                or checked_at >= expected_eligible_at
            ):
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "waiting result conflicts with exact supervisor state"
                )
            return

        if self.stage is AlpacaPaperOrderViewSupervisorStage.LATER_PAGE_ADVANCED:
            if (
                type(self.value) is not AlpacaPaperAuthenticatedOrderSnapshotPageReceipt
                or prior_later.terminal
                or prior_later.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED
            ):
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "later-page result conflicts with exact supervisor state"
                )
            _validate_exact_page_append(
                prior_later,
                later,
                self.value,
                fence=self.fence,
            )
            _require_strict_source_ingress_order(earlier, later)
            _require_authenticated_later_start(
                later,
                eligible_at=expected_eligible_at,
            )
            if not prior_later.prefix.page_receipts:
                checked_at = _require_utc(
                    self.checked_at,
                    "supervisor separation checked_at",
                )
                if checked_at < expected_eligible_at:
                    raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                        "later first-page result predates the trusted clock gate"
                    )
            elif self.checked_at is not None:
                raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                    "continued later traversal cannot claim a first-page clock check"
                )
            return

        if (
            self.stage is not AlpacaPaperOrderViewSupervisorStage.COMPARISON_RECORDED
            or type(self.value) is not AlpacaPaperAuthenticatedOrderViewComparisonReceipt
            or prior_later != later
            or not later.terminal
            or self.checked_at is not None
            or self.value.evidence.earlier_prefix != earlier.prefix
            or self.value.evidence.later_prefix != later.prefix
            or self.value.earlier_source_head_sha256 != earlier.source_head_sha256
            or self.value.later_source_head_sha256 != later.source_head_sha256
        ):
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "comparison result conflicts with exact terminal source state"
            )
        _require_strict_source_ingress_order(earlier, later)
        _require_authenticated_later_start(
            later,
            eligible_at=expected_eligible_at,
        )

    @property
    def round_id(self) -> str:
        self._validate()
        return alpaca_paper_order_view_supervisor_round_id(
            self.earlier_state.prefix.plan,
            self.later_state.prefix.plan,
        )

    @property
    def result_id(self) -> str:
        self._validate()
        value_kind, value_id, value_sha256 = _value_material(self.value)
        return canonical_id(
            "alpaca-paper-authenticated-order-view-supervisor-result",
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256,
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
        round_id = alpaca_paper_order_view_supervisor_round_id(
            self.earlier_state.prefix.plan,
            self.later_state.prefix.plan,
        )
        result_id = canonical_id(
            "alpaca-paper-authenticated-order-view-supervisor-result",
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256,
            round_id,
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
        return (
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_CONTRACT_VERSION,
            "authenticated_order_view_supervisor_result",
            result_id,
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_ID,
            ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256,
            round_id,
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


def _alpaca_paper_authenticated_order_view_supervisor_result(
    *,
    stage: AlpacaPaperOrderViewSupervisorStage,
    prior_earlier_state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    prior_later_state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    earlier_state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    later_state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    fence: AccountFence,
    checked_at: datetime | None,
    eligible_at: datetime | None,
    value: AlpacaPaperOrderViewSupervisorValue,
) -> AlpacaPaperAuthenticatedOrderViewSupervisorResult:
    result = object.__new__(AlpacaPaperAuthenticatedOrderViewSupervisorResult)
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


def _validate_plan_pair(
    earlier_plan: AlpacaPaperOrderSnapshotPlan,
    later_plan: AlpacaPaperOrderSnapshotPlan,
) -> None:
    if earlier_plan.snapshot_id == later_plan.snapshot_id:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervision requires two distinct plans"
        )
    if earlier_plan.account_id != later_plan.account_id:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervision plans cross account identities"
        )
    if (
        earlier_plan.page_limit != later_plan.page_limit
        or earlier_plan.maximum_pages != later_plan.maximum_pages
    ):
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervision plans use different traversal profiles"
        )


def alpaca_paper_order_view_supervisor_round_id(
    earlier_plan: AlpacaPaperOrderSnapshotPlan,
    later_plan: AlpacaPaperOrderSnapshotPlan,
) -> str:
    """Return the stable identity of one ordered exact Phase 4Q plan pair."""

    earlier_plan = _require_plan(earlier_plan, "earlier order-view plan")
    later_plan = _require_plan(later_plan, "later order-view plan")
    _validate_plan_pair(earlier_plan, later_plan)
    return canonical_id(
        "alpaca-paper-authenticated-order-view-supervisor-round",
        ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256,
        earlier_plan.snapshot_id,
        earlier_plan.semantic_sha256,
        later_plan.snapshot_id,
        later_plan.semantic_sha256,
    )


def _load_exact_state(
    plan: AlpacaPaperOrderSnapshotPlan,
    *,
    state_loader: AlpacaPaperOrderSnapshotSupervisorStateLoader,
) -> AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
    try:
        state = state_loader.load_state(plan)
    except AlpacaPaperAuthenticatedOrderViewSupervisorError:
        raise
    except Exception as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "authenticated supervisor source state could not be loaded"
        ) from error
    if type(state) is not AlpacaPaperAuthenticatedOrderSnapshotSupervisorState:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "supervisor state loader returned a non-canonical value"
        )
    state._validate()
    if state.prefix.plan != plan:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "supervisor state loader substituted another plan"
        )
    return state


def _trusted_now(clock: Clock) -> datetime:
    if not callable(getattr(clock, "now", None)):
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervision requires a trusted clock"
        )
    try:
        value = clock.now()
    except Exception as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervisor clock failed"
        ) from error
    return _require_utc(value, "order-view supervisor checked_at")


def _advance_exactly_one_page(
    state: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    *,
    state_loader: AlpacaPaperOrderSnapshotSupervisorStateLoader,
    page_workflow: AlpacaPaperOrderSnapshotSupervisorPageWorkflow,
    fence: AccountFence,
) -> tuple[
    AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    AlpacaPaperAuthenticatedOrderSnapshotPageReceipt,
]:
    description = state.prefix.capture.next_page_description
    if description is None:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "terminal order-view source cannot execute another page"
        )
    try:
        receipt = page_workflow.advance_one_page(description, fence=fence)
    except AlpacaPaperAuthenticatedOrderViewSupervisorError:
        raise
    except Exception as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "injected Phase 4O page workflow failed"
        ) from error
    if type(receipt) is not AlpacaPaperAuthenticatedOrderSnapshotPageReceipt:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "Phase 4O page workflow returned a non-canonical receipt"
        )
    try:
        receipt._validate()
    except (AlpacaPaperOrderSnapshotConflict, TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "Phase 4O page workflow returned invalid evidence"
        ) from error
    advanced = _load_exact_state(
        state.prefix.plan,
        state_loader=state_loader,
    )
    if advanced.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorStalled(
            "page workflow left the source conservatively stalled"
        )
    _validate_exact_page_append(
        state,
        advanced,
        receipt,
        fence=fence,
    )
    return advanced, receipt


def _require_strict_source_ingress_order(
    earlier: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    later: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
) -> None:
    if not later.prefix.page_receipts:
        return
    earlier_tip_sequence = earlier.prefix.page_receipts[-1].persisted_page.receipt.ingress_sequence
    later_first_sequence = later.prefix.page_receipts[0].persisted_page.receipt.ingress_sequence
    if earlier_tip_sequence >= later_first_sequence:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "later source does not strictly follow the earlier raw ingress history"
        )


def _require_authenticated_later_start(
    later: AlpacaPaperAuthenticatedOrderSnapshotSupervisorState,
    *,
    eligible_at: datetime,
) -> None:
    if not later.prefix.page_receipts:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "later source has no authenticated first-page timing evidence"
        )
    first_receipt = later.prefix.page_receipts[0]
    first_page = later.prefix.capture.pages[0]
    if (
        first_receipt.evidence.preparation.prepared_at < eligible_at
        or first_receipt.evidence.request.started_at < eligible_at
        or first_page.observation.received_at < eligible_at
    ):
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "later source lacks authenticated gate-separated start evidence"
        )


def _validate_ports(
    *,
    state_loader: object,
    page_workflow: object,
    comparison_repository: object,
    clock: object,
) -> None:
    for value, method_name, field_name in (
        (state_loader, "load_state", "authenticated source-state loader"),
        (state_loader, "load_prefix", "Phase 4O prefix loader"),
        (page_workflow, "advance_one_page", "Phase 4O one-page workflow"),
        (comparison_repository, "record", "Phase 4P comparison recorder"),
        (comparison_repository, "load", "Phase 4P comparison loader"),
        (clock, "now", "trusted clock"),
    ):
        if not callable(getattr(value, method_name, None)):
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                f"order-view supervision requires a {field_name}"
            )
    try:
        identities = tuple(
            getattr(value, "runtime_store_identity", None)
            for value in (
                state_loader,
                page_workflow,
                comparison_repository,
            )
        )
    except Exception as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervision ports could not identify their runtime durable store"
        ) from error
    if (
        any(type(identity) is not int or identity <= 0 for identity in identities)
        or len(set(identities)) != 1
    ):
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervision ports do not share one runtime durable store"
        )


def supervise_authenticated_alpaca_paper_order_views_once(
    earlier_plan: AlpacaPaperOrderSnapshotPlan,
    later_plan: AlpacaPaperOrderSnapshotPlan,
    *,
    fence: AccountFence,
    clock: Clock,
    state_loader: AlpacaPaperOrderSnapshotSupervisorStateLoader,
    page_workflow: AlpacaPaperOrderSnapshotSupervisorPageWorkflow,
    comparison_repository: AlpacaPaperOrderViewSupervisorComparisonRepository,
) -> AlpacaPaperAuthenticatedOrderViewSupervisorResult:
    """Perform at most one exact page execution or one Phase 4P append."""

    earlier_plan = _require_plan(earlier_plan, "earlier order-view plan")
    later_plan = _require_plan(later_plan, "later order-view plan")
    _validate_plan_pair(earlier_plan, later_plan)
    if type(fence) is not AccountFence:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervision requires an exact account fence"
        )
    try:
        fence.__post_init__()
    except (AccountCoordinatorError, TypeError, ValueError) as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervision fence is invalid"
        ) from error
    if fence.account_id != earlier_plan.account_id:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "order-view supervision fence crosses account identities"
        )
    _validate_ports(
        state_loader=state_loader,
        page_workflow=page_workflow,
        comparison_repository=comparison_repository,
        clock=clock,
    )

    earlier = _load_exact_state(earlier_plan, state_loader=state_loader)
    later = _load_exact_state(later_plan, state_loader=state_loader)
    stalled = [
        label
        for label, state in (("earlier", earlier), ("later", later))
        if state.stage is AlpacaPaperOrderSnapshotSupervisorSourceStage.STALLED
    ]
    if stalled:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorStalled(
            f"{' and '.join(stalled)} order-view source is conservatively stalled"
        )

    if not earlier.terminal:
        if later.stage is not AlpacaPaperOrderSnapshotSupervisorSourceStage.ABSENT:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "later source advanced before the earlier source became terminal"
            )
        advanced, receipt = _advance_exactly_one_page(
            earlier,
            state_loader=state_loader,
            page_workflow=page_workflow,
            fence=fence,
        )
        reloaded_later = _load_exact_state(
            later_plan,
            state_loader=state_loader,
        )
        if reloaded_later != later:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "unselected later source changed during earlier page execution"
            )
        return _alpaca_paper_authenticated_order_view_supervisor_result(
            stage=AlpacaPaperOrderViewSupervisorStage.EARLIER_PAGE_ADVANCED,
            prior_earlier_state=earlier,
            prior_later_state=later,
            earlier_state=advanced,
            later_state=reloaded_later,
            fence=fence,
            checked_at=None,
            eligible_at=None,
            value=receipt,
        )

    earlier_capture = earlier.prefix.capture
    eligible_at = (
        earlier_capture.pages[-1].observation.received_at
        + ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION
    )
    if not later.terminal:
        checked_at: datetime | None = None
        if not later.prefix.page_receipts:
            checked_at = _trusted_now(clock)
            if checked_at < eligible_at:
                return _alpaca_paper_authenticated_order_view_supervisor_result(
                    stage=(AlpacaPaperOrderViewSupervisorStage.WAITING_MINIMUM_SEPARATION),
                    prior_earlier_state=earlier,
                    prior_later_state=later,
                    earlier_state=earlier,
                    later_state=later,
                    fence=fence,
                    checked_at=checked_at,
                    eligible_at=eligible_at,
                    value=None,
                )
        else:
            _require_strict_source_ingress_order(earlier, later)
            _require_authenticated_later_start(
                later,
                eligible_at=eligible_at,
            )
        advanced, receipt = _advance_exactly_one_page(
            later,
            state_loader=state_loader,
            page_workflow=page_workflow,
            fence=fence,
        )
        _require_authenticated_later_start(
            advanced,
            eligible_at=eligible_at,
        )
        _require_strict_source_ingress_order(earlier, advanced)
        reloaded_earlier = _load_exact_state(
            earlier_plan,
            state_loader=state_loader,
        )
        if reloaded_earlier != earlier:
            raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
                "unselected earlier source changed during later page execution"
            )
        return _alpaca_paper_authenticated_order_view_supervisor_result(
            stage=AlpacaPaperOrderViewSupervisorStage.LATER_PAGE_ADVANCED,
            prior_earlier_state=earlier,
            prior_later_state=later,
            earlier_state=reloaded_earlier,
            later_state=advanced,
            fence=fence,
            checked_at=checked_at,
            eligible_at=eligible_at,
            value=receipt,
        )

    _require_strict_source_ingress_order(earlier, later)
    _require_authenticated_later_start(
        later,
        eligible_at=eligible_at,
    )
    try:
        comparison_receipt = compare_and_record_authenticated_alpaca_paper_order_snapshot_prefixes(
            earlier_plan,
            later_plan,
            fence=fence,
            prefix_loader=state_loader,
            comparison_repository=comparison_repository,
        )
    except AlpacaPaperAuthenticatedOrderViewComparisonError as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "Phase 4P comparison workflow failed"
        ) from error
    try:
        reloaded = comparison_repository.load(comparison_receipt.receipt_id)
    except Exception as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "Phase 4P comparison receipt could not be reauthenticated"
        ) from error
    if type(reloaded) is not AlpacaPaperAuthenticatedOrderViewComparisonReceipt:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "Phase 4P comparison loader returned a non-canonical receipt"
        )
    try:
        reloaded._validate()
    except AlpacaPaperAuthenticatedOrderViewComparisonError as error:
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "Phase 4P comparison loader returned invalid evidence"
        ) from error
    if (
        reloaded != comparison_receipt
        or comparison_receipt.evidence.earlier_prefix != earlier.prefix
        or comparison_receipt.evidence.later_prefix != later.prefix
        or comparison_receipt.earlier_source_head_sha256 != earlier.source_head_sha256
        or comparison_receipt.later_source_head_sha256 != later.source_head_sha256
    ):
        raise AlpacaPaperAuthenticatedOrderViewSupervisorConflict(
            "Phase 4P result conflicts with current terminal source bindings"
        )
    return _alpaca_paper_authenticated_order_view_supervisor_result(
        stage=AlpacaPaperOrderViewSupervisorStage.COMPARISON_RECORDED,
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
    "ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_CONTRACT_VERSION",
    "ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_ID",
    "ALPACA_PAPER_AUTHENTICATED_ORDER_VIEW_SUPERVISOR_POLICY_SHA256",
    "ALPACA_PAPER_ORDER_VIEW_MINIMUM_START_SEPARATION",
    "AlpacaPaperAuthenticatedOrderSnapshotSupervisorState",
    "AlpacaPaperAuthenticatedOrderViewSupervisorConflict",
    "AlpacaPaperAuthenticatedOrderViewSupervisorError",
    "AlpacaPaperAuthenticatedOrderViewSupervisorResult",
    "AlpacaPaperAuthenticatedOrderViewSupervisorStalled",
    "AlpacaPaperOrderSnapshotSupervisorPageWorkflow",
    "AlpacaPaperOrderSnapshotSupervisorSourceStage",
    "AlpacaPaperOrderSnapshotSupervisorStateLoader",
    "AlpacaPaperOrderViewSupervisorComparisonRepository",
    "AlpacaPaperOrderViewSupervisorStage",
    "AlpacaPaperOrderViewSupervisorValue",
    "alpaca_paper_order_view_supervisor_round_id",
    "supervise_authenticated_alpaca_paper_order_views_once",
]
