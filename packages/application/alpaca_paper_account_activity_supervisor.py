"""Bounded restart-safe supervision for two authenticated account-activity views.

Phase 4AI performs at most one provider page or one Phase 4AG comparison
append per invocation.  It reloads exact Phase 4AE traversal states on every
call, never retries a stalled single-use page claim, and starts the later
capture only at or after the fixed two-second boundary.  The result is
deterministic historical evidence, not current account status, complete
activity history, reconciliation, readiness, broker, or trading authority.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from packages.adapters.broker.alpaca_paper_account_activities import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
    AlpacaPaperAccountActivityPageDescription,
    AlpacaPaperAccountActivityPlan,
)
from packages.adapters.broker.alpaca_paper_account_activity_comparison import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_MINIMUM_UTC_SEPARATION,
    AlpacaPaperAccountActivityComparisonDisposition,
)
from packages.adapters.broker.alpaca_paper_account_activity_runtime import (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAccountActivityTraversalStage,
    AlpacaPaperAuthenticatedAccountActivityPageReceipt,
    AlpacaPaperAuthenticatedAccountActivityTraversalState,
)
from packages.application.alpaca_paper_account_activity_comparison import (
    ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
    ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
    AlpacaPaperAuthenticatedAccountActivityComparisonError,
    AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
    AlpacaPaperAuthenticatedAccountActivityComparisonReceipt,
    compare_and_record_authenticated_alpaca_paper_account_activity_prefixes,
)
from packages.domain.account_coordinator import AccountCoordinatorError, AccountFence
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.clock import Clock
from packages.domain.identifiers import canonical_id
from packages.domain.models import require_utc

ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_CONTRACT_VERSION = (
    "phase4ai-bounded-authenticated-account-activity-supervisor-v1"
)
ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_ID = (
    "phase4ai-one-effect-account-activity-supervisor-policy-v1"
)
ALPACA_PAPER_ACCOUNT_ACTIVITY_SUPERVISOR_MINIMUM_START_SEPARATION = (
    ALPACA_PAPER_ACCOUNT_ACTIVITY_MINIMUM_UTC_SEPARATION
)


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _duration_microseconds(value: timedelta) -> int:
    if type(value) is not timedelta:
        raise TypeError("account-activity supervisor duration must be an exact timedelta")
    return (value.days * 86_400 + value.seconds) * 1_000_000 + value.microseconds


ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_CONTRACT_VERSION,
        "supervisor_policy",
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_ID,
        ALPACA_PAPER_ACCOUNT_ACTIVITY_CONTRACT_VERSION,
        ALPACA_PAPER_ACCOUNT_ACTIVITY_RUNTIME_CONTRACT_VERSION,
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_CONTRACT_VERSION,
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_COMPARISON_POLICY_SHA256,
        _duration_microseconds(ALPACA_PAPER_ACCOUNT_ACTIVITY_SUPERVISOR_MINIMUM_START_SEPARATION),
        "two_distinct_ordered_exact_phase4ad_plans",
        "same_account_and_traversal_profile",
        "reload_and_revalidate_both_phase4ae_states_each_invocation",
        "all_ports_share_one_positive_process_local_runtime_store_identity",
        "stalled_single_use_claims_never_resend",
        "earlier_capture_advances_first",
        "later_first_page_starts_at_or_after_exact_boundary",
        "one_provider_page_or_one_phase4ag_append_per_invocation",
        "wait_without_provider_or_append_effect",
        "no_loop_sleep_retry_or_pair_admission",
        "historical_non_authorizing_result",
    )
)


class AlpacaPaperAuthenticatedAccountActivitySupervisorError(RuntimeError):
    """Phase 4AI could not safely select or authenticate its next bounded action."""


class AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
    AlpacaPaperAuthenticatedAccountActivitySupervisorError
):
    """Plans, durable state, time, or a delegated effect conflict with evidence."""


class AlpacaPaperAuthenticatedAccountActivitySupervisorStalled(
    AlpacaPaperAuthenticatedAccountActivitySupervisorConflict
):
    """At least one exact Phase 4AE single-use page claim is stalled."""


class AlpacaPaperAccountActivitySupervisorAction(StrEnum):
    """The one effect, or explicit no-effect wait, selected by an invocation."""

    EARLIER_PAGE_ADVANCED = "earlier_page_advanced"
    WAITING_MINIMUM_SEPARATION = "waiting_minimum_separation"
    LATER_PAGE_ADVANCED = "later_page_advanced"
    COMPARISON_RECORDED = "comparison_recorded"


class AlpacaPaperAccountActivitySupervisorReason(StrEnum):
    """Deterministic reason for the selected Phase 4AI action."""

    EARLIER_TRAVERSAL_REQUIRES_PAGE = "earlier_traversal_requires_page"
    LATER_START_GATE_NOT_REACHED = "later_start_gate_not_reached"
    LATER_TRAVERSAL_REQUIRES_PAGE = "later_traversal_requires_page"
    TERMINAL_PAIR_READY = "terminal_pair_ready"


class _NoAccountActivitySupervisorAuthority:
    __slots__ = ()

    @property
    def request_budget_enforced(self) -> bool:
        return False

    @property
    def authenticated_provider_evidence(self) -> bool:
        return False

    @property
    def raw_response_persisted(self) -> bool:
        return False

    @property
    def provider_io_performed(self) -> bool:
        return False

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def account_status_current(self) -> bool:
        return False

    @property
    def provider_account_status_current(self) -> bool:
        return False

    @property
    def capture_authenticated(self) -> bool:
        return False

    @property
    def durable_source_positions_authenticated(self) -> bool:
        return False

    @property
    def comparison_durably_recorded(self) -> bool:
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
    def activity_history_complete(self) -> bool:
        return False

    @property
    def activity_history_consistent(self) -> bool:
        return False

    @property
    def converged(self) -> bool:
        return False

    @property
    def monotonic_timing_qualified(self) -> bool:
        return False

    @property
    def provider_activity_identity_qualified(self) -> bool:
        return False

    @property
    def provider_activity_sequence_identity_qualified(self) -> bool:
        return False

    @property
    def provider_activity_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_execution_identity_qualified(self) -> bool:
        return False

    @property
    def canonical_execution_identity_qualified(self) -> bool:
        return False

    @property
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def execution_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_identity_qualified(self) -> bool:
        return False

    @property
    def provider_bust_identity_qualified(self) -> bool:
        return False

    @property
    def provider_correction_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_execution_revision_authorized(self) -> bool:
        return False

    @property
    def canonical_account_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_ledger_fact_authorized(self) -> bool:
        return False

    @property
    def canonical_cash_fact_authorized(self) -> bool:
        return False

    @property
    def execution_application_authorized(self) -> bool:
        return False

    @property
    def bust_application_authorized(self) -> bool:
        return False

    @property
    def correction_application_authorized(self) -> bool:
        return False

    @property
    def manual_activity_application_authorized(self) -> bool:
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
    def reservation_release_authorized(self) -> bool:
        return False

    @property
    def resubmission_authorized(self) -> bool:
        return False

    @property
    def readiness_transition_authorized(self) -> bool:
        return False

    @property
    def activity_snapshot_pagination_ready(self) -> bool:
        return False

    @property
    def decode_quarantine_ready(self) -> bool:
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
    def additional_reconciliation_required(self) -> bool:
        return True


def _require_utc(value: object, field_name: str) -> datetime:
    if type(value) is not datetime:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} must be an exact datetime"
        )
    try:
        require_utc(value, field_name)
    except ValueError:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} must be UTC"
        ) from None
    return value


def _require_plan(
    value: object,
    field_name: str,
) -> AlpacaPaperAccountActivityPlan:
    if type(value) is not AlpacaPaperAccountActivityPlan:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} must be an exact Phase 4AD plan"
        )
    try:
        value.__post_init__()
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} is invalid"
        ) from None
    return value


def _validate_plan_pair(
    earlier_plan: AlpacaPaperAccountActivityPlan,
    later_plan: AlpacaPaperAccountActivityPlan,
) -> None:
    if earlier_plan.capture_id == later_plan.capture_id:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity supervision requires two distinct ordered plans"
        )
    if earlier_plan.account_id != later_plan.account_id:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity supervision plans cross account identities"
        )
    if (
        earlier_plan.page_size != later_plan.page_size
        or earlier_plan.maximum_pages != later_plan.maximum_pages
        or earlier_plan.maximum_items != later_plan.maximum_items
    ):
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity supervision plans use different traversal profiles"
        )


def _terminal(
    state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
) -> bool:
    return state.stage in (
        AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED,
        AlpacaPaperAccountActivityTraversalStage.BOUNDED_TRUNCATED,
    )


def _validate_state(
    value: object,
    *,
    plan: AlpacaPaperAccountActivityPlan,
    field_name: str,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    if type(value) is not AlpacaPaperAuthenticatedAccountActivityTraversalState:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} loader returned a non-canonical Phase 4AE state"
        )
    try:
        value._validate()
        loaded_plan = value.prefix.plan
        _ = value.semantic_sha256
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} failed exact Phase 4AE reconstruction"
        ) from None
    if loaded_plan != plan:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} loader substituted another plan"
        )
    return value


class AlpacaPaperAccountActivitySupervisorStateLoader(Protocol):
    """Reload one exact Phase 4AE traversal state."""

    @property
    def runtime_store_identity(self) -> int: ...

    def load_state(
        self,
        plan: AlpacaPaperAccountActivityPlan,
    ) -> AlpacaPaperAuthenticatedAccountActivityTraversalState | None: ...


class AlpacaPaperAccountActivitySupervisorPageRuntime(Protocol):
    """Execute and durably append exactly one Phase 4AE page."""

    @property
    def runtime_store_identity(self) -> int: ...

    def advance_one_page(
        self,
        description: AlpacaPaperAccountActivityPageDescription,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedAccountActivityPageReceipt: ...


class AlpacaPaperAccountActivitySupervisorComparisonRepository(Protocol):
    """Append one exact Phase 4AG comparison under an account fence."""

    @property
    def runtime_store_identity(self) -> int: ...

    def record(
        self,
        evidence: AlpacaPaperAuthenticatedAccountActivityComparisonEvidence,
        *,
        fence: AccountFence,
    ) -> AlpacaPaperAuthenticatedAccountActivityComparisonReceipt: ...


AlpacaPaperAccountActivitySupervisorValue = (
    AlpacaPaperAuthenticatedAccountActivityPageReceipt
    | AlpacaPaperAuthenticatedAccountActivityComparisonReceipt
    | None
)


def _runtime_store_identity(value: object, field_name: str) -> int:
    try:
        identity = value.runtime_store_identity  # type: ignore[attr-defined]
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} runtime-store identity is unavailable"
        ) from None
    if type(identity) is not int or identity <= 0:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} runtime-store identity must be a positive exact integer"
        )
    return identity


def _validate_ports(
    *,
    state_loader: object,
    page_runtime: object,
    comparison_repository: object,
    clock: object,
) -> int:
    identities = (
        _runtime_store_identity(
            state_loader,
            "account-activity state loader",
        ),
        _runtime_store_identity(
            page_runtime,
            "account-activity one-page runtime",
        ),
        _runtime_store_identity(
            comparison_repository,
            "account-activity comparison repository",
        ),
    )
    if len(set(identities)) != 1:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity supervisor ports do not share one process-local runtime store"
        )
    try:
        capabilities = tuple(
            (
                getattr(value, method_name, None),
                field_name,
            )
            for value, method_name, field_name in (
                (state_loader, "load_state", "Phase 4AE state loader"),
                (page_runtime, "advance_one_page", "Phase 4AE one-page runtime"),
                (
                    comparison_repository,
                    "record",
                    "Phase 4AG comparison repository",
                ),
                (clock, "now", "trusted clock"),
            )
        )
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity supervisor port capabilities are unavailable"
        ) from None
    for capability, field_name in capabilities:
        if not callable(capability):
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                f"account-activity supervision requires a {field_name}"
            )
    return identities[0]


def _load_exact_state(
    plan: AlpacaPaperAccountActivityPlan,
    *,
    state_loader: AlpacaPaperAccountActivitySupervisorStateLoader,
    field_name: str,
) -> AlpacaPaperAuthenticatedAccountActivityTraversalState:
    try:
        value = state_loader.load_state(plan)
    except AlpacaPaperAuthenticatedAccountActivitySupervisorError:
        raise
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} could not be loaded"
        ) from None
    if value is None:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} loader returned no explicit Phase 4AE state"
        )
    return _validate_state(
        value,
        plan=plan,
        field_name=field_name,
    )


def _trusted_now(clock: Clock) -> datetime:
    try:
        value = clock.now()
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity supervisor clock failed"
        ) from None
    return _require_utc(
        value,
        "account-activity supervisor checked_at",
    )


def _eligible_at(
    earlier: AlpacaPaperAuthenticatedAccountActivityTraversalState,
) -> datetime:
    if not _terminal(earlier):
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "later eligibility requires a terminal earlier activity source"
        )
    try:
        received_at = earlier.prefix.capture.pages[-1].observation.received_at
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "terminal earlier activity source has no exact final receive instant"
        ) from None
    return (
        _require_utc(
            received_at,
            "earlier terminal account-activity received_at",
        )
        + ALPACA_PAPER_ACCOUNT_ACTIVITY_SUPERVISOR_MINIMUM_START_SEPARATION
    )


def _require_strict_source_ingress_order(
    earlier: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    later: AlpacaPaperAuthenticatedAccountActivityTraversalState,
) -> None:
    try:
        earlier_sequence = earlier.prefix.page_receipts[-1].persisted_page.receipt.ingress_sequence
        later_sequence = later.prefix.page_receipts[0].persisted_page.receipt.ingress_sequence
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity source ingress evidence is malformed"
        ) from None
    if earlier_sequence >= later_sequence:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "later account-activity source does not follow earlier raw ingress"
        )


def _require_authenticated_later_start(
    later: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    *,
    eligible_at: datetime,
    selected_at: datetime | None = None,
) -> None:
    try:
        first_receipt = later.prefix.page_receipts[0]
        first_receipt._validate()
        preparation_at = first_receipt.evidence.preparation.prepared_at
        request_at = first_receipt.evidence.request.started_at
        received_at = first_receipt.persisted_page.observation.received_at
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "later account-activity source lacks exact first-page timing evidence"
        ) from None
    if selected_at is not None:
        selected_at = _require_utc(
            selected_at,
            "later account-activity selected_at",
        )
    if (
        preparation_at < eligible_at
        or (selected_at is not None and preparation_at < selected_at)
        or request_at < eligible_at
        or received_at < eligible_at
    ):
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "later account-activity source lacks gate-separated start evidence"
        )


def _validate_exact_page_append(
    before: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    after: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    receipt: AlpacaPaperAuthenticatedAccountActivityPageReceipt,
    *,
    fence: AccountFence,
) -> None:
    if before.stage not in (
        AlpacaPaperAccountActivityTraversalStage.ABSENT,
        AlpacaPaperAccountActivityTraversalStage.ACTIVE,
    ) or after.stage not in (
        AlpacaPaperAccountActivityTraversalStage.ACTIVE,
        AlpacaPaperAccountActivityTraversalStage.CURSOR_EXHAUSTED,
        AlpacaPaperAccountActivityTraversalStage.BOUNDED_TRUNCATED,
    ):
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "page workflow does not bind one executable Phase 4AE transition"
        )
    try:
        description = before.prefix.next_page_description
        receipt._validate()
        expected_receipts = (*before.prefix.page_receipts, receipt)
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "page workflow returned malformed Phase 4AE evidence"
        ) from None
    if (
        description is None
        or after.prefix.plan != before.prefix.plan
        or after.prefix.page_receipts != expected_receipts
        or receipt.description != description
        or receipt != after.prefix.page_receipts[-1]
        or after.source_head_sha256 is None
        or after.source_head_sha256 == before.source_head_sha256
        or receipt.evidence.pre_fence_receipt.fence != fence
        or receipt.evidence.post_fence_receipt.fence != fence
        or receipt.commit_fence_receipt.fence != fence
    ):
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "page workflow did not prove one exact same-fence append"
        )


def _advance_exactly_one_page(
    state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    *,
    state_loader: AlpacaPaperAccountActivitySupervisorStateLoader,
    page_runtime: AlpacaPaperAccountActivitySupervisorPageRuntime,
    fence: AccountFence,
    field_name: str,
) -> tuple[
    AlpacaPaperAuthenticatedAccountActivityTraversalState,
    AlpacaPaperAuthenticatedAccountActivityPageReceipt,
]:
    try:
        description = state.prefix.next_page_description
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} has malformed next-page evidence"
        ) from None
    if description is None:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            f"{field_name} is terminal and cannot advance another page"
        )
    try:
        receipt = page_runtime.advance_one_page(
            description,
            fence=fence,
        )
    except AlpacaPaperAuthenticatedAccountActivitySupervisorError:
        raise
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "injected Phase 4AE one-page runtime failed"
        ) from None
    if type(receipt) is not AlpacaPaperAuthenticatedAccountActivityPageReceipt:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "Phase 4AE one-page runtime returned a non-canonical receipt"
        )
    advanced = _load_exact_state(
        state.prefix.plan,
        state_loader=state_loader,
        field_name=field_name,
    )
    if advanced.stage is AlpacaPaperAccountActivityTraversalStage.STALLED:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorStalled(
            f"{field_name} remained stalled after its single page claim"
        )
    _validate_exact_page_append(
        state,
        advanced,
        receipt,
        fence=fence,
    )
    return advanced, receipt


def _value_material(
    value: AlpacaPaperAccountActivitySupervisorValue,
) -> tuple[str, str | None, str | None]:
    if value is None:
        return ("none", None, None)
    if type(value) is AlpacaPaperAuthenticatedAccountActivityPageReceipt:
        return (
            "authenticated_account_activity_page_receipt",
            value.receipt_id,
            value.semantic_sha256,
        )
    if type(value) is AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
        return (
            "authenticated_account_activity_comparison_receipt",
            value.receipt_id,
            value.semantic_sha256,
        )
    raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
        "account-activity supervisor result has an invalid value"
    )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperAuthenticatedAccountActivitySupervisorResult(
    _NoAccountActivitySupervisorAuthority
):
    """One deterministic historical, non-authorizing Phase 4AI decision."""

    action: AlpacaPaperAccountActivitySupervisorAction
    reason: AlpacaPaperAccountActivitySupervisorReason
    prior_earlier_state: AlpacaPaperAuthenticatedAccountActivityTraversalState
    prior_later_state: AlpacaPaperAuthenticatedAccountActivityTraversalState
    earlier_state: AlpacaPaperAuthenticatedAccountActivityTraversalState
    later_state: AlpacaPaperAuthenticatedAccountActivityTraversalState
    fence: AccountFence
    checked_at: datetime | None
    next_eligible_at: datetime | None
    value: AlpacaPaperAccountActivitySupervisorValue

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError(
            "AlpacaPaperAuthenticatedAccountActivitySupervisorResult must be proof-constructed"
        )

    def _validate(self) -> None:
        if type(self.action) is not AlpacaPaperAccountActivitySupervisorAction:
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "account-activity supervisor result has an invalid action"
            )
        if type(self.reason) is not AlpacaPaperAccountActivitySupervisorReason:
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "account-activity supervisor result has an invalid reason"
            )
        states = (
            ("prior earlier state", self.prior_earlier_state),
            ("prior later state", self.prior_later_state),
            ("earlier state", self.earlier_state),
            ("later state", self.later_state),
        )
        for label, state in states:
            if type(state) is not AlpacaPaperAuthenticatedAccountActivityTraversalState:
                raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                    "account-activity supervisor result requires exact Phase 4AE states"
                )
            try:
                plan = state.prefix.plan
            except Exception:
                raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                    f"{label} failed exact Phase 4AE reconstruction"
                ) from None
            _validate_state(
                state,
                plan=plan,
                field_name=label,
            )
        earlier_plan = self.earlier_state.prefix.plan
        later_plan = self.later_state.prefix.plan
        _validate_plan_pair(earlier_plan, later_plan)
        if (
            self.prior_earlier_state.prefix.plan != earlier_plan
            or self.prior_later_state.prefix.plan != later_plan
        ):
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "account-activity supervisor result changed its ordered pair"
            )
        if type(self.fence) is not AccountFence:
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "account-activity supervisor result requires an exact account fence"
            )
        try:
            self.fence.__post_init__()
        except (AccountCoordinatorError, TypeError, ValueError):
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "account-activity supervisor result fence is invalid"
            ) from None
        if self.fence.account_id != earlier_plan.account_id:
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "account-activity supervisor result fence crosses account identities"
            )
        _value_material(self.value)

        prior_earlier = self.prior_earlier_state
        prior_later = self.prior_later_state
        earlier = self.earlier_state
        later = self.later_state

        if self.action is AlpacaPaperAccountActivitySupervisorAction.EARLIER_PAGE_ADVANCED:
            if (
                self.reason
                is not AlpacaPaperAccountActivitySupervisorReason.EARLIER_TRAVERSAL_REQUIRES_PAGE
                or type(self.value) is not AlpacaPaperAuthenticatedAccountActivityPageReceipt
                or prior_earlier.stage
                not in (
                    AlpacaPaperAccountActivityTraversalStage.ABSENT,
                    AlpacaPaperAccountActivityTraversalStage.ACTIVE,
                )
                or prior_later.stage is not AlpacaPaperAccountActivityTraversalStage.ABSENT
                or later != prior_later
                or self.checked_at is not None
            ):
                raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                    "earlier-page result conflicts with exact supervisor state"
                )
            _validate_exact_page_append(
                prior_earlier,
                earlier,
                self.value,
                fence=self.fence,
            )
            expected_next = _eligible_at(earlier) if _terminal(earlier) else None
            if self.next_eligible_at != expected_next:
                raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                    "earlier-page result has another next eligible instant"
                )
            return

        if prior_earlier != earlier or not _terminal(earlier):
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "later action requires an unchanged terminal earlier source"
            )
        eligible_at = _eligible_at(earlier)

        if self.action is AlpacaPaperAccountActivitySupervisorAction.WAITING_MINIMUM_SEPARATION:
            checked_at = _require_utc(
                self.checked_at,
                "account-activity wait checked_at",
            )
            if (
                self.reason
                is not AlpacaPaperAccountActivitySupervisorReason.LATER_START_GATE_NOT_REACHED
                or self.value is not None
                or prior_later != later
                or later.stage is not AlpacaPaperAccountActivityTraversalStage.ABSENT
                or checked_at < earlier.prefix.capture.pages[-1].observation.received_at
                or checked_at >= eligible_at
                or self.next_eligible_at != eligible_at
            ):
                raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                    "waiting result conflicts with the exact later-start boundary"
                )
            return

        if self.action is AlpacaPaperAccountActivitySupervisorAction.LATER_PAGE_ADVANCED:
            if (
                self.reason
                is not AlpacaPaperAccountActivitySupervisorReason.LATER_TRAVERSAL_REQUIRES_PAGE
                or type(self.value) is not AlpacaPaperAuthenticatedAccountActivityPageReceipt
                or prior_later.stage
                not in (
                    AlpacaPaperAccountActivityTraversalStage.ABSENT,
                    AlpacaPaperAccountActivityTraversalStage.ACTIVE,
                )
                or self.next_eligible_at is not None
            ):
                raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                    "later-page result conflicts with exact supervisor state"
                )
            _validate_exact_page_append(
                prior_later,
                later,
                self.value,
                fence=self.fence,
            )
            _require_strict_source_ingress_order(earlier, later)
            if prior_later.stage is AlpacaPaperAccountActivityTraversalStage.ABSENT:
                checked_at = _require_utc(
                    self.checked_at,
                    "later first-page checked_at",
                )
                if checked_at < eligible_at:
                    raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                        "later first-page selection predates the exact boundary"
                    )
                _require_authenticated_later_start(
                    later,
                    eligible_at=eligible_at,
                    selected_at=checked_at,
                )
            else:
                if self.checked_at is not None:
                    raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                        "continued later traversal cannot claim a first-page clock check"
                    )
                _require_authenticated_later_start(
                    later,
                    eligible_at=eligible_at,
                )
            return

        if (
            self.action is not AlpacaPaperAccountActivitySupervisorAction.COMPARISON_RECORDED
            or self.reason is not AlpacaPaperAccountActivitySupervisorReason.TERMINAL_PAIR_READY
            or type(self.value) is not AlpacaPaperAuthenticatedAccountActivityComparisonReceipt
            or prior_later != later
            or not _terminal(later)
            or self.checked_at is not None
            or self.next_eligible_at is not None
        ):
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "comparison result conflicts with exact terminal activity states"
            )
        try:
            self.value._validate()
        except Exception:
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "comparison result contains invalid Phase 4AG evidence"
            ) from None
        if (
            self.value.evidence.earlier_state != earlier
            or self.value.evidence.later_state != later
            or self.value.earlier_source_head_sha256 != earlier.source_head_sha256
            or self.value.later_source_head_sha256 != later.source_head_sha256
            or self.value.commit_fence_receipt.fence != self.fence
            or self.value.evidence.comparison.disposition
            is AlpacaPaperAccountActivityComparisonDisposition.WAITING_MINIMUM_SEPARATION
        ):
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "comparison result changed current terminal source bindings"
            )
        _require_strict_source_ingress_order(earlier, later)
        _require_authenticated_later_start(
            later,
            eligible_at=eligible_at,
        )

    @property
    def stage(self) -> AlpacaPaperAccountActivitySupervisorAction:
        """Compatibility alias for the explicit action."""

        self._validate()
        return self.action

    @property
    def round_id(self) -> str:
        self._validate()
        return alpaca_paper_account_activity_supervisor_round_id(
            self.earlier_state.prefix.plan,
            self.later_state.prefix.plan,
        )

    @property
    def result_id(self) -> str:
        self._validate()
        value_kind, value_id, value_sha256 = _value_material(self.value)
        return canonical_id(
            "alpaca-paper-authenticated-account-activity-supervisor-result",
            ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_SHA256,
            self.round_id,
            self.action,
            self.reason,
            self.prior_earlier_state.semantic_sha256,
            self.prior_later_state.semantic_sha256,
            self.earlier_state.semantic_sha256,
            self.later_state.semantic_sha256,
            self.fence.semantic_sha256,
            self.checked_at,
            self.next_eligible_at,
            value_kind,
            value_id,
            value_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        value_kind, value_id, value_sha256 = _value_material(self.value)
        return (
            ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_CONTRACT_VERSION,
            "authenticated_account_activity_supervisor_result",
            self.result_id,
            ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_ID,
            ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_SHA256,
            self.round_id,
            self.action,
            self.reason,
            self.prior_earlier_state.semantic_sha256,
            self.prior_later_state.semantic_sha256,
            self.earlier_state.semantic_sha256,
            self.later_state.semantic_sha256,
            self.fence.semantic_sha256,
            self.checked_at,
            self.next_eligible_at,
            value_kind,
            value_id,
            value_sha256,
            self.request_budget_enforced,
            self.authenticated_provider_evidence,
            self.raw_response_persisted,
            self.provider_io_performed,
            self.runtime_current,
            self.account_status_current,
            self.provider_account_status_current,
            self.capture_authenticated,
            self.durable_source_positions_authenticated,
            self.comparison_durably_recorded,
            self.snapshot_isolation_qualified,
            self.provider_snapshot_complete,
            self.snapshot_complete,
            self.activity_history_complete,
            self.activity_history_consistent,
            self.converged,
            self.monotonic_timing_qualified,
            self.provider_activity_identity_qualified,
            self.provider_activity_sequence_identity_qualified,
            self.provider_activity_revision_identity_qualified,
            self.provider_execution_identity_qualified,
            self.canonical_execution_identity_qualified,
            self.provider_revision_identity_qualified,
            self.execution_revision_identity_qualified,
            self.provider_deduplication_identity_qualified,
            self.provider_bust_identity_qualified,
            self.provider_correction_identity_qualified,
            self.provider_deduplication_authorized,
            self.canonical_execution_fact_authorized,
            self.canonical_execution_revision_authorized,
            self.canonical_account_fact_authorized,
            self.canonical_ledger_fact_authorized,
            self.canonical_cash_fact_authorized,
            self.execution_application_authorized,
            self.bust_application_authorized,
            self.correction_application_authorized,
            self.manual_activity_application_authorized,
            self.normalized_fact_authorized,
            self.inbox_application_authorized,
            self.lifecycle_application_authorized,
            self.reconciliation_application_authorized,
            self.reconciliation_completion_authorized,
            self.reconciliation_complete,
            self.unknown_resolution_authorized,
            self.reservation_release_authorized,
            self.resubmission_authorized,
            self.readiness_transition_authorized,
            self.activity_snapshot_pagination_ready,
            self.decode_quarantine_ready,
            self.reconciliation_ready,
            self.dispatch_preflight_ready,
            self.paper_startup_ready,
            self.transport_submission_ready,
            self.submission_authorized,
            self.transport_authorized,
            self.broker_call_authorized,
            self.trading_effect_authorized,
            self.additional_reconciliation_required,
        )

    @property
    def semantic_sha256(self) -> str:
        return _semantic_sha256(self._semantic_material())

    @property
    def canonical_json(self) -> str:
        return canonical_json_text(self._semantic_material())


def _alpaca_paper_authenticated_account_activity_supervisor_result(
    *,
    action: AlpacaPaperAccountActivitySupervisorAction,
    reason: AlpacaPaperAccountActivitySupervisorReason,
    prior_earlier_state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    prior_later_state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    earlier_state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    later_state: AlpacaPaperAuthenticatedAccountActivityTraversalState,
    fence: AccountFence,
    checked_at: datetime | None,
    next_eligible_at: datetime | None,
    value: AlpacaPaperAccountActivitySupervisorValue,
) -> AlpacaPaperAuthenticatedAccountActivitySupervisorResult:
    result = object.__new__(AlpacaPaperAuthenticatedAccountActivitySupervisorResult)
    for field_name, field_value in (
        ("action", action),
        ("reason", reason),
        ("prior_earlier_state", prior_earlier_state),
        ("prior_later_state", prior_later_state),
        ("earlier_state", earlier_state),
        ("later_state", later_state),
        ("fence", fence),
        ("checked_at", checked_at),
        ("next_eligible_at", next_eligible_at),
        ("value", value),
    ):
        object.__setattr__(result, field_name, field_value)
    result._validate()
    return result


def alpaca_paper_account_activity_supervisor_round_id(
    earlier_plan: AlpacaPaperAccountActivityPlan,
    later_plan: AlpacaPaperAccountActivityPlan,
) -> str:
    """Return the stable identity of one ordered exact Phase 4AI plan pair."""

    earlier = _require_plan(
        earlier_plan,
        "earlier account-activity supervisor plan",
    )
    later = _require_plan(
        later_plan,
        "later account-activity supervisor plan",
    )
    _validate_plan_pair(earlier, later)
    return canonical_id(
        "alpaca-paper-authenticated-account-activity-supervisor-round",
        ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_SHA256,
        earlier.capture_id,
        earlier.semantic_sha256,
        later.capture_id,
        later.semantic_sha256,
    )


def supervise_authenticated_alpaca_paper_account_activities_once(
    earlier_plan: AlpacaPaperAccountActivityPlan,
    later_plan: AlpacaPaperAccountActivityPlan,
    *,
    fence: AccountFence,
    clock: Clock,
    state_loader: AlpacaPaperAccountActivitySupervisorStateLoader,
    page_runtime: AlpacaPaperAccountActivitySupervisorPageRuntime,
    comparison_repository: AlpacaPaperAccountActivitySupervisorComparisonRepository,
) -> AlpacaPaperAuthenticatedAccountActivitySupervisorResult:
    """Perform at most one exact Phase 4AE page or one Phase 4AG append."""

    _validate_ports(
        state_loader=state_loader,
        page_runtime=page_runtime,
        comparison_repository=comparison_repository,
        clock=clock,
    )
    earlier_plan = _require_plan(
        earlier_plan,
        "earlier account-activity supervisor plan",
    )
    later_plan = _require_plan(
        later_plan,
        "later account-activity supervisor plan",
    )
    _validate_plan_pair(earlier_plan, later_plan)
    if type(fence) is not AccountFence:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity supervision requires an exact account fence"
        )
    try:
        fence.__post_init__()
    except (AccountCoordinatorError, TypeError, ValueError):
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity supervision fence is invalid"
        ) from None
    if fence.account_id != earlier_plan.account_id:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "account-activity supervision fence crosses account identities"
        )

    earlier = _load_exact_state(
        earlier_plan,
        state_loader=state_loader,
        field_name="earlier account-activity state",
    )
    later = _load_exact_state(
        later_plan,
        state_loader=state_loader,
        field_name="later account-activity state",
    )
    stalled = tuple(
        label
        for label, state in (("earlier", earlier), ("later", later))
        if state.stage is AlpacaPaperAccountActivityTraversalStage.STALLED
    )
    if stalled:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorStalled(
            f"{' and '.join(stalled)} account-activity source is conservatively stalled"
        )

    if not _terminal(earlier):
        if later.stage is not AlpacaPaperAccountActivityTraversalStage.ABSENT:
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "later account-activity source advanced before earlier termination"
            )
        advanced, receipt = _advance_exactly_one_page(
            earlier,
            state_loader=state_loader,
            page_runtime=page_runtime,
            fence=fence,
            field_name="earlier account-activity state",
        )
        reloaded_later = _load_exact_state(
            later_plan,
            state_loader=state_loader,
            field_name="later account-activity state",
        )
        if reloaded_later != later:
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "unselected later activity source changed during earlier page"
            )
        return _alpaca_paper_authenticated_account_activity_supervisor_result(
            action=AlpacaPaperAccountActivitySupervisorAction.EARLIER_PAGE_ADVANCED,
            reason=(AlpacaPaperAccountActivitySupervisorReason.EARLIER_TRAVERSAL_REQUIRES_PAGE),
            prior_earlier_state=earlier,
            prior_later_state=later,
            earlier_state=advanced,
            later_state=reloaded_later,
            fence=fence,
            checked_at=None,
            next_eligible_at=(_eligible_at(advanced) if _terminal(advanced) else None),
            value=receipt,
        )

    eligible_at = _eligible_at(earlier)
    if not _terminal(later):
        checked_at: datetime | None = None
        if later.stage is AlpacaPaperAccountActivityTraversalStage.ABSENT:
            checked_at = _trusted_now(clock)
            earlier_received_at = earlier.prefix.capture.pages[-1].observation.received_at
            if checked_at < earlier_received_at:
                raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                    "account-activity supervisor clock regressed behind source evidence"
                )
            if checked_at < eligible_at:
                return _alpaca_paper_authenticated_account_activity_supervisor_result(
                    action=(AlpacaPaperAccountActivitySupervisorAction.WAITING_MINIMUM_SEPARATION),
                    reason=(
                        AlpacaPaperAccountActivitySupervisorReason.LATER_START_GATE_NOT_REACHED
                    ),
                    prior_earlier_state=earlier,
                    prior_later_state=later,
                    earlier_state=earlier,
                    later_state=later,
                    fence=fence,
                    checked_at=checked_at,
                    next_eligible_at=eligible_at,
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
            page_runtime=page_runtime,
            fence=fence,
            field_name="later account-activity state",
        )
        _require_strict_source_ingress_order(earlier, advanced)
        _require_authenticated_later_start(
            advanced,
            eligible_at=eligible_at,
            selected_at=checked_at,
        )
        reloaded_earlier = _load_exact_state(
            earlier_plan,
            state_loader=state_loader,
            field_name="earlier account-activity state",
        )
        if reloaded_earlier != earlier:
            raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
                "unselected earlier activity source changed during later page"
            )
        return _alpaca_paper_authenticated_account_activity_supervisor_result(
            action=AlpacaPaperAccountActivitySupervisorAction.LATER_PAGE_ADVANCED,
            reason=(AlpacaPaperAccountActivitySupervisorReason.LATER_TRAVERSAL_REQUIRES_PAGE),
            prior_earlier_state=earlier,
            prior_later_state=later,
            earlier_state=reloaded_earlier,
            later_state=advanced,
            fence=fence,
            checked_at=checked_at,
            next_eligible_at=None,
            value=receipt,
        )

    _require_strict_source_ingress_order(earlier, later)
    _require_authenticated_later_start(
        later,
        eligible_at=eligible_at,
    )
    try:
        comparison_receipt = (
            compare_and_record_authenticated_alpaca_paper_account_activity_prefixes(
                earlier_plan,
                later_plan,
                fence=fence,
                state_loader=state_loader,
                comparison_repository=comparison_repository,
            )
        )
    except AlpacaPaperAuthenticatedAccountActivityComparisonError:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "Phase 4AG comparison workflow failed"
        ) from None
    if type(comparison_receipt) is not AlpacaPaperAuthenticatedAccountActivityComparisonReceipt:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "Phase 4AG workflow returned a non-canonical receipt"
        )
    try:
        comparison_receipt._validate()
    except Exception:
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "Phase 4AG workflow returned invalid evidence"
        ) from None
    if (
        comparison_receipt.evidence.earlier_state != earlier
        or comparison_receipt.evidence.later_state != later
        or comparison_receipt.earlier_source_head_sha256 != earlier.source_head_sha256
        or comparison_receipt.later_source_head_sha256 != later.source_head_sha256
        or comparison_receipt.commit_fence_receipt.fence != fence
        or comparison_receipt.evidence.comparison.disposition
        is AlpacaPaperAccountActivityComparisonDisposition.WAITING_MINIMUM_SEPARATION
    ):
        raise AlpacaPaperAuthenticatedAccountActivitySupervisorConflict(
            "Phase 4AG result conflicts with current terminal source bindings"
        )
    return _alpaca_paper_authenticated_account_activity_supervisor_result(
        action=AlpacaPaperAccountActivitySupervisorAction.COMPARISON_RECORDED,
        reason=AlpacaPaperAccountActivitySupervisorReason.TERMINAL_PAIR_READY,
        prior_earlier_state=earlier,
        prior_later_state=later,
        earlier_state=earlier,
        later_state=later,
        fence=fence,
        checked_at=None,
        next_eligible_at=None,
        value=comparison_receipt,
    )


__all__ = [
    "ALPACA_PAPER_ACCOUNT_ACTIVITY_SUPERVISOR_MINIMUM_START_SEPARATION",
    "ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_CONTRACT_VERSION",
    "ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_ID",
    "ALPACA_PAPER_AUTHENTICATED_ACCOUNT_ACTIVITY_SUPERVISOR_POLICY_SHA256",
    "AlpacaPaperAccountActivitySupervisorAction",
    "AlpacaPaperAccountActivitySupervisorComparisonRepository",
    "AlpacaPaperAccountActivitySupervisorPageRuntime",
    "AlpacaPaperAccountActivitySupervisorReason",
    "AlpacaPaperAccountActivitySupervisorStateLoader",
    "AlpacaPaperAccountActivitySupervisorValue",
    "AlpacaPaperAuthenticatedAccountActivitySupervisorConflict",
    "AlpacaPaperAuthenticatedAccountActivitySupervisorError",
    "AlpacaPaperAuthenticatedAccountActivitySupervisorResult",
    "AlpacaPaperAuthenticatedAccountActivitySupervisorStalled",
    "alpaca_paper_account_activity_supervisor_round_id",
    "supervise_authenticated_alpaca_paper_account_activities_once",
]
