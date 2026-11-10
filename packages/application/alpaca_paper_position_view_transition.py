"""Durable admission proofs for one position-pair capture transition.

Phase 4X registers an exact ordered pair before either member may be prepared.
It can then admit the earlier capture from two absent sources or the later
capture from one exact complete earlier source and one absent later source.
The proofs authorize only the existing Phase 4U single-use preparation; they
do not authorize credentials, request capacity, provider I/O, reconciliation,
readiness, or trading.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from packages.adapters.broker.alpaca_paper_position_snapshot_comparison import (
    ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION,
)
from packages.adapters.broker.alpaca_paper_position_snapshot_runtime import (
    ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
    AlpacaPaperAuthenticatedPositionSnapshotReceipt,
    AlpacaPaperPositionSnapshotConflict,
    AlpacaPaperPositionSnapshotPreparationReceipt,
    AlpacaPaperPositionSnapshotRuntimePlan,
)
from packages.domain.account_coordinator import (
    AccountCoordinatorError,
    AccountFenceReceipt,
)
from packages.domain.canonical import canonical_json_bytes, canonical_json_text
from packages.domain.identifiers import canonical_id

ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION = (
    "phase4x-durable-position-view-transition-admission-v1"
)
ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_ID = (
    "phase4x-exact-pair-single-use-transition-policy-v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _semantic_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256 = _semantic_sha256(
    (
        ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION,
        "transition_policy",
        ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_ID,
        ALPACA_PAPER_POSITION_SNAPSHOT_RUNTIME_CONTRACT_VERSION,
        int(ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION.total_seconds() * 1_000_000),
        "one_exact_ordered_pair_membership",
        "one_plan_may_belong_to_only_one_round_in_either_role",
        "earlier_requires_both_sources_absent",
        "later_requires_exact_earlier_complete_and_later_absent",
        "later_selection_requires_minimum_receive_time_boundary",
        "claim_precedes_and_is_consumed_with_single_use_preparation",
        "unscoped_preparation_of_registered_members_is_forbidden",
        "historical_claim_retry_reauthenticates_current_fence",
        "new_claim_final_same_lease_fence_revalidation",
        "no_provider_io_or_reconciliation_authority",
    )
)


class AlpacaPaperPositionViewTransitionError(RuntimeError):
    """An exact position-pair transition could not be admitted."""


class AlpacaPaperPositionViewTransitionConflict(AlpacaPaperPositionViewTransitionError):
    """Durable pair state conflicts with the requested transition."""


class AlpacaPaperPositionViewTransitionRole(StrEnum):
    """The only two single-use captures in an ordered position-view round."""

    EARLIER = "earlier"
    LATER = "later"


class _NoPositionViewTransitionAuthority:
    __slots__ = ()

    @property
    def runtime_current(self) -> bool:
        return False

    @property
    def provider_io_performed(self) -> bool:
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
    def provider_revision_identity_qualified(self) -> bool:
        return False

    @property
    def provider_deduplication_authorized(self) -> bool:
        return False

    @property
    def canonical_position_fact_authorized(self) -> bool:
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
    def paper_startup_ready(self) -> bool:
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


def _require_plan(
    value: object,
    field_name: str,
) -> AlpacaPaperPositionSnapshotRuntimePlan:
    if type(value) is not AlpacaPaperPositionSnapshotRuntimePlan:
        raise AlpacaPaperPositionViewTransitionConflict(
            f"{field_name} must be an exact position-snapshot runtime plan"
        )
    try:
        value.__post_init__()
    except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError):
        raise AlpacaPaperPositionViewTransitionConflict(f"{field_name} is invalid") from None
    return value


def _require_source_receipt(
    value: object,
) -> AlpacaPaperAuthenticatedPositionSnapshotReceipt:
    if type(value) is not AlpacaPaperAuthenticatedPositionSnapshotReceipt:
        raise AlpacaPaperPositionViewTransitionConflict(
            "later transition requires the exact complete earlier receipt"
        )
    try:
        value._validate()
    except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError):
        raise AlpacaPaperPositionViewTransitionConflict(
            "later transition earlier receipt is invalid"
        ) from None
    return value


@dataclass(frozen=True, slots=True)
class AlpacaPaperPositionViewTransitionPlan(_NoPositionViewTransitionAuthority):
    """One exact ordered pair whose members may be claimed only by Phase 4X."""

    earlier_plan: AlpacaPaperPositionSnapshotRuntimePlan
    later_plan: AlpacaPaperPositionSnapshotRuntimePlan

    def __post_init__(self) -> None:
        earlier = _require_plan(self.earlier_plan, "earlier transition plan")
        later = _require_plan(self.later_plan, "later transition plan")
        if earlier.description.account_id != later.description.account_id:
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition plans cross local accounts"
            )
        if (
            earlier.reference.expected_provider_account_id
            != later.reference.expected_provider_account_id
        ):
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition plans cross provider accounts"
            )
        if (
            earlier.plan_id == later.plan_id
            or earlier.description.capture_id == later.description.capture_id
        ):
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition requires two distinct plans"
            )

    @property
    def account_id(self) -> str:
        self.__post_init__()
        return self.earlier_plan.description.account_id

    @property
    def expected_provider_account_id(self) -> str:
        self.__post_init__()
        return self.earlier_plan.reference.expected_provider_account_id

    @property
    def round_id(self) -> str:
        self.__post_init__()
        return canonical_id(
            "alpaca-paper-position-view-transition-round",
            ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256,
            self.earlier_plan.plan_id,
            self.earlier_plan.semantic_sha256,
            self.later_plan.plan_id,
            self.later_plan.semantic_sha256,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self.__post_init__()
        return (
            ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION,
            "transition_plan",
            self.round_id,
            ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_ID,
            ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256,
            self.account_id,
            self.expected_provider_account_id,
            self.earlier_plan.plan_id,
            self.earlier_plan.semantic_sha256,
            self.earlier_plan.description.capture_id,
            self.later_plan.plan_id,
            self.later_plan.semantic_sha256,
            self.later_plan.description.capture_id,
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

    def selected_plan(
        self,
        role: AlpacaPaperPositionViewTransitionRole,
    ) -> AlpacaPaperPositionSnapshotRuntimePlan:
        if type(role) is not AlpacaPaperPositionViewTransitionRole:
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition role is invalid"
            )
        return (
            self.earlier_plan
            if role is AlpacaPaperPositionViewTransitionRole.EARLIER
            else self.later_plan
        )


def create_alpaca_paper_position_view_transition_plan(
    *,
    earlier_plan: AlpacaPaperPositionSnapshotRuntimePlan,
    later_plan: AlpacaPaperPositionSnapshotRuntimePlan,
) -> AlpacaPaperPositionViewTransitionPlan:
    return AlpacaPaperPositionViewTransitionPlan(
        earlier_plan=earlier_plan,
        later_plan=later_plan,
    )


def alpaca_paper_position_view_transition_claim_id(
    plan: AlpacaPaperPositionViewTransitionPlan,
    selected_role: AlpacaPaperPositionViewTransitionRole,
) -> str:
    """Return the stable identifier for one exact role admission."""

    if type(plan) is not AlpacaPaperPositionViewTransitionPlan:
        raise AlpacaPaperPositionViewTransitionConflict(
            "position-view transition claim identity requires an exact plan"
        )
    plan.__post_init__()
    if type(selected_role) is not AlpacaPaperPositionViewTransitionRole:
        raise AlpacaPaperPositionViewTransitionConflict(
            "position-view transition claim identity requires an exact role"
        )
    return canonical_id(
        "alpaca-paper-position-view-transition-claim",
        ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256,
        plan.round_id,
        selected_role,
    )


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperPositionViewTransitionClaim(_NoPositionViewTransitionAuthority):
    """Repository-produced admission of one exact pair member."""

    plan: AlpacaPaperPositionViewTransitionPlan
    selected_role: AlpacaPaperPositionViewTransitionRole
    prior_earlier_receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None
    commit_fence_receipt: AccountFenceReceipt

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("position-view transition claims must be repository-produced")

    def _validate(self) -> None:
        if type(self.plan) is not AlpacaPaperPositionViewTransitionPlan:
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition claim requires an exact plan"
            )
        self.plan.__post_init__()
        if type(self.selected_role) is not AlpacaPaperPositionViewTransitionRole:
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition claim role is invalid"
            )
        if type(self.commit_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition claim requires an exact commit fence"
            )
        try:
            self.commit_fence_receipt._validate()
        except (AccountCoordinatorError, TypeError, ValueError):
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition claim fence is invalid"
            ) from None
        if self.commit_fence_receipt.fence.account_id != self.plan.account_id:
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition claim fence crosses accounts"
            )
        if self.selected_role is AlpacaPaperPositionViewTransitionRole.EARLIER:
            if self.prior_earlier_receipt is not None:
                raise AlpacaPaperPositionViewTransitionConflict(
                    "earlier transition cannot name a prior source receipt"
                )
            return
        earlier = _require_source_receipt(self.prior_earlier_receipt)
        if earlier.plan != self.plan.earlier_plan:
            raise AlpacaPaperPositionViewTransitionConflict(
                "later transition names another earlier source"
            )
        eligible_at = self.eligible_at
        assert eligible_at is not None
        if self.selected_at < eligible_at:
            raise AlpacaPaperPositionViewTransitionConflict(
                "later transition was selected before its receive-time boundary"
            )
        if self.selected_at < earlier.commit_fence_receipt.validated_at:
            raise AlpacaPaperPositionViewTransitionConflict(
                "later transition predates the earlier source commit"
            )

    @property
    def selected_plan(self) -> AlpacaPaperPositionSnapshotRuntimePlan:
        self._validate()
        return self.plan.selected_plan(self.selected_role)

    @property
    def selected_at(self) -> datetime:
        self._validate_fence_only()
        return self.commit_fence_receipt.validated_at

    def _validate_fence_only(self) -> None:
        if type(self.commit_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition claim requires an exact commit fence"
            )
        try:
            self.commit_fence_receipt._validate()
        except (AccountCoordinatorError, TypeError, ValueError):
            raise AlpacaPaperPositionViewTransitionConflict(
                "position-view transition claim fence is invalid"
            ) from None

    @property
    def eligible_at(self) -> datetime | None:
        if self.selected_role is AlpacaPaperPositionViewTransitionRole.EARLIER:
            return None
        earlier = _require_source_receipt(self.prior_earlier_receipt)
        return (
            earlier.persisted_snapshot.observation.received_at
            + ALPACA_PAPER_POSITION_SNAPSHOT_MINIMUM_UTC_SEPARATION
        )

    @property
    def claim_id(self) -> str:
        self._validate()
        return alpaca_paper_position_view_transition_claim_id(
            self.plan,
            self.selected_role,
        )

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        prior = self.prior_earlier_receipt
        return (
            ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION,
            "transition_claim",
            self.claim_id,
            ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_ID,
            ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256,
            self.plan.round_id,
            self.plan.semantic_sha256,
            self.selected_role,
            self.selected_plan.plan_id,
            self.selected_plan.semantic_sha256,
            None if prior is None else prior.receipt_id,
            None if prior is None else prior.semantic_sha256,
            self.selected_at,
            self.eligible_at,
            self.commit_fence_receipt.receipt_id,
            self.commit_fence_receipt.semantic_sha256,
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


def _alpaca_paper_position_view_transition_claim(
    *,
    plan: AlpacaPaperPositionViewTransitionPlan,
    selected_role: AlpacaPaperPositionViewTransitionRole,
    prior_earlier_receipt: AlpacaPaperAuthenticatedPositionSnapshotReceipt | None,
    commit_fence_receipt: AccountFenceReceipt,
) -> AlpacaPaperPositionViewTransitionClaim:
    value = object.__new__(AlpacaPaperPositionViewTransitionClaim)
    for field_name, field_value in (
        ("plan", plan),
        ("selected_role", selected_role),
        ("prior_earlier_receipt", prior_earlier_receipt),
        ("commit_fence_receipt", commit_fence_receipt),
    ):
        object.__setattr__(value, field_name, field_value)
    value._validate()
    return value


@dataclass(frozen=True, slots=True, init=False)
class AlpacaPaperPositionViewTransitionConsumption(_NoPositionViewTransitionAuthority):
    """Atomic proof that one claim created its unchanged Phase 4U preparation."""

    claim: AlpacaPaperPositionViewTransitionClaim
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt
    commit_fence_receipt: AccountFenceReceipt

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("position-view transition consumption must be repository-produced")

    def _validate(self) -> None:
        if type(self.claim) is not AlpacaPaperPositionViewTransitionClaim:
            raise AlpacaPaperPositionViewTransitionConflict(
                "transition consumption requires an exact claim"
            )
        self.claim._validate()
        if type(self.preparation) is not AlpacaPaperPositionSnapshotPreparationReceipt:
            raise AlpacaPaperPositionViewTransitionConflict(
                "transition consumption requires an exact Phase 4U preparation"
            )
        try:
            self.preparation._validate()
        except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError):
            raise AlpacaPaperPositionViewTransitionConflict(
                "transition consumption preparation is invalid"
            ) from None
        if self.preparation.plan != self.claim.selected_plan:
            raise AlpacaPaperPositionViewTransitionConflict(
                "transition consumption prepared another plan"
            )
        if self.preparation.prepared_at < self.claim.selected_at:
            raise AlpacaPaperPositionViewTransitionConflict(
                "transition consumption predates its claim"
            )
        if type(self.commit_fence_receipt) is not AccountFenceReceipt:
            raise AlpacaPaperPositionViewTransitionConflict(
                "transition consumption requires an exact commit fence"
            )
        try:
            self.commit_fence_receipt._validate()
        except (AccountCoordinatorError, TypeError, ValueError):
            raise AlpacaPaperPositionViewTransitionConflict(
                "transition consumption fence is invalid"
            ) from None
        claim_fence = self.claim.commit_fence_receipt
        consumption_fence = self.commit_fence_receipt
        if (
            consumption_fence.fence != claim_fence.fence
            or consumption_fence.policy_sha256 != claim_fence.policy_sha256
            or consumption_fence.lease_sha256 != claim_fence.lease_sha256
            or consumption_fence.valid_until != claim_fence.valid_until
            or consumption_fence.validated_at < claim_fence.validated_at
            or consumption_fence.validated_at < self.preparation.prepared_at
            or consumption_fence.validated_at >= consumption_fence.valid_until
        ):
            raise AlpacaPaperPositionViewTransitionConflict(
                "transition consumption fence conflicts with its preparation"
            )

    @property
    def consumption_id(self) -> str:
        self._validate()
        return alpaca_paper_position_view_transition_consumption_id(
            self.claim,
            self.preparation,
        )

    @property
    def consumed_at(self) -> datetime:
        self._validate()
        return self.commit_fence_receipt.validated_at

    def _semantic_material(self) -> tuple[object, ...]:
        self._validate()
        return (
            ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION,
            "transition_consumption",
            self.consumption_id,
            self.claim.claim_id,
            self.claim.semantic_sha256,
            self.preparation.preparation_id,
            self.preparation.semantic_sha256,
            self.preparation.plan.plan_id,
            self.preparation.plan.semantic_sha256,
            self.commit_fence_receipt.receipt_id,
            self.commit_fence_receipt.semantic_sha256,
            self.consumed_at,
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


def _alpaca_paper_position_view_transition_consumption(
    *,
    claim: AlpacaPaperPositionViewTransitionClaim,
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt,
    commit_fence_receipt: AccountFenceReceipt,
) -> AlpacaPaperPositionViewTransitionConsumption:
    value = object.__new__(AlpacaPaperPositionViewTransitionConsumption)
    for field_name, field_value in (
        ("claim", claim),
        ("preparation", preparation),
        ("commit_fence_receipt", commit_fence_receipt),
    ):
        object.__setattr__(value, field_name, field_value)
    value._validate()
    return value


def alpaca_paper_position_view_transition_consumption_id(
    claim: AlpacaPaperPositionViewTransitionClaim,
    preparation: AlpacaPaperPositionSnapshotPreparationReceipt,
) -> str:
    """Return the stable identifier for one exact claim consumption."""

    if type(claim) is not AlpacaPaperPositionViewTransitionClaim:
        raise AlpacaPaperPositionViewTransitionConflict(
            "transition consumption identity requires an exact claim"
        )
    claim._validate()
    if type(preparation) is not AlpacaPaperPositionSnapshotPreparationReceipt:
        raise AlpacaPaperPositionViewTransitionConflict(
            "transition consumption identity requires an exact preparation"
        )
    try:
        preparation._validate()
    except (AlpacaPaperPositionSnapshotConflict, TypeError, ValueError):
        raise AlpacaPaperPositionViewTransitionConflict(
            "transition consumption identity preparation is invalid"
        ) from None
    if preparation.plan != claim.selected_plan:
        raise AlpacaPaperPositionViewTransitionConflict(
            "transition consumption identity prepared another plan"
        )
    return canonical_id(
        "alpaca-paper-position-view-transition-consumption",
        claim.claim_id,
        preparation.preparation_id,
    )


__all__ = [
    "ALPACA_PAPER_POSITION_VIEW_TRANSITION_CONTRACT_VERSION",
    "ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_ID",
    "ALPACA_PAPER_POSITION_VIEW_TRANSITION_POLICY_SHA256",
    "AlpacaPaperPositionViewTransitionClaim",
    "AlpacaPaperPositionViewTransitionConflict",
    "AlpacaPaperPositionViewTransitionConsumption",
    "AlpacaPaperPositionViewTransitionError",
    "AlpacaPaperPositionViewTransitionPlan",
    "AlpacaPaperPositionViewTransitionRole",
    "_alpaca_paper_position_view_transition_claim",
    "_alpaca_paper_position_view_transition_consumption",
    "alpaca_paper_position_view_transition_claim_id",
    "alpaca_paper_position_view_transition_consumption_id",
    "create_alpaca_paper_position_view_transition_plan",
]
